use alloc::{string::String, sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use x86_64::{
    instructions::hlt,
    registers::control::Cr3,
    structures::paging::{mapper::MapToError, Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    memory::paging::paging::map_page,
    scheduling::scheduler::{self, Scheduler},
};
use crate::{
    memory::paging::{
        frame_alloc::BootInfoFrameAllocator, paging::unmap_range_unchecked, tables::init_mapper,
    },
    scheduling::{scheduler::SCHEDULER, task::Task},
    structs::range_tracker::RangeTracker,
    util::boot_info,
};

use super::pe_loadable::{self, LoadError};
#[derive(Clone)]
pub struct Module {
    pub title: String,
    pub image_path: String,
    pub parent_pid: u64,
    pub image_base: VirtAddr,
    pub symbols: Vec<(String, usize)>,
}
pub struct Program {
    pub title: String,
    pub image_path: String, 
    pub pid: u64,
    pub image_base: VirtAddr,
    pub main_thread: Option<Task>,
    pub managed_threads: Mutex<Vec<u64>>,
    pub modules: Mutex<Vec<Module>>,
    pub cr3: PhysFrame,
    pub tracker: Arc<RangeTracker>,
}
impl Program {
    pub fn virtual_map_alloc(
        &self,
        virt_addr: VirtAddr,
        size: usize,
    ) -> Result<(), MapToError<Size4KiB>> {
        let start = virt_addr;
        let end = virt_addr + size as u64;

        self.tracker
            .alloc(start.as_u64(), size as u64)
            .map_err(|_| MapToError::FrameAllocationFailed)?;

        let old_cr3 = Cr3::read();
        unsafe { Cr3::write(self.cr3, old_cr3.1) };

        let res = (|| {
            let boot_info = boot_info();
            let phys_mem_offset = VirtAddr::new(
                boot_info
                    .physical_memory_offset
                    .into_option()
                    .expect("phys mem off missing"),
            );
            let mut mapper = init_mapper(phys_mem_offset);
            let mut frame_alloc = BootInfoFrameAllocator::init(&boot_info.memory_regions);
            let flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE;

            for addr in (start.as_u64()..end.as_u64()).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new(addr));
                map_page(&mut mapper, page, &mut frame_alloc, flags)?;
            }
            Ok(())
        })();

        unsafe { Cr3::write(old_cr3.0, old_cr3.1) };
        res
    }

    /// Map an already-tracked range.  Caller must ensure the range was reserved.
    pub unsafe fn virtual_map(
        &self,
        virt_addr: VirtAddr,
        size: usize,
    ) -> Result<(), MapToError<Size4KiB>> {
        let start = virt_addr;
        let end = virt_addr + size as u64;

        let old_cr3 = Cr3::read();
        Cr3::write(self.cr3, old_cr3.1);

        let result = (|| {
            let boot_info = boot_info();
            let phys_mem_offset = VirtAddr::new(
                boot_info
                    .physical_memory_offset
                    .into_option()
                    .expect("phys mem off missing"),
            );
            let mut mapper = init_mapper(phys_mem_offset);
            let mut frame_alloc = BootInfoFrameAllocator::init(&boot_info.memory_regions);
            let flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE;

            for addr in (start.as_u64()..end.as_u64()).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new(addr));
                map_page(&mut mapper, page, &mut frame_alloc, flags)?;
            }
            Ok(())
        })();

        Cr3::write(old_cr3.0, old_cr3.1);
        result
    }
    pub fn load_module(&mut self, path: String) -> Result<(), LoadError> {
        if let Some(mut dll) = pe_loadable::PELoader::new(&path) {
            let module = dll.dll_load(self)?;
            return Ok(());
        }
        Err(LoadError::NoFile)
    }
    pub fn kill(&mut self) -> Result<(), LoadError> {
        if let Some(main_id) = &self.main_thread {
            let managed_threads = self.managed_threads.lock();
            loop {
                hlt();

                let mut scheduler = SCHEDULER.lock();
                let mut running = managed_threads.len() + 1;
                if scheduler.get_task_by_id(main_id.id).is_none() {
                    running -= 1;
                }
                for id in &*managed_threads {
                    if scheduler.get_task_by_id(*id).is_none() {
                        running -= 1;
                    }
                }

                if running == 0 {
                    break;
                }
            }
            for (start, end) in self.tracker.get_allocations() {
                unsafe { unmap_range_unchecked(VirtAddr::new(start), end - start) };
            }
            Ok(())
        } else {
            Err(LoadError::NoMainThread)
        }
    }
    pub fn has_module(&self, name_lc: &str) -> bool {
        self.modules
            .lock()
            .iter()
            .any(|m| m.title.eq_ignore_ascii_case(name_lc))
    }
}

pub struct ProgramManager {
    programs: Vec<Program>,
    next_pid: u64,
}

impl ProgramManager {
    pub const fn new() -> Self {
        Self {
            programs: Vec::new(),
            next_pid: 0,
        }
    }

    pub fn add_program(&mut self, mut program: Program) -> u64 {
        let pid = self.next_pid;
        self.next_pid += 1;
        program.pid = pid;
        if let Some(ref mut task) = program.main_thread {
            task.parent_pid = pid;
        }
        self.programs.push(program);
        pid
    }
    ///Returns the thread id of the main thread if successful
    pub fn start_pid(&self, pid: u64, scheduler: &mut Scheduler) -> Option<u64> {
        let program = self.get(pid)?;
        let task = program.main_thread.clone()?;
        scheduler.add_task(task);
        return Some(scheduler.get_task_by_name(program.title.clone())?.id);
    }

    pub fn kill_program(&mut self, pid: u64) -> Result<(), LoadError> {
        self.get_mut(pid).ok_or(LoadError::BadPID)?.kill();
        self.programs.retain(|p| p.pid != pid);
        Ok(())
    }

    pub fn get(&self, pid: u64) -> Option<&Program> {
        self.programs.iter().find(|p| p.pid == pid)
    }

    pub fn get_mut(&mut self, pid: u64) -> Option<&mut Program> {
        self.programs.iter_mut().find(|p| p.pid == pid)
    }

    pub fn all(&self) -> &Vec<Program> {
        &self.programs
    }
}

lazy_static! {
    pub static ref PROGRAM_MANAGER: RwLock<ProgramManager> = RwLock::new(ProgramManager::new());
}
