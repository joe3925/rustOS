use alloc::{string::String, sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use x86_64::{
    structures::paging::{mapper::MapToError, Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    memory::paging::{init_mapper, unmap_range, unmap_range_unchecked, BootInfoFrameAllocator}, scheduling::{scheduler::{self, SCHEDULER}, task::Task}, structs::range_tracker::RangeTracker, util::boot_info
};

use super::pe_loadable::{self, LoadError};
pub struct Module {
    pub title: String,
    pub image_path: String,
    pub parent_pid: u64,
    pub image_base: VirtAddr,
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

        let boot_info = boot_info();
        let phys_mem_offset = VirtAddr::new(
            boot_info
                .physical_memory_offset
                .into_option()
                .expect("physical_memory_offset missing"),
        );

        let mut mapper = init_mapper(phys_mem_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

        let flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

        for addr in (start.as_u64()..end.as_u64()).step_by(0x1000) {
            let page = Page::containing_address(VirtAddr::new(addr));
            crate::memory::paging::map_page(&mut mapper, page, &mut frame_allocator, flags)?;
        }

        Ok(())
    }

    ///Safety: User must make sure the address mapped by this function is allocated by the range tracker or virtual_map will silently fail
    pub unsafe fn virtual_map(
        &self,
        virt_addr: VirtAddr,
        size: usize,
    ) -> Result<(), MapToError<Size4KiB>> {
        let start = virt_addr;
        let end = virt_addr + size as u64;

        let boot_info = boot_info();
        let phys_mem_offset = VirtAddr::new(
            boot_info
                .physical_memory_offset
                .into_option()
                .expect("physical_memory_offset missing"),
        );

        let mut mapper = init_mapper(phys_mem_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

        let flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

        for addr in (start.as_u64()..end.as_u64()).step_by(0x1000) {
            let page = Page::containing_address(VirtAddr::new(addr));
            crate::memory::paging::map_page(&mut mapper, page, &mut frame_allocator, flags)?;
        }

        Ok(())
    }
    pub fn load_module(&mut self, path: String) -> Result<(), LoadError> {
        if let Some(mut dll) = pe_loadable::PELoader::new("C:\\BIN\\TEST.DLL") {
            let module = dll.dll_load(self.pid)?;
            self.modules.lock().push(module);
            return Ok(());
        }
        Err(LoadError::NoFile)
    }
    pub fn kill(&mut self) -> Result<(), LoadError>{
        if let Some(main_id) = &self.main_thread{
            let mut can_kill = false;
            let managed_threads = self.managed_threads.lock();
            let mut scheduler = SCHEDULER.lock();
            while(!can_kill){
                let mut running_threads = managed_threads.len() + 1;
                if(scheduler.get_task_by_id(main_id.id).is_none()){
                    running_threads -= 1;
                }
                for id in &*managed_threads{
                                    if(scheduler.get_task_by_id(*id).is_none()){
                    running_threads -= 1;
                }
                }
                if(running_threads == 0){
                    can_kill = true;
                }
            }
            for allocation in self.tracker.get_allocations(){
                unsafe { unmap_range_unchecked(VirtAddr::new(allocation.0), allocation.1 - allocation.0) };
            }
            Ok(())
        }else{
            Err(LoadError::NoMainThread)
        }
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
    pub fn start_pid(&self, pid: u64) -> Option<u64> {
        let program = self.get(pid)?;
        let mut scheduler = SCHEDULER.lock();
        let task = program.main_thread.clone()?;
        scheduler.add_task(task);
        return Some(scheduler.get_task_by_name(program.title.clone())?.id);
    }

    pub fn remove_program(&mut self, pid: u64) {
        self.programs.retain(|p| p.pid != pid);
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
