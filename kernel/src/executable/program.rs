use core::sync::atomic::{AtomicU64, Ordering};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use kernel_types::{device::ModuleHandle, fs::Path, status::PageMapError};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use x86_64::{
    instructions::hlt,
    registers::control::Cr3,
    structures::paging::{mapper::MapToError, Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    executable::pe_loadable::PELoader,
    memory::paging::paging::{map_page, map_range_with_huge_pages},
    object_manager::{Object, ObjectPayload, ObjectTag, OBJECT_MANAGER},
    scheduling::{
        scheduler::{self, Scheduler},
        task::TaskHandle,
    },
    util::{generate_guid, random_number},
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

type ObjectRef = Arc<Object>;
pub type ProgramHandle = Arc<RwLock<Program>>;
pub type QueueHandle = Arc<RwLock<MessageQueue>>;
pub type UserHandle = u64;

#[inline]
fn obj_as_program(obj: &ObjectRef) -> Option<ProgramHandle> {
    match &obj.payload {
        ObjectPayload::Program(p) => Some(p.clone()),
        _ => None,
    }
}
#[inline]
fn obj_as_queue(obj: &ObjectRef) -> Option<QueueHandle> {
    match &obj.payload {
        ObjectPayload::Queue(q) => Some(q.clone()),
        _ => None,
    }
}
#[inline]
fn guid_to_string(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    alloc::format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

#[derive(Debug)]
pub struct MessageQueue {
    pub queue: VecDeque<Message>,
}
#[derive(Debug)]
pub struct HandleTable {
    pub handles: BTreeMap<UserHandle, ObjectRef>,
}
impl HandleTable {
    pub fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
        }
    }
    pub fn resolve(&self, handle: UserHandle) -> Option<ObjectRef> {
        self.handles.get(&handle).cloned()
    }
    pub fn handle_to_program(&self, target_pid: u64) -> Option<UserHandle> {
        self.handles.iter().find_map(|(uh, obj)| {
            if let Some(ph) = obj_as_program(obj) {
                if ph.read().pid == target_pid {
                    return Some(*uh);
                }
            }
            None
        })
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageId {
    KeyDown = 0x0001,
    KeyUp = 0x0002,
    MouseMove = 0x0003,
    MouseClick = 0x0004,
    WindowClose = 0x0005,
    TimerExpired = 0x0006,
    IoComplete = 0x0007,
    ProcessExit = 0x0008,
    User(u32),
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: MessageId,
    pub sender: Option<UserHandle>,
    pub wparam: usize,
    pub lparam: usize,
    pub timestamp: u64,
}

#[derive(Clone, Debug)]
pub enum RoutingAction {
    Block,
    Allow,
    Reroute(QueueHandle),
    Callback(TaskHandle, Option<QueueHandle>),
}

#[derive(Clone, Debug)]
pub struct RoutingRule {
    pub msg_id: MessageId,
    pub from_pid: Option<u64>,
    pub action: RoutingAction,
}

pub type RuleList = Vec<RoutingRule>;

#[derive(Debug)]
pub struct Program {
    pub title: String,
    pub image_path: Path,
    pub pid: u64,
    pub image_base: VirtAddr,
    pub main_thread: Option<TaskHandle>,
    pub managed_threads: Mutex<Vec<TaskHandle>>,
    pub modules: RwLock<Vec<ModuleHandle>>,
    pub cr3: PhysFrame,
    pub tracker: Arc<RangeTracker>,

    pub handle_table: RwLock<HandleTable>,
    pub working_dir: Path,

    pub default_queue: QueueHandle,
    pub extra_queues: Mutex<BTreeMap<u64, QueueHandle>>,

    pub routing_rules: Mutex<RuleList>,
}
impl Program {
    pub fn new(
        title: String,
        image_path: Path,
        image_base: VirtAddr,
        cr3: PhysFrame,
        tracker: Arc<RangeTracker>,
    ) -> Self {
        let working_dir = image_path.parent().unwrap_or(image_path.clone());
        Self {
            title,
            image_path,
            pid: 0,
            image_base,
            main_thread: None,
            managed_threads: Mutex::new(Vec::new()),
            modules: RwLock::new(Vec::new()),
            cr3,
            tracker,
            handle_table: RwLock::new(HandleTable::new()),
            working_dir,
            default_queue: Arc::new(RwLock::new(MessageQueue {
                queue: VecDeque::new(),
            })),
            extra_queues: Mutex::new(BTreeMap::new()),
            routing_rules: Mutex::new(Vec::new()),
        }
    }

    pub fn virtual_map_alloc(&self, virt_addr: VirtAddr, size: usize) -> Result<(), PageMapError> {
        let start = virt_addr;
        let end = virt_addr + size as u64;

        self.tracker
            .alloc(start.as_u64(), size as u64)
            .map_err(|_| PageMapError::NoMemory())?;

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

            unsafe {
                map_range_with_huge_pages(
                    &mut mapper,
                    start,
                    end.as_u64() - start.as_u64(),
                    &mut frame_alloc,
                    flags,
                )
            }?;
            Ok(())
        })();

        unsafe { Cr3::write(old_cr3.0, old_cr3.1) };
        res
    }

    pub unsafe fn virtual_map(&self, virt_addr: VirtAddr, size: usize) -> Result<(), PageMapError> {
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

            map_range_with_huge_pages(
                &mut mapper,
                start,
                end.as_u64() - start.as_u64(),
                &mut frame_alloc,
                flags,
            )?;
            Ok(())
        })();

        Cr3::write(old_cr3.0, old_cr3.1);
        result
    }

    pub async fn load_module(&mut self, root_path: Path) -> Result<ModuleHandle, LoadError> {
        let mut queue = Vec::new();
        queue.push(root_path);

        let mut last_handle = None;

        while let Some(path) = queue.pop() {
            let mut loader = PELoader::new(&path).await.ok_or(LoadError::NoFile)?;
            let handle = loader.dll_load(self).await?;

            last_handle = Some(handle.clone());

            for dll in loader.list_import_dlls() {
                if self.has_module(&dll) {
                    continue;
                }

                let search_dirs = [
                    self.working_dir.clone(),
                    Path::from_string(r"C:\bin\mod"),
                    Path::from_string(r"C:\system"),
                ];

                let mut found = false;
                for dir in &search_dirs {
                    let candidate = dir.clone().join(&dll);
                    if PELoader::new(&candidate).await.is_some() {
                        queue.push(candidate);
                        found = true;
                        break;
                    }
                }

                if !found {
                    return Err(LoadError::NoFile);
                }
            }
        }

        last_handle.ok_or(LoadError::NotDLL)
    }

    pub fn kill(&mut self) -> Result<(), LoadError> {
        let main_tid = match &self.main_thread {
            Some(handle) => handle.inner.read().executer_id.unwrap(),
            None => return Err(LoadError::NoMainThread),
        };

        let managed = self.managed_threads.lock();

        loop {
            hlt();

            let mut running = managed.len() + 1;

            if SCHEDULER.get_task_by_id(main_tid).is_none() {
                running -= 1;
            }
            for tid in &*managed {
                if SCHEDULER
                    .get_task_by_id(tid.inner.read().executer_id.unwrap())
                    .is_none()
                {
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
    }

    pub fn find_import(&self, dll_name: &str, symbol_name: &str) -> Option<VirtAddr> {
        let modules = self.modules.read();

        for module in modules.iter() {
            if module.read().title.eq_ignore_ascii_case(dll_name) {
                if let Some(symbol) = module
                    .read()
                    .symbols
                    .iter()
                    .find(|(name, _)| name == symbol_name)
                {
                    return Some(module.read().image_base + symbol.1 as u64);
                }
            }
        }

        None
    }

    pub fn has_module(&self, name_lc: &str) -> bool {
        self.modules
            .read()
            .iter()
            .any(|m| m.read().title.eq_ignore_ascii_case(name_lc))
    }

    pub fn resolve_handle(&self, handle: UserHandle) -> Option<ObjectRef> {
        // Prefer local cache. Fallback to global index.
        self.handle_table
            .read()
            .resolve(handle)
            .or_else(|| OBJECT_MANAGER.open_by_id(handle))
    }

    pub fn create_user_handle_for_object(&self, obj: ObjectRef) -> UserHandle {
        let id = obj.id;
        self.handle_table.write().handles.insert(id, obj);
        id
    }

    pub fn new_mq(&self) -> ObjectRef {
        let qh = Arc::new(RwLock::new(MessageQueue {
            queue: VecDeque::new(),
        }));
        let base = alloc::format!("\\Proc\\{}\\Queues", self.pid);
        let _ = OBJECT_MANAGER.mkdir_p("\\Proc".to_string());
        let _ = OBJECT_MANAGER.mkdir_p(alloc::format!("\\Proc\\{}", self.pid));
        let _ = OBJECT_MANAGER.mkdir_p(base.clone());

        let name = guid_to_string(&generate_guid());
        let q_obj = Object::with_name(ObjectTag::Queue, name.clone(), ObjectPayload::Queue(qh));
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\{}", base, name), &q_obj);
        q_obj
    }

    pub fn has_handle(&self, pid: u64) -> Option<UserHandle> {
        self.handle_table.read().handle_to_program(pid)
    }

    pub fn add_routing_rule(&self, rule: RoutingRule) {
        let mut rules = self.routing_rules.lock();

        if let RoutingAction::Reroute(_) = rule.action {
            if rules
                .iter()
                .any(|r| r.msg_id == rule.msg_id && matches!(r.action, RoutingAction::Reroute(_)))
            {
                return;
            }
        }

        rules.push(rule);
    }

    pub fn clear_routing_rule(&self, msg_id: MessageId, from_pid: Option<u64>) {
        let mut rules = self.routing_rules.lock();
        rules.retain(|r| !(r.msg_id == msg_id && r.from_pid == from_pid));
    }

    pub fn receive_message(&self, msg: Message) {
        let rule_opt = {
            let rules = self.routing_rules.lock();
            rules
                .iter()
                .find(|r| {
                    r.msg_id == msg.id
                        && r.from_pid
                            .map_or(true, |pid| msg.sender.is_some() && r.from_pid == Some(pid))
                })
                .cloned()
        };

        match rule_opt.map(|r| r.action) {
            Some(RoutingAction::Block) => {}

            Some(RoutingAction::Allow) | None => {
                self.default_queue.write().queue.push_back(msg);
            }

            Some(RoutingAction::Reroute(qh)) => {
                qh.write().queue.push_back(msg);
            }

            Some(RoutingAction::Callback(th, qh_opt)) => {
                if let Some(qh) = qh_opt {
                    qh.write().queue.push_back(msg);
                } else {
                    self.default_queue.write().queue.push_back(msg);
                }

                let mut task = th;
                if task.is_terminated() {
                    return;
                }
            }
        }
    }
}

pub struct ProgramManager {
    next_pid: AtomicU64,
    programs: RwLock<BTreeMap<u64, ProgramHandle>>,
}

impl ProgramManager {
    pub const fn new() -> Self {
        Self {
            next_pid: AtomicU64::new(0),
            programs: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn add_program(&self, mut prog: Program) -> u64 {
        let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        prog.pid = pid;
        if let Some(ref mut task) = prog.main_thread {
            x86_64::instructions::interrupts::without_interrupts(move || {
                task.inner.write().parent_pid = pid;
            });
        }

        let handle = Arc::new(RwLock::new(prog));
        self.programs.write().insert(pid, handle.clone());

        let proc_dir = alloc::format!("\\Proc\\{}", pid);
        let _ = OBJECT_MANAGER.mkdir_p("\\Proc".to_string());
        let _ = OBJECT_MANAGER.mkdir_p(proc_dir.clone());

        let prog_obj = Object::with_name(
            ObjectTag::Program,
            "Program".to_string(),
            ObjectPayload::Program(handle.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\Program", proc_dir), &prog_obj);

        let dq_obj = Object::with_name(
            ObjectTag::Queue,
            "DefaultQueue".to_string(),
            ObjectPayload::Queue(handle.read().default_queue.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\DefaultQueue", proc_dir), &dq_obj);

        pid
    }

    pub fn get(&self, pid: u64) -> Option<ProgramHandle> {
        self.programs.read().get(&pid).map(Arc::clone)
    }

    pub fn start_pid(&self, pid: u64) -> Option<TaskHandle> {
        let handle = self.get(pid)?;
        let task_arc = {
            let prog = handle.write();
            Arc::clone(prog.main_thread.as_ref()?)
        };
        let tid = task_arc.task_id();
        SCHEDULER.add_task(task_arc);
        SCHEDULER.get_task_by_id(tid)
    }

    pub fn kill_program(&self, pid: u64) -> Result<(), LoadError> {
        let handle = self
            .programs
            .write()
            .remove(&pid)
            .ok_or(LoadError::BadPID)?;
        let _ = OBJECT_MANAGER.unlink(alloc::format!("\\Proc\\{}", pid));
        handle.write().kill()?;
        Ok(())
    }

    pub fn all(&self) -> Vec<ProgramHandle> {
        self.programs.read().values().cloned().collect()
    }
}

lazy_static! {
    pub static ref PROGRAM_MANAGER: ProgramManager = ProgramManager::new();
}
