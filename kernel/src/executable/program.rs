use core::sync::atomic::{AtomicU64, Ordering};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    string::String,
    sync::Arc,
    vec::Vec,
};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use x86_64::{
    instructions::{hlt, interrupts},
    registers::control::Cr3,
    structures::paging::{mapper::MapToError, Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    memory::paging::paging::map_page,
    scheduling::scheduler::{self, Scheduler, TaskHandle},
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
#[derive(Clone)]
pub struct Module {
    pub title: String,
    pub image_path: String,
    pub parent_pid: u64,
    pub image_base: VirtAddr,
    pub symbols: Vec<(String, usize)>,
}

pub type ProgramHandle = Arc<RwLock<Program>>;
pub type QueueHandle = Arc<RwLock<MessageQueue>>;

pub type UserHandle = u64;

pub struct MessageQueue {
    pub queue: VecDeque<Message>,
}

#[derive(Clone)]
pub enum HandleTarget {
    Program(ProgramHandle),
    MessageQueue(u64, QueueHandle),
    Thread(TaskHandle),
}
pub struct HandleTable {
    pub handles: BTreeMap<UserHandle, HandleTarget>,
}
impl HandleTable {
    pub fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
        }
    }
    pub fn resolve(&self, handle: UserHandle) -> Option<HandleTarget> {
        self.handles.get(&handle).cloned()
    }
    pub fn handle_to_program(&self, target_pid: u64) -> Option<UserHandle> {
        self.handles
            .iter()
            .find_map(|(user_handle, target)| match target {
                HandleTarget::Program(program_handle) => {
                    if program_handle.read().pid == target_pid {
                        Some(*user_handle)
                    } else {
                        None
                    }
                }
                _ => None,
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
    User(u32), // Must be >= 0x8000
}
#[derive(Debug, Clone)]
pub struct Message {
    pub id: MessageId,
    pub sender: Option<UserHandle>,
    pub wparam: usize,
    pub lparam: usize,
    pub timestamp: u64,
}

#[derive(Clone)]
pub enum RoutingAction {
    /// Drop the message (it never reaches any queue)
    Block,

    /// Deliver to the program’s default queue (same as no rule)
    Allow,

    /// Deliver to this queue instead of the default queue
    Reroute(QueueHandle),

    /// Wake a specific thread when a message arrives
    /// (thread will still have to pop the message itself)
    Callback(TaskHandle, Option<QueueHandle>),
}

#[derive(Clone)]
pub struct RoutingRule {
    /// Which message ID the rule applies to
    pub msg_id: MessageId,

    /// Optional sender-PID filter (`None` = any sender)
    pub from_pid: Option<u64>,

    /// Action taken when the rule matches
    pub action: RoutingAction,
}

pub type RuleList = Vec<RoutingRule>;
pub struct Program {
    pub title: String,
    pub image_path: String,
    pub pid: u64,
    pub image_base: VirtAddr,
    pub main_thread: Option<TaskHandle>,
    pub managed_threads: Mutex<Vec<TaskHandle>>,
    pub modules: Mutex<Vec<Module>>,
    pub cr3: PhysFrame,
    pub tracker: Arc<RangeTracker>,
    pub handle_table: RwLock<HandleTable>,
    pub working_dir: String,
    pub default_queue: QueueHandle,
    pub extra_queues: Mutex<BTreeMap<u64, QueueHandle>>,
    pub routing_rules: Mutex<RuleList>,
}
impl Program {
    pub fn new(
        title: String,
        image_path: String,
        image_base: VirtAddr,
        cr3: PhysFrame,
        tracker: Arc<RangeTracker>,
    ) -> Self {
        Self {
            title,
            image_path: image_path.clone(),
            pid: 0,
            image_base,
            main_thread: None,
            managed_threads: Mutex::new(Vec::new()),
            modules: Mutex::new(Vec::new()),
            cr3,
            tracker,
            handle_table: RwLock::new(HandleTable::new()),
            working_dir: image_path,
            default_queue: Arc::new(RwLock::new(MessageQueue {
                queue: VecDeque::new(),
            })),
            extra_queues: Mutex::new(BTreeMap::new()),
            routing_rules: Mutex::new(Vec::new()),
        }
    }
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
        let main_tid = match &self.main_thread {
            Some(handle) => handle.read().id,
            None => return Err(LoadError::NoMainThread),
        };

        let managed = self.managed_threads.lock();

        loop {
            hlt();

            let scheduler = SCHEDULER.lock();
            let mut running = managed.len() + 1;

            if scheduler.get_task_by_id(main_tid).is_none() {
                running -= 1;
            }
            for tid in &*managed {
                if scheduler.get_task_by_id(tid.read().id).is_none() {
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
        let modules = self.modules.lock();

        for module in modules.iter() {
            if module.title.eq_ignore_ascii_case(dll_name) {
                if let Some(symbol) = module.symbols.iter().find(|(name, _)| name == symbol_name) {
                    return Some(module.image_base + symbol.1 as u64);
                }
            }
        }

        None
    }
    pub fn has_module(&self, name_lc: &str) -> bool {
        self.modules
            .lock()
            .iter()
            .any(|m| m.title.eq_ignore_ascii_case(name_lc))
    }
    pub fn resolve_handle(&self, handle: UserHandle) -> Option<HandleTarget> {
        let table = self.handle_table.read();
        table.handles.get(&handle).cloned()
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
    pub fn receive_message(&self, mut msg: Message) {
        // ── find first matching rule ────────────────────────────────────────────
        let rule_opt = {
            let rules = self.routing_rules.lock();
            rules
                .iter()
                .find(|r| {
                    r.msg_id == msg.id
                        && r.from_pid
                            .map_or(true, |pid| msg.sender.map(|_| pid).is_some())
                })
                .cloned()
        };

        match rule_opt.map(|r| r.action) {
            Some(RoutingAction::Block) => return,

            Some(RoutingAction::Allow) | None => {
                self.default_queue.write().queue.push_back(msg);
            }

            Some(RoutingAction::Reroute(qh)) => {
                qh.write().queue.push_back(msg);
            }

            Some(RoutingAction::Callback(th, qh)) => {
                if let Some(q) = qh {
                    q.write().queue.push_back(msg);
                } else {
                    self.default_queue.write().queue.push_back(msg);
                }

                let mut task = th.write();
                if task.terminated {
                    return;
                }
                if task.is_sleeping {
                    task.is_sleeping = false;
                }
            }
        }
    }
    pub fn create_user_handle(&self, target: HandleTarget) -> UserHandle {
        let mut table = self.handle_table.write();

        loop {
            let raw = random_number();

            if raw != 0 && !table.handles.contains_key(&raw) {
                table.handles.insert(raw, target.clone());
                return raw;
            }
        }
    }
    pub fn new_mq(&self) -> HandleTarget {
        let handle = {
            let qh = Arc::new(RwLock::new(MessageQueue {
                queue: VecDeque::new(),
            }));
            HandleTarget::MessageQueue(self.pid, qh)
        };

        handle
    }
    pub fn has_handle(&self, pid: u64) -> Option<UserHandle> {
        self.handle_table.read().handle_to_program(pid)
    }
}
pub struct ProgramManager {
    next_pid: AtomicU64,
    programs: RwLock<BTreeMap<u64, ProgramHandle>>, // pid → Arc
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
            interrupts::without_interrupts(move || {
                task.write().parent_pid = pid;
            });
        }

        let handle = Arc::new(RwLock::new(prog));
        self.programs.write().insert(pid, handle);
        pid
    }

    pub fn get(&self, pid: u64) -> Option<ProgramHandle> {
        self.programs.read().get(&pid).map(Arc::clone)
    }
    pub fn start_pid(&self, pid: u64, scheduler: &mut Scheduler) -> Option<TaskHandle> {
        let handle = self.get(pid)?;

        let task_arc = {
            let prog = handle.write();
            Arc::clone(prog.main_thread.as_ref()?)
        };
        let tid = task_arc.read().id;
        scheduler.add_task(task_arc);
        scheduler.get_task_by_id(tid)
    }

    pub fn kill_program(&self, pid: u64) -> Result<(), LoadError> {
        let handle = self
            .programs
            .write()
            .remove(&pid)
            .ok_or(LoadError::BadPID)?;

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
