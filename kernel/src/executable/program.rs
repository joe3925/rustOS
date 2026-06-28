use crate::platform::user_vm_layout;
use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;
use kernel_types::object_manager::ObjectTag;
use kernel_types::status::LoadError::NoSuchSymbol;
use kernel_types::{device::ModuleHandle, fs::Path, memory::PeInfo, status::PageMapError};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};

use crate::{
    executable::pe_loadable::PELoader,
    object_manager::{Object, ObjectPayload, OBJECT_MANAGER},
    platform,
    scheduling::task::TaskHandle,
    util::generate_guid,
};
use crate::{
    memory::paging::{map_range, unmap_range_unchecked, AddressSpaceRoot},
    scheduling::scheduler::SCHEDULER,
    structs::range_tracker::RangeTracker,
};
use kernel_types::arch::{PageFlags, VirtAddr};

use kernel_types::status::LoadError;

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

pub struct MessageQueue {
    queue: VecDeque<Message>,
    waiters: Vec<Waker>,
}

impl core::fmt::Debug for MessageQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MessageQueue")
            .field("queued", &self.queue.len())
            .field("waiters", &self.waiters.len())
            .finish()
    }
}

impl MessageQueue {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            waiters: Vec::new(),
        }
    }

    pub fn push_message(&mut self, msg: Message) {
        self.queue.push_back(msg);
        self.wake_waiters();
    }

    pub fn try_pop_message(&mut self) -> Option<Message> {
        self.queue.pop_front()
    }

    pub fn peek_message(&self) -> Option<&Message> {
        self.queue.front()
    }

    pub fn register_waker(&mut self, waker: &Waker) {
        if self
            .waiters
            .iter()
            .all(|existing| !existing.will_wake(waker))
        {
            self.waiters.push(waker.clone());
        }
    }

    pub fn wake_waiters(&mut self) {
        let waiters = core::mem::take(&mut self.waiters);
        for waiter in waiters {
            waiter.wake();
        }
    }
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
    pub pe_info: Option<PeInfo>,
    pub main_thread: Option<TaskHandle>,
    pub managed_threads: Mutex<Vec<TaskHandle>>,
    pub modules: RwLock<Vec<ModuleHandle>>,
    pub address_space_root: AddressSpaceRoot,
    pub tracker: Arc<RangeTracker>,

    pub handle_table: RwLock<HandleTable>,
    pub working_dir: Path,

    pub default_queue: QueueHandle,
    pub extra_queues: Mutex<BTreeMap<u64, QueueHandle>>,

    pub routing_rules: Mutex<RuleList>,
    pub page_table_lock: Mutex<()>,
}
impl Program {
    pub fn new(
        title: String,
        image_path: Path,
        image_base: VirtAddr,
        address_space_root: AddressSpaceRoot,
        tracker: Arc<RangeTracker>,
    ) -> Self {
        let working_dir = image_path.parent().unwrap_or(image_path.clone());
        Self {
            title,
            image_path,
            pid: 0,
            image_base,
            pe_info: None,
            main_thread: None,
            managed_threads: Mutex::new(Vec::new()),
            modules: RwLock::new(Vec::new()),
            address_space_root,
            tracker,
            handle_table: RwLock::new(HandleTable::new()),
            working_dir,
            default_queue: Arc::new(RwLock::new(MessageQueue::new())),
            page_table_lock: Mutex::new(()),
            extra_queues: Mutex::new(BTreeMap::new()),
            routing_rules: Mutex::new(Vec::new()),
        }
    }

    pub fn virtual_map_alloc(&self, virt_addr: VirtAddr, size: usize) -> Result<(), PageMapError> {
        let _guard = self.page_table_lock.lock();

        let start = virt_addr;
        let end = virt_addr + size as u64;
        self.tracker
            .alloc(start.as_u64(), size as u64)
            .map_err(|_| PageMapError::NoMemory())?;

        let old_address_space_root = crate::memory::paging::current_address_space_root();

        platform::with_interrupts_disabled(|| unsafe {
            crate::memory::paging::switch_address_space_root(self.address_space_root);
        });

        let res = (|| {
            let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE;

            unsafe { map_range(start.into(), end.as_u64() - start.as_u64(), flags, false) }
        })();

        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }

        res
    }
    pub unsafe fn virtual_map(&self, virt_addr: VirtAddr, size: usize) -> Result<(), PageMapError> {
        let start = virt_addr;
        let end = virt_addr + size as u64;
        let old_address_space_root = crate::memory::paging::current_address_space_root();

        unsafe {
            crate::memory::paging::switch_address_space_root(self.address_space_root);
        }

        let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE;
        let result =
            unsafe { map_range(start.into(), end.as_u64() - start.as_u64(), flags, false) };

        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }

        result
    }
    pub fn virtual_map_auto_alloc(&self, size: usize) -> Result<VirtAddr, PageMapError> {
        let _guard = self.page_table_lock.lock();
        let start: VirtAddr = self
            .tracker
            .alloc_auto(size as u64)
            .ok_or(PageMapError::NoMemory())?
            .into();
        let end = start + size as u64;

        let old_address_space_root = crate::memory::paging::current_address_space_root();

        platform::with_interrupts_disabled(|| unsafe {
            crate::memory::paging::switch_address_space_root(self.address_space_root);
        });

        let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE;

        unsafe {
            map_range(start.into(), end.as_u64() - start.as_u64(), flags, false)?;
        }
        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }

        Ok(start)
    }
    pub fn unmap_user_vm(&self, virt_addr: VirtAddr, size: usize) -> Result<(), PageMapError> {
        let size = crate::memory::paging::align_up_to_base_page(size as u64)
            .ok_or(PageMapError::NoMemory())?;

        if size == 0 {
            return Ok(());
        }

        let start = virt_addr.as_u64();
        let end = start.checked_add(size).ok_or(PageMapError::NoMemory())?;
        let layout = user_vm_layout();

        if start < layout.start || end > layout.end {
            return Err(PageMapError::NoMemory());
        }

        if start % layout.base_page_size != 0 {
            return Err(PageMapError::NoMemory());
        }

        let _guard = self.page_table_lock.lock();

        unsafe { self.tracker.dealloc(start, size) };

        let old_address_space_root = crate::memory::paging::current_address_space_root();

        platform::with_interrupts_disabled(|| unsafe {
            crate::memory::paging::switch_address_space_root(self.address_space_root);
            crate::memory::paging::unmap_range_unchecked(virt_addr.into(), size);
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        });

        Ok(())
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
            platform::enable_interrupts_and_halt();

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
            unsafe { unmap_range_unchecked(VirtAddr::new(start).into(), end - start) };
        }

        Ok(())
    }

    pub fn find_import(&self, dll_name: &str, symbol_name: &str) -> Result<VirtAddr, LoadError> {
        let want = strip_ext(dll_name);
        let modules = self.modules.read();

        for module in modules.iter() {
            let m = module.read();
            let have = strip_ext(&m.title);

            if have.eq_ignore_ascii_case(want) {
                if let Some((_, rva)) = m.symbols.iter().find(|(name, _)| name == symbol_name) {
                    return Ok((m.image_base + *rva as u64).into());
                }
            }
        }

        Err(NoSuchSymbol(symbol_name.to_string()))
    }

    pub fn has_module(&self, name_lc: &str) -> bool {
        let want = strip_ext(name_lc);

        self.modules
            .read()
            .iter()
            .any(|m| strip_ext(&m.read().title).eq_ignore_ascii_case(want))
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
        let qh = Arc::new(RwLock::new(MessageQueue::new()));
        let base = alloc::format!("\\Proc\\{}\\Queues", self.pid);
        let _ = OBJECT_MANAGER.mkdir_p("\\Proc");
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
                            .is_none_or(|pid| msg.sender.is_some() && r.from_pid == Some(pid))
                })
                .cloned()
        };

        match rule_opt.map(|r| r.action) {
            Some(RoutingAction::Block) => {}

            Some(RoutingAction::Allow) | None => {
                self.default_queue.write().push_message(msg);
            }

            Some(RoutingAction::Reroute(qh)) => {
                qh.write().push_message(msg);
            }

            Some(RoutingAction::Callback(th, qh_opt)) => {
                if let Some(qh) = qh_opt {
                    qh.write().push_message(msg);
                } else {
                    self.default_queue.write().push_message(msg);
                }

                let task = th;
                if task.is_terminated() {}
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
            platform::with_interrupts_disabled(move || {
                task.inner.write().parent_pid = pid;
            });
        }

        let handle = Arc::new(RwLock::new(prog));
        self.programs.write().insert(pid, handle.clone());

        let proc_dir = alloc::format!("\\Proc\\{}", pid);
        let _ = OBJECT_MANAGER.mkdir_p("\\Proc");
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
fn basename(s: &str) -> &str {
    s.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(s)
}
fn strip_ext(s: &str) -> &str {
    let s = basename(s);

    match s.rfind('.') {
        Some(0) | None => s,
        Some(dot) => &s[..dot],
    }
}
lazy_static! {
    pub static ref PROGRAM_MANAGER: ProgramManager = ProgramManager::new();
}
