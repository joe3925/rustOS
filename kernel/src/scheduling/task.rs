use crate::arch::paging::PageTableFlags;
use crate::arch::scheduling::task_return_trampoline;
use crate::arch::VirtAddr;
use crate::cpu::get_cpu_info;
use crate::drivers::interrupt_index::current_is_in_interrupt_atomic;
use crate::gdt::PER_CPU_GDT;
use crate::memory::paging::paging::map_kernel_range;
use crate::memory::paging::stack::{allocate_kernel_stack, deallocate_kernel_stack, StackSize};
use crate::scheduling::domain::{DomainId, TaskSchedBinding};
use crate::scheduling::scheduler::default_task_sched_binding;
use crate::scheduling::state::{BlockReason, FpuState, SchedState, State};
use crate::scheduling::tls::KernelTls;
use crate::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use kernel_types::status::PageMapError;
use spin::Mutex;
use spin::RwLock;
pub type TaskEntry = crate::arch::scheduling::TaskEntry;

const PAGE_SIZE: u64 = 4096;
const C_SHADOW_SPACE_BYTES: u64 = 32;
const RETURN_ADDRESS_BYTES: u64 = 8;
const C_ENTRY_FRAME_BYTES: u64 = RETURN_ADDRESS_BYTES + C_SHADOW_SPACE_BYTES;

pub const IDLE_UUID_UPPER: u64 = 0x1c82f35548bcbe24;
pub const IDLE_MAGIC_LOWER: u64 = 0x890189d70ecaca7f;
/// Sentinel value indicating no task in wait queue
pub const WAIT_QUEUE_NONE: u64 = 0;
#[derive(Debug)]
/// TaskRef is the primary handle to a task, containing:
/// - Atomic scheduling state accessible without locks (for scheduler hot path)
/// - Inner Task data behind RwLock (for context, stack info, etc.)
///
/// This separation allows the scheduler to check task state and make
/// scheduling decisions without contending on the Task RwLock.
pub struct TaskRef {
    /// Unique task identifier (immutable after creation)
    pub id: AtomicU64,

    /// Current scheduling state (Runnable, Running, Parking, Blocked, Terminated)
    /// Accessed atomically by scheduler without taking inner lock
    sched_state: AtomicU8,

    /// Preferred CPU for this task's run queue
    /// Used by unpark() to decide where to enqueue
    target_cpu: AtomicUsize,

    /// Park/unpark permit token (0 or 1)
    /// - unpark() sets this to 1
    /// - park_current() consumes it (swap to 0)
    /// This prevents lost wakeups via the commit-point handshake
    permit: AtomicU8,

    /// Why this task is blocked (for diagnostics)
    block_reason: AtomicU32,

    /// Intrusive wait queue link - holds task ID of next waiter (or WAIT_QUEUE_NONE)
    /// Used for mutex, condvar, channel wait queues
    pub wait_next: AtomicU64,

    /// Intrusive wait queue link for IPI scheduling
    pub inbound_next: AtomicU64,

    /// The inner task data (context, stack, etc.) - requires lock for access
    pub inner: RwLock<Task>,

    /// Fast path for kernel mode check
    pub is_kernel_mode: AtomicBool,

    /// Top of the allocated stack region (write-once, read lock-free)
    pub stack_start: AtomicU64,

    /// Current guard page address; advanced downward on each stack growth.
    /// Written only by the page-fault handler while the task is running on
    /// this CPU — no lock needed.
    pub guard_page: AtomicU64,

    /// Total reserved stack bytes (write-once, read lock-free)
    pub stack_size: AtomicU64,

    /// Scheduler-restored kernel TLS pointer for this task.
    pub tls_thread_pointer: AtomicU64,

    /// Active scheduler-domain binding and erased scheduler-class state.
    sched_binding: RwLock<TaskSchedBinding>,
    active_domain_id: AtomicU32,

    /// Lazy domain migration target. The scheduler commits this at a point
    /// where the task is not owned by an old-domain run queue.
    pending_sched_binding: Mutex<Option<TaskSchedBinding>>,

    /// Fast negative check for the common path where no lazy migration exists.
    pending_sched_binding_present: AtomicBool,
}

/// Handle type used throughout the scheduler
pub type TaskHandle = Arc<TaskRef>;

impl TaskRef {
    /// Get the current scheduling state
    #[inline(always)]
    pub fn sched_state(&self) -> SchedState {
        SchedState::from_u8(self.sched_state.load(Ordering::Acquire))
    }

    /// Set the scheduling state
    #[inline(always)]
    pub fn set_sched_state(&self, state: SchedState) {
        self.sched_state.store(state as u8, Ordering::Release);
    }

    /// Compare-and-swap scheduling state
    /// Returns Ok(()) if successful, Err(actual) if the current state didn't match expected
    #[inline(always)]
    pub fn cas_sched_state(&self, expected: SchedState, new: SchedState) -> Result<(), SchedState> {
        match self.sched_state.compare_exchange(
            expected as u8,
            new as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(actual) => Err(SchedState::from_u8(actual)),
        }
    }

    /// Get the target CPU for this task
    #[inline(always)]
    pub fn target_cpu(&self) -> usize {
        self.target_cpu.load(Ordering::Relaxed)
    }

    /// Set the target CPU for this task
    #[inline(always)]
    pub fn set_target_cpu(&self, cpu: usize) {
        self.target_cpu.store(cpu, Ordering::Relaxed);
    }

    /// Check if task is terminated (convenience method)
    #[inline(always)]
    pub fn is_terminated(&self) -> bool {
        self.sched_state() == SchedState::Terminated
    }

    /// Mark the task as terminated
    #[inline(always)]
    pub fn terminate(&self) {
        self.set_sched_state(SchedState::Terminated);
    }

    /// Deliver a wake permit (called by unpark)
    /// Returns the previous permit value
    #[inline(always)]
    pub fn grant_permit(&self) -> u8 {
        self.permit.swap(1, Ordering::Release)
    }

    /// Consume the wake permit (called by park_current)
    /// Returns true if a permit was available (no need to block)
    #[inline(always)]
    pub fn consume_permit(&self) -> bool {
        self.permit.swap(0, Ordering::Acquire) == 1
    }

    /// Check if permit is available without consuming
    #[inline(always)]
    pub fn has_permit(&self) -> bool {
        self.permit.load(Ordering::Acquire) == 1
    }

    /// Get the task ID
    #[inline(always)]
    pub fn task_id(&self) -> u64 {
        self.id.load(Ordering::Relaxed)
    }

    /// Set the task ID (should only be called once during task creation)
    #[inline(always)]
    pub fn set_task_id(&self, id: u64) {
        self.id.store(id, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn domain_id(&self) -> DomainId {
        DomainId(self.active_domain_id.load(Ordering::Acquire) as u16)
    }

    #[inline(always)]
    pub(crate) fn with_class_state<T, R>(
        &self,
        expected_domain: DomainId,
        f: impl FnOnce(&T) -> R,
    ) -> R {
        let binding = self.sched_binding.read();
        assert_eq!(
            binding.domain_id(),
            expected_domain,
            "task scheduled through non-owning domain"
        );

        let ptr = binding.class_state();
        f(unsafe { ptr.cast::<T>().as_ref() })
    }

    pub(crate) fn set_pending_sched_binding(
        &self,
        sched_binding: TaskSchedBinding,
    ) -> Result<(), TaskSchedBinding> {
        let mut pending = self.pending_sched_binding.lock();
        if pending.is_some() {
            return Err(sched_binding);
        }

        *pending = Some(sched_binding);
        self.pending_sched_binding_present
            .store(true, Ordering::Release);
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn has_pending_sched_binding(&self) -> bool {
        self.pending_sched_binding_present.load(Ordering::Acquire)
    }

    pub(crate) fn take_pending_sched_binding(&self) -> Option<TaskSchedBinding> {
        if !self.has_pending_sched_binding() {
            return None;
        }

        let mut pending = self.pending_sched_binding.lock();
        let binding = pending.take();
        self.pending_sched_binding_present
            .store(false, Ordering::Release);
        binding
    }

    pub(crate) fn replace_sched_binding(
        &self,
        sched_binding: TaskSchedBinding,
    ) -> TaskSchedBinding {
        let new_domain_id = sched_binding.domain_id();
        let mut active = self.sched_binding.write();
        let old = core::mem::replace(&mut *active, sched_binding);
        self.active_domain_id
            .store(new_domain_id.0 as u32, Ordering::Release);
        old
    }

    /// Attempt to grow the kernel stack by one page.
    ///
    /// Called from the page-fault handler without holding `inner` — safe
    /// because a task can only fault on the CPU it is currently running on,
    /// so there is no concurrent writer for `guard_page`.
    pub fn grow_stack(&self, flags: PageTableFlags) -> Result<bool, PageMapError> {
        if !self.is_kernel_mode.load(Ordering::Relaxed) {
            return Ok(false);
        }

        let gp = self.guard_page.load(Ordering::Acquire);
        if gp == 0 {
            return Ok(false);
        }

        let next_guard = match gp.checked_sub(PAGE_SIZE) {
            Some(v) => v,
            None => return Ok(false),
        };

        unsafe {
            map_kernel_range(VirtAddr::new(gp), PAGE_SIZE, flags, false)?;
        }

        let stack_top = self.stack_start.load(Ordering::Acquire);
        if stack_top != 0 && gp < stack_top {
            self.stack_size.store(stack_top - gp, Ordering::Release);
        } else {
            self.stack_size.fetch_add(PAGE_SIZE, Ordering::AcqRel);
        }

        self.guard_page.store(next_guard, Ordering::Release);

        Ok(true)
    }

    /// Unmap the kernel stack backing this task.
    pub fn destroy(&self) {
        if !self.is_kernel_mode.load(Ordering::Relaxed) {
            return;
        }
        let stack_top = self.stack_start.swap(0, Ordering::AcqRel);
        if stack_top == 0 {
            return;
        }

        self.guard_page.store(0, Ordering::Release);
        self.stack_size.store(0, Ordering::Release);
        deallocate_kernel_stack(VirtAddr::new(stack_top));
    }
}

impl Drop for TaskRef {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// Inner task data - accessed through RwLock
#[derive(Debug)]
pub struct Task {
    pub name: String,
    pub context: State,
    pub fpu_state: FpuState,
    pub kernel_tls: Option<KernelTls>,
    pub is_user_mode: bool,
    pub parent_pid: u64,
    pub executer_id: Option<u64>,

    // Accounting (can be accessed via inner lock or made atomic if needed)
    sched_in_cycles: AtomicU64,
    last_quantum_cycles: AtomicU64,
    total_run_cycles: AtomicU64,
    quantum_count: AtomicU64,
    last_cpu: AtomicUsize,
}

impl Task {
    pub fn new_user_mode(
        entry_point: TaskEntry,
        context: usize,
        stack_size: u64,
        name: String,
        stack_pointer: VirtAddr,
        parent_pid: u64,
    ) -> TaskHandle {
        Self::new_user_mode_with_sched_binding(
            entry_point,
            context,
            stack_size,
            name,
            stack_pointer,
            parent_pid,
            default_task_sched_binding(),
        )
    }

    pub fn new_user_mode_with_sched_binding(
        entry_point: TaskEntry,
        context: usize,
        stack_size: u64,
        name: String,
        stack_pointer: VirtAddr,
        parent_pid: u64,
        sched_binding: TaskSchedBinding,
    ) -> TaskHandle {
        let gdt = PER_CPU_GDT.lock();
        let cpu_id = get_cpu_info()
            .get_feature_info()
            .expect("NO CPUID")
            .initial_local_apic_id();

        let stack_top = stack_pointer.as_u64();
        let guard_page = initial_guard_page(stack_top, stack_size);

        let mut state = State::new(0);
        state.rip = entry_point as u64;
        state.rcx = context as u64;
        state.rsp = initial_c_entry_rsp(stack_top);
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = task_return_trampoline as *const () as u64;
        }

        let selectors = gdt.selectors_per_cpu.get_by_id(cpu_id as usize);
        state.cs = selectors.user_code_selector.0 as u64 | 3;
        state.ss = selectors.user_data_selector.0 as u64 | 3;

        let inner_task = Task {
            name,
            context: state,
            fpu_state: FpuState::default(),
            kernel_tls: None,
            is_user_mode: true,
            parent_pid,
            executer_id: None,
            sched_in_cycles: AtomicU64::new(0),
            last_quantum_cycles: AtomicU64::new(0),
            total_run_cycles: AtomicU64::new(0),
            quantum_count: AtomicU64::new(0),
            last_cpu: AtomicUsize::new(usize::MAX),
        };

        let active_domain_id = sched_binding.domain_id();

        Arc::new(TaskRef {
            id: AtomicU64::new(0),
            sched_state: AtomicU8::new(SchedState::Runnable as u8),
            target_cpu: AtomicUsize::new(cpu_id as usize),
            permit: AtomicU8::new(0),
            block_reason: AtomicU32::new(BlockReason::None as u32),
            wait_next: AtomicU64::new(WAIT_QUEUE_NONE),
            inbound_next: AtomicU64::new(0),
            inner: RwLock::new(inner_task),
            is_kernel_mode: AtomicBool::new(false),
            stack_start: AtomicU64::new(stack_top),
            guard_page: AtomicU64::new(guard_page),
            stack_size: AtomicU64::new(stack_size),
            tls_thread_pointer: AtomicU64::new(0),
            sched_binding: RwLock::new(sched_binding),
            active_domain_id: AtomicU32::new(active_domain_id.0 as u32),
            pending_sched_binding: Mutex::new(None),
            pending_sched_binding_present: AtomicBool::new(false),
        })
    }

    pub fn new_kernel_mode(
        entry_point: TaskEntry,
        context: usize,
        stack_size: StackSize,
        name: String,
        parent_pid: u64,
    ) -> TaskHandle {
        Self::new_kernel_mode_with_sched_binding(
            entry_point,
            context,
            stack_size,
            name,
            parent_pid,
            default_task_sched_binding(),
        )
    }

    pub fn new_kernel_mode_with_sched_binding(
        entry_point: TaskEntry,
        context: usize,
        stack_size: StackSize,
        name: String,
        parent_pid: u64,
        sched_binding: TaskSchedBinding,
    ) -> TaskHandle {
        let gdt = PER_CPU_GDT.lock();
        let cpu_id = get_cpu_info()
            .get_feature_info()
            .expect("NO CPUID")
            .initial_local_apic_id();

        let stack_top = allocate_kernel_stack(stack_size).expect("Failed to allocate stack");
        let stack_top_u64 = stack_top.as_u64();
        let guard_page = initial_guard_page(stack_top_u64, stack_size.as_bytes());

        let mut state = State::new(0);
        state.rip = entry_point as u64;
        state.rcx = context as u64;
        state.rsp = initial_c_entry_rsp(stack_top_u64);
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = task_return_trampoline as *const () as u64;
        }

        let selectors = gdt.selectors_per_cpu.get_by_id(cpu_id as usize);
        state.cs = selectors.kernel_code_selector.0 as u64;
        state.ss = selectors.kernel_data_selector.0 as u64;

        let kernel_tls = KernelTls::for_kernel_thread();
        let tls_thread_pointer = kernel_tls.as_ref().map_or(0, KernelTls::thread_pointer);

        let inner_task = Task {
            name,
            context: state,
            fpu_state: FpuState::default(),
            kernel_tls,
            is_user_mode: false,
            parent_pid,
            executer_id: None,
            sched_in_cycles: AtomicU64::new(0),
            last_quantum_cycles: AtomicU64::new(0),
            total_run_cycles: AtomicU64::new(0),
            quantum_count: AtomicU64::new(0),
            last_cpu: AtomicUsize::new(usize::MAX),
        };

        let active_domain_id = sched_binding.domain_id();

        Arc::new(TaskRef {
            id: AtomicU64::new(0),
            sched_state: AtomicU8::new(SchedState::Runnable as u8),
            target_cpu: AtomicUsize::new(cpu_id as usize),
            permit: AtomicU8::new(0),
            block_reason: AtomicU32::new(BlockReason::None as u32),
            wait_next: AtomicU64::new(WAIT_QUEUE_NONE),
            inbound_next: AtomicU64::new(0),
            inner: RwLock::new(inner_task),
            is_kernel_mode: AtomicBool::new(true),
            stack_start: AtomicU64::new(stack_top_u64),
            guard_page: AtomicU64::new(guard_page),
            stack_size: AtomicU64::new(stack_size.as_bytes()),
            tls_thread_pointer: AtomicU64::new(tls_thread_pointer),
            sched_binding: RwLock::new(sched_binding),
            active_domain_id: AtomicU32::new(active_domain_id.0 as u32),
            pending_sched_binding: Mutex::new(None),
            pending_sched_binding_present: AtomicBool::new(false),
        })
    }

    pub fn update_from_context(&mut self, context: *mut State) {
        self.context = unsafe { *context };
    }

    #[inline(always)]
    pub fn mark_scheduled_in(&self, cpu_id: usize, now_cycles: u64) {
        self.last_cpu.store(cpu_id, Ordering::Relaxed);
        self.sched_in_cycles.store(now_cycles, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn account_switched_out(&self, now_cycles: u64) {
        let start = self.sched_in_cycles.swap(0, Ordering::Relaxed);
        if start == 0 || now_cycles <= start {
            return;
        }
        let delta = now_cycles - start;
        self.last_quantum_cycles.store(delta, Ordering::Relaxed);
        self.total_run_cycles.fetch_add(delta, Ordering::Relaxed);
        self.quantum_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn last_cpu(&self) -> usize {
        self.last_cpu.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn save_fpu_state(&mut self) {
        self.fpu_state.save();
    }

    #[inline(always)]
    pub fn restore_fpu_state(&mut self) {
        self.fpu_state.restore();
    }
}

fn initial_guard_page(stack_top: u64, stack_size: u64) -> u64 {
    if stack_top == 0 || stack_size == 0 {
        return 0;
    }
    let bottom = match stack_top.checked_sub(stack_size) {
        Some(v) => v,
        None => return 0,
    };
    match bottom.checked_sub(PAGE_SIZE) {
        Some(v) => v,
        None => 0,
    }
}

fn initial_c_entry_rsp(stack_top: u64) -> u64 {
    // On the current PE/COFF MSVC target, extern "C" uses the Windows x64 ABI:
    // [rsp] return address, [rsp+8..rsp+40) caller-allocated shadow space.
    (stack_top & !0xf).saturating_sub(C_ENTRY_FRAME_BYTES)
}
pub(crate) struct CurrentTask {
    ptr: AtomicPtr<TaskRef>,
}

impl CurrentTask {
    #[inline(always)]
    pub(crate) fn new(task: &TaskHandle) -> Self {
        Self {
            ptr: AtomicPtr::new(Arc::as_ptr(task) as *mut TaskRef),
        }
    }

    #[inline(always)]
    pub(crate) fn store(&self, task: &TaskHandle) {
        self.ptr
            .store(Arc::as_ptr(task) as *mut TaskRef, Ordering::Release);
    }

    #[inline(always)]
    pub(crate) fn load(&self) -> Option<TaskHandle> {
        let p = self.ptr.load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }

        unsafe {
            Arc::increment_strong_count(p);
            Some(Arc::from_raw(p))
        }
    }

    #[inline(always)]
    pub(crate) fn is_task(&self, task: &TaskHandle) -> bool {
        let p = self.ptr.load(Ordering::Acquire);
        core::ptr::eq(p, Arc::as_ptr(task) as *mut TaskRef)
    }
}

const TASK_ID_INDEX_BITS: u64 = 32;
const TASK_ID_INDEX_MASK: u64 = (1u64 << TASK_ID_INDEX_BITS) - 1;
const TASK_ID_MAX_GENERATION: u64 = 1u64 << (64 - TASK_ID_INDEX_BITS);

#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
}

const TASK_SLOT_EMPTY: usize = 0;
const TASK_SLOT_RESERVED: usize = 1;
const TASK_SLOT_LIVE: usize = 2;
const TASK_SLOT_RETIRED: usize = 3;
const TASK_SLOT_REAPING: usize = 4;

struct TaskSlot {
    generation: AtomicU64,
    readers: AtomicUsize,
    retired_next: AtomicUsize,
    ptr: AtomicPtr<TaskRef>,
    state: AtomicUsize,
}

pub(crate) struct TaskTable {
    slots: Box<[TaskSlot]>,
    free_hint: AtomicUsize,
    retired_head: AtomicUsize,
    reap_lock: Mutex<()>,
}

impl TaskSlot {
    #[inline(always)]
    fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            readers: AtomicUsize::new(0),
            retired_next: AtomicUsize::new(0),
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            state: AtomicUsize::new(TASK_SLOT_EMPTY),
        }
    }
}

impl TaskTable {
    pub(crate) fn new(initial_slots: usize) -> Self {
        if initial_slots == 0 || initial_slots as u64 > TASK_ID_INDEX_MASK {
            panic!("bad fixed task table capacity");
        }

        let slot_count = initial_slots
            .checked_add(1)
            .expect("fixed task table capacity overflow");
        let mut slots = Vec::with_capacity(slot_count);

        for _ in 0..slot_count {
            slots.push(TaskSlot::new());
        }

        Self {
            slots: slots.into_boxed_slice(),
            free_hint: AtomicUsize::new(0),
            retired_head: AtomicUsize::new(0),
            reap_lock: Mutex::new(()),
        }
    }

    #[inline(always)]
    fn readable_state(state: usize) -> bool {
        state == TASK_SLOT_LIVE
    }

    #[inline(always)]
    fn make_id(idx: usize, generation: u64) -> u64 {
        if idx == 0 || idx as u64 > TASK_ID_INDEX_MASK {
            panic!("task id index overflow");
        }
        if generation >= TASK_ID_MAX_GENERATION {
            panic!("task id generation overflow");
        }

        (generation << TASK_ID_INDEX_BITS) | idx as u64
    }

    #[inline(always)]
    fn decode_id(id: u64) -> Option<(usize, u64)> {
        let idx = (id & TASK_ID_INDEX_MASK) as usize;
        let generation = id >> TASK_ID_INDEX_BITS;

        if idx == 0 {
            return None;
        }

        Some((idx, generation))
    }

    #[inline(always)]
    fn slot(&self, idx: usize) -> Option<&TaskSlot> {
        if idx == 0 {
            return None;
        }

        self.slots.get(idx)
    }

    #[inline(always)]
    fn try_insert_at(&self, idx: usize, task: &TaskHandle) -> Option<u64> {
        let slot = self.slot(idx)?;
        if slot
            .state
            .compare_exchange(
                TASK_SLOT_EMPTY,
                TASK_SLOT_RESERVED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }

        let generation = slot.generation.load(Ordering::Acquire);
        let id = Self::make_id(idx, generation);
        task.set_task_id(id);

        let raw = Arc::into_raw(task.clone()) as *mut TaskRef;
        slot.retired_next.store(0, Ordering::Release);
        slot.ptr.store(raw, Ordering::Release);
        slot.state.store(TASK_SLOT_LIVE, Ordering::Release);
        Some(id)
    }

    pub(crate) fn insert(&self, task: &TaskHandle) -> Option<u64> {
        let hinted = self.free_hint.swap(0, Ordering::AcqRel);

        if hinted != 0 && hinted < self.slots.len() {
            if let Some(id) = self.try_insert_at(hinted, task) {
                return Some(id);
            }
        }

        for idx in 1..self.slots.len() {
            if let Some(id) = self.try_insert_at(idx, task) {
                return Some(id);
            }
        }

        None
    }

    #[inline(always)]
    pub(crate) fn get(&self, id: u64) -> Option<TaskHandle> {
        let (idx, generation) = Self::decode_id(id)?;
        let slot = self.slot(idx)?;

        let state = slot.state.load(Ordering::Acquire);
        if !Self::readable_state(state) {
            return None;
        }

        if slot.generation.load(Ordering::Acquire) != generation {
            return None;
        }

        slot.readers.fetch_add(1, Ordering::Acquire);

        let state = slot.state.load(Ordering::Acquire);
        if !Self::readable_state(state) || slot.generation.load(Ordering::Acquire) != generation {
            slot.readers.fetch_sub(1, Ordering::Release);
            return None;
        }

        let p = slot.ptr.load(Ordering::Acquire);
        if p.is_null() {
            slot.readers.fetch_sub(1, Ordering::Release);
            return None;
        }

        unsafe {
            Arc::increment_strong_count(p);
        }

        slot.readers.fetch_sub(1, Ordering::Release);

        unsafe { Some(Arc::from_raw(p)) }
    }

    #[inline(always)]
    fn push_retired_idx(&self, idx: usize) -> bool {
        let Some(slot) = self.slot(idx) else {
            return false;
        };

        let mut head = self.retired_head.load(Ordering::Acquire);
        loop {
            slot.retired_next.store(head, Ordering::Relaxed);
            match self.retired_head.compare_exchange_weak(
                head,
                idx,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(new_head) => head = new_head,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn retire(&self, id: u64, task: &TaskHandle) -> bool {
        let Some((idx, generation)) = Self::decode_id(id) else {
            return false;
        };

        let Some(slot) = self.slot(idx) else {
            return false;
        };

        if slot.generation.load(Ordering::Acquire) != generation {
            return false;
        }

        let expected = Arc::as_ptr(task) as *mut TaskRef;
        if slot.ptr.load(Ordering::Acquire) != expected {
            return false;
        }

        if slot
            .state
            .compare_exchange(
                TASK_SLOT_LIVE,
                TASK_SLOT_RETIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }

        if !self.push_retired_idx(idx) {
            panic!("failed to enqueue retired task slot");
        }

        true
    }

    fn reap_one_retired_idx(&self, idx: usize) -> Option<*mut TaskRef> {
        let Some(slot) = self.slot(idx) else {
            return None;
        };

        if slot.state.load(Ordering::Acquire) != TASK_SLOT_RETIRED {
            return None;
        }

        if slot.readers.load(Ordering::Acquire) != 0 {
            if !self.push_retired_idx(idx) {
                panic!("failed to requeue retired task slot");
            }
            return None;
        }

        if slot
            .state
            .compare_exchange(
                TASK_SLOT_RETIRED,
                TASK_SLOT_REAPING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }

        if slot.readers.load(Ordering::Acquire) != 0 {
            slot.state.store(TASK_SLOT_RETIRED, Ordering::Release);
            if !self.push_retired_idx(idx) {
                panic!("failed to requeue retired task slot");
            }
            return None;
        }

        let p = slot.ptr.swap(core::ptr::null_mut(), Ordering::AcqRel);

        if slot
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |g| {
                let next = g.checked_add(1)?;
                if next >= TASK_ID_MAX_GENERATION {
                    None
                } else {
                    Some(next)
                }
            })
            .is_err()
        {
            panic!("task slot generation exhausted");
        }

        slot.retired_next.store(0, Ordering::Release);
        slot.state.store(TASK_SLOT_EMPTY, Ordering::Release);
        self.free_hint.store(idx, Ordering::Release);

        if p.is_null() {
            None
        } else {
            Some(p)
        }
    }

    pub(crate) fn reap_retired(&self) {
        if current_is_in_interrupt_atomic().load(Ordering::Relaxed) {
            return;
        }

        let Some(_guard) = self.reap_lock.try_lock() else {
            return;
        };

        let mut curr = self.retired_head.swap(0, Ordering::AcqRel);
        let mut checked = 0usize;

        while curr != 0 {
            checked += 1;

            let idx = curr;
            let next = match self.slot(curr) {
                Some(slot) => slot.retired_next.swap(0, Ordering::AcqRel),
                None => 0,
            };

            if let Some(p) = self.reap_one_retired_idx(idx) {
                unsafe {
                    drop(Arc::from_raw(p));
                }
            }

            curr = next;

            if checked > self.slots.len() {
                panic!("retired task slot list cycle detected");
            }
        }
    }
}
