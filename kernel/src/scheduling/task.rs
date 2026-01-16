use crate::cpu::get_cpu_info;
use crate::gdt::PER_CPU_GDT;
use crate::memory::paging::paging::map_kernel_range;
use crate::memory::paging::stack::{allocate_kernel_stack, StackSize};
use crate::memory::paging::virt_tracker::deallocate_kernel_range;
use crate::scheduling::runtime::runtime::{yield_now, BLOCKING_POOL, RUNTIME_POOL};
use crate::scheduling::scheduler::{self, kernel_task_end, Scheduler, SCHEDULER};
use crate::scheduling::state::{BlockReason, SchedState, State};
use crate::static_handlers::task_yield;
use crate::structs::thread_pool::ThreadPool;
use alloc::string::String;
use alloc::sync::Arc;
use core::arch::naked_asm;
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use kernel_types::status::PageMapError;
use spin::RwLock;
use x86_64::instructions::hlt;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

pub type TaskEntry = extern "win64" fn(usize);

const PAGE_SIZE: u64 = 4096;

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

    /// The inner task data (context, stack, etc.) - requires lock for access
    pub inner: RwLock<Task>,

    /// Fast path for kernel mode check
    pub is_kernel_mode: AtomicBool,
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

    /// Get the block reason
    #[inline(always)]
    pub fn block_reason(&self) -> BlockReason {
        BlockReason::from_u32(self.block_reason.load(Ordering::Relaxed))
    }

    /// Set the block reason
    #[inline(always)]
    pub fn set_block_reason(&self, reason: BlockReason) {
        self.block_reason.store(reason as u32, Ordering::Relaxed);
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
}

/// Inner task data - accessed through RwLock
#[derive(Debug)]
pub struct Task {
    pub name: String,
    pub context: State,
    pub stack_start: u64,
    pub guard_page: u64,
    pub is_user_mode: bool,
    pub parent_pid: u64,
    pub executer_id: Option<u64>,
    pub stack_size: u64,

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
        state.rsp = stack_top - 8;
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = kernel_task_end as u64;
        }

        state.cs = gdt
            .selectors_per_cpu
            .get(cpu_id as usize)
            .expect("")
            .user_code_selector
            .0 as u64
            | 3;
        state.ss = gdt
            .selectors_per_cpu
            .get(cpu_id as usize)
            .expect("")
            .user_data_selector
            .0 as u64
            | 3;

        let inner_task = Task {
            name,
            context: state,
            stack_start: stack_top,
            guard_page,
            is_user_mode: true,
            parent_pid,
            executer_id: None,
            stack_size,
            sched_in_cycles: AtomicU64::new(0),
            last_quantum_cycles: AtomicU64::new(0),
            total_run_cycles: AtomicU64::new(0),
            quantum_count: AtomicU64::new(0),
            last_cpu: AtomicUsize::new(usize::MAX),
        };

        Arc::new(TaskRef {
            id: AtomicU64::new(0),
            sched_state: AtomicU8::new(SchedState::Runnable as u8),
            target_cpu: AtomicUsize::new(cpu_id as usize),
            permit: AtomicU8::new(0),
            block_reason: AtomicU32::new(BlockReason::None as u32),
            wait_next: AtomicU64::new(WAIT_QUEUE_NONE),
            inner: RwLock::new(inner_task),
            is_kernel_mode: AtomicBool::new(false),
        })
    }

    pub fn new_kernel_mode(
        entry_point: TaskEntry,
        context: usize,
        stack_size: StackSize,
        name: String,
        parent_pid: u64,
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
        state.rsp = stack_top_u64 - 8;
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = kernel_task_end as u64;
        }

        state.cs = gdt
            .selectors_per_cpu
            .get(cpu_id as usize)
            .expect("")
            .kernel_code_selector
            .0 as u64;
        state.ss = gdt
            .selectors_per_cpu
            .get(cpu_id as usize)
            .expect("")
            .kernel_data_selector
            .0 as u64;

        let inner_task = Task {
            name,
            context: state,
            stack_start: stack_top_u64,
            guard_page,
            is_user_mode: false,
            parent_pid,
            executer_id: None,
            stack_size: stack_size.as_bytes(),
            sched_in_cycles: AtomicU64::new(0),
            last_quantum_cycles: AtomicU64::new(0),
            total_run_cycles: AtomicU64::new(0),
            quantum_count: AtomicU64::new(0),
            last_cpu: AtomicUsize::new(usize::MAX),
        };

        Arc::new(TaskRef {
            id: AtomicU64::new(0),
            sched_state: AtomicU8::new(SchedState::Runnable as u8),
            target_cpu: AtomicUsize::new(cpu_id as usize),
            permit: AtomicU8::new(0),
            block_reason: AtomicU32::new(BlockReason::None as u32),
            wait_next: AtomicU64::new(WAIT_QUEUE_NONE),
            inner: RwLock::new(inner_task),
            is_kernel_mode: AtomicBool::new(true),
        })
    }

    pub fn update_from_context(&mut self, context: *mut State) {
        self.context = unsafe { *context };
    }

    pub fn destroy(&mut self) {
        if self.is_user_mode {
            return;
        }
        deallocate_kernel_range(VirtAddr::new(self.stack_start), self.stack_size);
    }

    pub fn grow_stack(&mut self, flags: PageTableFlags) -> Result<bool, PageMapError> {
        if self.is_user_mode || self.guard_page == 0 {
            return Ok(false);
        }

        let base = self.guard_page;
        let next_guard = match base.checked_sub(PAGE_SIZE) {
            Some(v) => v,
            None => return Ok(false),
        };

        let _ = unsafe { map_kernel_range(VirtAddr::new(base), PAGE_SIZE, flags) }?;
        self.guard_page = next_guard;
        Ok(true)
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
#[unsafe(naked)]
pub(crate) extern "win64" fn idle_task(_ctx: usize) {
    naked_asm!("3:", "hlt", "jmp 3b",);
}
