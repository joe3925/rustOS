// scheduling/task.rs

use crate::cpu::get_cpu_info;
use crate::gdt::PER_CPU_GDT;
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::paging::{map_kernel_range, map_range_with_huge_pages};
use crate::memory::paging::stack::{allocate_kernel_stack, deallocate_kernel_stack, StackSize};
use crate::memory::paging::virt_tracker::{
    allocate_kernel_range, allocate_kernel_range_mapped, deallocate_kernel_range,
};
use crate::println;
use crate::scheduling::runtime::runtime::{yield_now, BLOCKING_POOL, RUNTIME_POOL};
use crate::scheduling::scheduler::kernel_task_end;
use crate::scheduling::state::State;
use crate::structs::thread_pool::ThreadPool;
use alloc::string::String;
use alloc::sync::Arc;
use core::hint::black_box;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use kernel_types::status::PageMapError;
use spin::RwLock;
use x86_64::instructions::hlt;
use x86_64::structures::paging::{Mapper, PageSize, PageTableFlags, Size1GiB, Size2MiB, Size4KiB};
use x86_64::VirtAddr;

use super::scheduler::TaskHandle;

pub type TaskEntry = extern "win64" fn(usize);

const PAGE_SIZE: u64 = 4096;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkState {
    Running = 0,
    ParkRequested = 1,
    Parked = 2,
    UnparkPending = 3,
}

impl From<u8> for ParkState {
    fn from(v: u8) -> Self {
        match v {
            0 => ParkState::Running,
            1 => ParkState::ParkRequested,
            2 => ParkState::Parked,
            3 => ParkState::UnparkPending,
            _ => ParkState::Running,
        }
    }
}

#[derive(Debug)]
pub struct Task {
    pub name: String,
    pub context: State,
    pub stack_start: u64,
    pub guard_page: u64,
    pub id: u64,
    pub terminated: bool,
    pub is_user_mode: bool,
    pub parent_pid: u64,
    pub executer_id: Option<u64>,
    pub stack_size: u64,

    /// Atomic park state - replaces the old `is_sleeping` bool
    park_state: AtomicU8,

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
        let id = get_cpu_info()
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
            .get(id as usize)
            .expect("")
            .user_code_selector
            .0 as u64
            | 3;
        state.ss = gdt
            .selectors_per_cpu
            .get(id as usize)
            .expect("")
            .user_data_selector
            .0 as u64
            | 3;

        Arc::new(RwLock::new(Self {
            name,
            context: state,
            stack_start: stack_top,
            guard_page,
            id: 0,
            terminated: false,
            is_user_mode: true,
            parent_pid,
            executer_id: None,
            stack_size,
            park_state: AtomicU8::new(ParkState::Running as u8),
            sched_in_cycles: AtomicU64::new(0),
            last_quantum_cycles: AtomicU64::new(0),
            total_run_cycles: AtomicU64::new(0),
            quantum_count: AtomicU64::new(0),
            last_cpu: AtomicUsize::new(usize::MAX),
        }))
    }

    pub fn new_kernel_mode(
        entry_point: TaskEntry,
        context: usize,
        stack_size: StackSize,
        name: String,
        parent_pid: u64,
    ) -> TaskHandle {
        let gdt = PER_CPU_GDT.lock();
        let id = get_cpu_info()
            .get_feature_info()
            .expect("NO CPUID")
            .initial_local_apic_id();

        let stack_top =
            allocate_kernel_stack(stack_size).expect("Failed to allocate kernel-mode stack");
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
            .get(id as usize)
            .expect("")
            .kernel_code_selector
            .0 as u64;
        state.ss = gdt
            .selectors_per_cpu
            .get(id as usize)
            .expect("")
            .kernel_data_selector
            .0 as u64;

        Arc::new(RwLock::new(Self {
            name,
            context: state,
            stack_start: stack_top_u64,
            guard_page,
            id: 0,
            terminated: false,
            is_user_mode: false,
            parent_pid,
            executer_id: None,
            stack_size: stack_size.as_bytes(),
            park_state: AtomicU8::new(ParkState::Running as u8),
            sched_in_cycles: AtomicU64::new(0),
            last_quantum_cycles: AtomicU64::new(0),
            total_run_cycles: AtomicU64::new(0),
            quantum_count: AtomicU64::new(0),
            last_cpu: AtomicUsize::new(usize::MAX),
        }))
    }

    pub fn update_from_context(&mut self, context: *mut State) {
        self.context = unsafe { *context };
    }

    pub fn destroy(&mut self) {
        if self.is_user_mode {
            todo!();
        } else {
            deallocate_kernel_range(VirtAddr::new(self.stack_start), self.stack_size);
        }
    }

    pub fn print(&self) {
        println!(
            "Task ID: {}, RIP: {:X}, RSP: {:X}",
            self.id, self.context.rip, self.context.rsp
        );
    }

    #[inline]
    pub fn park_begin(&self) -> bool {
        loop {
            let current = self.park_state.load(Ordering::Acquire);
            match ParkState::from(current) {
                ParkState::Running => {
                    if self
                        .park_state
                        .compare_exchange(
                            current,
                            ParkState::ParkRequested as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                ParkState::UnparkPending => {
                    if self
                        .park_state
                        .compare_exchange(
                            current,
                            ParkState::Running as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return false;
                    }
                }
                ParkState::ParkRequested | ParkState::Parked => {
                    return false;
                }
            }
        }
    }

    #[inline]
    pub fn park_commit(&self) -> bool {
        loop {
            let current = self.park_state.load(Ordering::Acquire);
            match ParkState::from(current) {
                ParkState::ParkRequested => {
                    // Normal case: complete the park
                    if self
                        .park_state
                        .compare_exchange(
                            current,
                            ParkState::Parked as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                ParkState::UnparkPending => {
                    if self
                        .park_state
                        .compare_exchange(
                            current,
                            ParkState::Running as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return false;
                    }
                }
                ParkState::Running => {
                    return false;
                }
                ParkState::Parked => {
                    return true;
                }
            }
        }
    }

    #[inline]
    pub fn park_abort(&self) {
        loop {
            let current = self.park_state.load(Ordering::Acquire);
            match ParkState::from(current) {
                ParkState::ParkRequested | ParkState::UnparkPending => {
                    if self
                        .park_state
                        .compare_exchange(
                            current,
                            ParkState::Running as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    #[inline]
    pub fn unpark(&self) -> bool {
        loop {
            let current = self.park_state.load(Ordering::Acquire);
            match ParkState::from(current) {
                ParkState::Running => {
                    // Already running, nothing to do
                    return false;
                }
                ParkState::ParkRequested => {
                    // Task wants to park but hasn't been moved to sleep queue yet.
                    // Set UnparkPending so park_commit() will abort the park.
                    if self
                        .park_state
                        .compare_exchange(
                            current,
                            ParkState::UnparkPending as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return false; // Scheduler will catch this in park_commit
                    }
                    // CAS failed, retry
                }
                ParkState::Parked => {
                    // Task is actually parked in sleep queue - wake it up
                    if self
                        .park_state
                        .compare_exchange(
                            current,
                            ParkState::Running as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true; // Caller must move task to run queue
                    }
                    // CAS failed, retry
                }
                ParkState::UnparkPending => {
                    // Already have a pending unpark, nothing more to do
                    return false;
                }
            }
        }
    }

    /// Check if task is in a parked or parking state.
    ///
    /// Note: This is a snapshot and may be stale. Use for scheduler decisions
    /// only in conjunction with park_commit().
    #[inline]
    pub fn is_park_requested(&self) -> bool {
        let state = ParkState::from(self.park_state.load(Ordering::Acquire));
        matches!(state, ParkState::ParkRequested | ParkState::UnparkPending)
    }

    /// Check if task is fully parked (in sleep queue).
    #[inline]
    pub fn is_parked(&self) -> bool {
        ParkState::from(self.park_state.load(Ordering::Acquire)) == ParkState::Parked
    }

    /// Get the current park state (for debugging).
    #[inline]
    pub fn park_state(&self) -> ParkState {
        ParkState::from(self.park_state.load(Ordering::Acquire))
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

        let mapped = unsafe { map_kernel_range(VirtAddr::new(base), PAGE_SIZE, flags) }?;
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
    pub fn current_slice_age_cycles(&self, now_cycles: u64) -> u64 {
        let start = self.sched_in_cycles.load(Ordering::Relaxed);
        if start == 0 || now_cycles <= start {
            return 0;
        }
        now_cycles - start
    }

    #[inline(always)]
    pub fn last_quantum_cycles(&self) -> u64 {
        self.last_quantum_cycles.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn total_run_cycles(&self) -> u64 {
        self.total_run_cycles.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn quantum_count(&self) -> u64 {
        self.quantum_count.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn last_cpu(&self) -> usize {
        self.last_cpu.load(Ordering::Relaxed)
    }
}

pub(crate) extern "win64" fn idle_task(_ctx: usize) {
    let runtime = RUNTIME_POOL.as_ref() as *const ThreadPool;
    let blocking = BLOCKING_POOL.as_ref() as *const ThreadPool;

    loop {
        unsafe {
            let runtime_var = (*runtime).is_shutdown();
            let blocking_var = (*blocking).is_shutdown();
            black_box(runtime_var);
            black_box(blocking_var);
        }
        yield_now();
        //hlt();
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
