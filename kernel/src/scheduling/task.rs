// scheduling/task.rs
use crate::cpu::get_cpu_info;
use crate::gdt::PER_CPU_GDT;
use crate::memory::paging::stack::{allocate_kernel_stack, deallocate_kernel_stack, StackSize};
use crate::println;
use crate::scheduling::scheduler::kernel_task_end;
use crate::scheduling::state::State;

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::RwLock;
use x86_64::instructions::hlt;
use x86_64::VirtAddr;

use super::scheduler::TaskHandle;

pub type TaskEntry = extern "win64" fn(usize);

#[derive(Debug)]
pub struct Task {
    pub name: String,
    pub context: State,
    pub stack_start: u64,
    pub id: u64,
    pub terminated: bool,
    pub is_user_mode: bool,
    pub is_sleeping: bool,
    pub parent_pid: u64,
    pub executer_id: Option<u16>,
    pub stack_size: StackSize,

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
            id: 0,
            terminated: false,
            is_user_mode: true,
            parent_pid,
            executer_id: None,
            is_sleeping: false,

            stack_size: StackSize::default(),

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

        let mut state = State::new(0);
        state.rip = entry_point as u64;
        state.rcx = context as u64;
        state.rsp = stack_top.as_u64() - 8;
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
            stack_start: stack_top.as_u64(),
            id: 0,
            terminated: false,
            is_user_mode: false,
            parent_pid,
            executer_id: None,
            is_sleeping: false,
            stack_size,

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
            deallocate_kernel_stack(VirtAddr::new(self.stack_start), self.stack_size);
        }
    }

    pub fn print(&self) {
        println!(
            "Task ID: {}, RIP: {:X}, RSP: {:X}",
            self.id, self.context.rip, self.context.rsp
        );
    }

    pub fn sleep(&mut self) {
        self.is_sleeping = true;
    }

    pub fn wake(&mut self) {
        self.is_sleeping = false;
    }

    pub fn is_sleeping(&self) -> bool {
        self.is_sleeping
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
    loop {
        hlt();
    }
}
