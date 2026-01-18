use crate::cpu;
use crate::drivers::interrupt_index::{
    current_cpu_id, get_current_logical_id, send_eoi, IpiDest, IpiKind, LocalApic, APIC,
};
use crate::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER};
use crate::executable::program::PROGRAM_MANAGER;
use crate::idt::SCHED_IPI_VECTOR;
use crate::memory::paging::stack::StackSize;
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::scheduler;
use crate::scheduling::state::{BlockReason, SchedState, State};
use crate::scheduling::task::{idle_task, Task, TaskRef, IDLE_MAGIC_LOWER, IDLE_UUID_UPPER};
use crate::util::KERNEL_INITIALIZED;

pub use crate::scheduling::task::TaskHandle;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task;
use alloc::vec::Vec;
use crossbeam_queue::ArrayQueue;
use goblin::mach::constants::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS;
use x86_64::instructions::interrupts::without_interrupts;

use core::arch::naked_asm;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use kernel_types::irq::IrqSafeMutex;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::{hlt, interrupts};
use x86_64::registers::control::Cr3;

const BALANCE_INTERVAL_TICKS: usize = 150;
const RUNQ_CAP: usize = 4096;

// hard cap: id is used as index. slot 0 is reserved as "none".
const MAX_TASKS: usize = 65_536;

#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
}

struct TaskTable {
    slots: Box<[AtomicPtr<TaskRef>]>,
}

impl TaskTable {
    fn new(max_tasks: usize) -> Self {
        let mut v: Vec<AtomicPtr<TaskRef>> = Vec::with_capacity(max_tasks + 1);
        for _ in 0..=max_tasks {
            v.push(AtomicPtr::new(ptr::null_mut()));
        }
        Self {
            slots: v.into_boxed_slice(),
        }
    }

    #[inline(always)]
    fn insert(&self, id: u64, task: &TaskHandle) {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            panic!(
                "task id {} out of bounds (cap={})",
                id,
                self.slots.len() - 1
            );
        }

        let raw = Arc::into_raw(task.clone()) as *mut TaskRef;

        let prev = self.slots[idx].compare_exchange(
            ptr::null_mut(),
            raw,
            Ordering::Release,
            Ordering::Relaxed,
        );

        if prev.is_err() {
            unsafe { drop(Arc::from_raw(raw)) };
            panic!("task id {} reused / slot not empty", id);
        }
    }

    #[inline(always)]
    fn get(&self, id: u64) -> Option<TaskHandle> {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            return None;
        }

        let p = self.slots[idx].load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }

        unsafe {
            Arc::increment_strong_count(p);
            Some(Arc::from_raw(p))
        }
    }
}

/// Per-core scheduler state
pub struct CoreScheduler {
    sched_lock: IrqSafeMutex<SchedulerState>,
    run_queue: ArrayQueue<TaskHandle>,
    idle_task: TaskHandle,
    current_ptr: AtomicPtr<TaskRef>,
}

struct SchedulerState {
    current: Option<TaskHandle>,
}

pub struct Scheduler {
    all_tasks: TaskTable,
    cores: Box<[CoreScheduler]>,
    next_task_id: AtomicU64,
    num_cores: AtomicUsize,
    last_balance_tick: AtomicUsize,
    balance_lock: Mutex<()>,
}

lazy_static! {
    pub static ref SCHEDULER: Scheduler = Scheduler::new();
}

impl Scheduler {
    fn new() -> Self {
        Self {
            all_tasks: TaskTable::new(MAX_TASKS),
            cores: Vec::new().into_boxed_slice(),
            next_task_id: AtomicU64::new(1),
            num_cores: AtomicUsize::new(0),
            last_balance_tick: AtomicUsize::new(0),
            balance_lock: Mutex::new(()),
        }
    }

    pub fn init(&self, num_cores: usize) {
        self.num_cores.store(num_cores, Ordering::Relaxed);

        let mut cores_vec: Vec<CoreScheduler> = Vec::with_capacity(num_cores);
        for i in 0..num_cores {
            let idle = Task::new_kernel_mode(idle_task, 0, StackSize::Tiny, "".into(), 0);

            idle.inner.write().context.r10 = 0x1c82f35548bcbe24;
            idle.inner.write().context.r11 = 0x890189d70ecaca7f;

            let idle_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
            idle.set_task_id(idle_id);
            idle.set_target_cpu(i);

            self.all_tasks.insert(idle_id, &idle);

            let idle_ptr = Arc::as_ptr(&idle) as *mut TaskRef;

            cores_vec.push(CoreScheduler {
                sched_lock: IrqSafeMutex::new(SchedulerState { current: None }),
                run_queue: ArrayQueue::new(RUNQ_CAP),
                idle_task: idle,
                current_ptr: AtomicPtr::new(idle_ptr),
            });
        }

        let cores_box = cores_vec.into_boxed_slice();
        let ptr = &self.cores as *const _ as *mut Box<[CoreScheduler]>;
        unsafe { ptr.write(cores_box) };
    }

    fn register_task(&self, task: TaskHandle) -> u64 {
        let id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        if (id as usize) > MAX_TASKS {
            panic!("task table exhausted: id {} > MAX_TASKS {}", id, MAX_TASKS);
        }
        task.set_task_id(id);
        self.all_tasks.insert(id, &task);
        id
    }

    pub fn spawn_task(&self, task: TaskHandle) -> u64 {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return 0;
        }

        let id = self.register_task(task.clone());
        let best_cpu = self.choose_core_for_new_task(n);
        task.set_target_cpu(best_cpu);
        self.enqueue_to_core(best_cpu, task);
        id
    }

    pub fn add_task(&self, task: TaskHandle) -> u64 {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return 0;
        }

        let id = self.register_task(task.clone());
        let best_cpu = self.choose_core_for_new_task(n);
        task.set_target_cpu(best_cpu);
        self.enqueue_to_core(best_cpu, task);
        id
    }

    fn enqueue_to_core(&self, cpu: usize, task: TaskHandle) {
        let core = &self.cores[cpu];
        Self::push_runqueue_or_panic(cpu, &core.run_queue, task);
    }

    #[inline(always)]
    fn push_runqueue_or_panic(cpu: usize, queue: &ArrayQueue<TaskHandle>, task: TaskHandle) {
        //queue.force_push(task);
        if let Some(err) = queue.push(task).err() {
            panic!("run queue overflow on cpu {cpu}");
        }
    }

    fn choose_core_for_new_task(&self, n: usize) -> usize {
        let start = (self.next_task_id.load(Ordering::Relaxed) as usize) % n;
        let mut best = start;
        let mut best_load = usize::MAX;

        for k in 0..n {
            let i = (start + k) % n;
            let load = self.core_load_unlocked(i);
            if load < best_load {
                best_load = load;
                best = i;
                if best_load == 0 {
                    break;
                }
            }
        }

        best
    }

    fn core_load_unlocked(&self, i: usize) -> usize {
        let core = &self.cores[i];
        if let Some(state) = core.sched_lock.try_lock() {
            let rq_len = core.run_queue.len();
            let running = match state.current.as_ref() {
                Some(t) if !Arc::ptr_eq(t, &core.idle_task) => 1,
                _ => 0,
            };
            rq_len + running
        } else {
            usize::MAX / 2
        }
    }

    fn core_effective_load(&self, i: usize) -> usize {
        self.core_load_unlocked(i)
    }

    #[inline(always)]
    pub fn get_task_by_id(&self, id: u64) -> Option<TaskHandle> {
        self.all_tasks.get(id)
    }

    #[inline(always)]
    pub fn get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        let core = &self.cores[cpu_id];
        let p = core.current_ptr.load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }
        unsafe {
            Arc::increment_strong_count(p);
            Some(Arc::from_raw(p))
        }
    }

    pub fn delete_task(&self, id: u64) -> Result<(), TaskError> {
        if let Some(h) = self.get_task_by_id(id) {
            h.terminate();
            Ok(())
        } else {
            Err(TaskError::NotFound(id))
        }
    }

    pub fn unpark(&self, task: &TaskHandle) {
        task.grant_permit();

        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return;
        }

        let mut spins: u32 = 0;

        loop {
            match task.sched_state() {
                SchedState::Blocked => {
                    if task
                        .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                        .is_err()
                    {
                        continue;
                    }

                    task.set_block_reason(BlockReason::None);

                    let target = task.target_cpu();
                    let best_cpu = if target < n {
                        let target_load = self.core_effective_load(target);
                        if target_load == 0 {
                            target
                        } else {
                            self.find_least_loaded_cpu(n, target)
                        }
                    } else {
                        self.find_least_loaded_cpu(n, 0)
                    };

                    task.set_target_cpu(best_cpu);
                    self.enqueue_to_core(best_cpu, task.clone());

                    if best_cpu != current_cpu_id() {
                        unsafe {
                            APIC.lock().as_ref().map(|a| {
                                // TODO: sending to all excluding kills multicore performance fix this at some point
                                a.lapic.send_ipi(
                                    IpiDest::AllExcludingSelf,
                                    IpiKind::Fixed {
                                        vector: SCHED_IPI_VECTOR,
                                    },
                                )
                            });
                        }
                    }
                    return;
                }

                SchedState::Parking => {
                    spins += 1;
                    if spins <= 64 {
                        core::hint::spin_loop();
                        continue;
                    }
                    return;
                }

                SchedState::Runnable | SchedState::Running | SchedState::Terminated => {
                    return;
                }
            }
        }
    }

    fn find_least_loaded_cpu(&self, n: usize, hint: usize) -> usize {
        let mut best = hint % n;
        let mut best_load = self.core_effective_load(best);

        for k in 1..n {
            let i = (hint + k) % n;
            let load = self.core_effective_load(i);
            if load < best_load {
                best_load = load;
                best = i;
                if best_load == 0 {
                    break;
                }
            }
        }

        best
    }

    pub fn park_current(&self, reason: BlockReason) {
        let cpu_id = current_cpu_id() as usize;
        let core = &self.cores[cpu_id];

        let current = {
            let state = core.sched_lock.lock();
            match state.current.as_ref() {
                Some(t) => t.clone(),
                None => return,
            }
        };

        if Arc::ptr_eq(&current, &core.idle_task) {
            return;
        }

        if current.consume_permit() {
            return;
        }

        {
            let mut _state = core.sched_lock.lock();

            if current.consume_permit() {
                return;
            }

            current.set_block_reason(reason);
            current.set_sched_state(SchedState::Parking);
        }

        yield_now();
        // unsafe {
        //     hlt();
        // };
    }

    pub fn park_current_if(&self, reason: BlockReason, should_park: bool) {
        let cpu_id = current_cpu_id() as usize;
        let core = &self.cores[cpu_id];

        if !should_park {
            return;
        }

        let current = {
            let state = core.sched_lock.lock();
            match state.current.as_ref() {
                Some(t) => t.clone(),
                None => return,
            }
        };

        if Arc::ptr_eq(&current, &core.idle_task) {
            return;
        }

        if current.consume_permit() {
            return;
        }

        {
            let mut _state = core.sched_lock.lock();

            if current.consume_permit() {
                return;
            }

            current.set_block_reason(reason);
            current.set_sched_state(SchedState::Parking);
        }
        // unsafe {
        //     hlt();
        // };
        yield_now();
    }
    // TODO: there is a bug somewhere in somewhere on "on_timer_tick" that is causing garbage to be left on the sack
    // not high prio but will be an issue if decided the timer and yield shouldn't be on there own IST or if yield shouldn't be on int 0x80
    #[inline(always)]
    pub fn on_timer_tick(&self, state: *mut State, cpu_id: usize) {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        //self.maybe_balance();

        let now_cycles = cpu::get_cycles();

        // Save current task's context. If we can't acquire the write lock,
        // skip this tick entirely to avoid context corruption.
        {
            let sched_state = self.cores[cpu_id].sched_lock.lock();
            if let Some(ref cur) = sched_state.current {
                // TODO: maybe causes a lost waker, investigate
                let Some(mut guard) = cur.inner.try_write() else {
                    // Can't save context - don't switch, try again next tick
                    return;
                };
                guard.update_from_context(state);
            }
        }

        let next = match self.schedule_next(cpu_id, now_cycles) {
            Some(task) => task,
            None => return,
        };

        self.restore_page_table(&next);

        // PER_CORE_SWITCHES
        //     .get(cpu_id)
        //     .unwrap()
        //     .fetch_add(1, Ordering::Relaxed);

        // Hold the guard while we restore context to avoid racing with another
        // CPU modifying the task's saved state.
        let ctx_guard = next.inner.read();
        unsafe { ctx_guard.context.restore(state) };
    }

    fn schedule_next(&self, cpu_id: usize, now_cycles: u64) -> Option<TaskHandle> {
        let core = &self.cores[cpu_id];
        let mut sched_state = core.sched_lock.lock();

        let previous = sched_state.current.take();

        if let Some(ref prev) = previous {
            if !Arc::ptr_eq(prev, &core.idle_task) {
                if let Some(t) = prev.inner.try_read() {
                    t.account_switched_out(now_cycles);
                }

                let prev_sched_state = prev.sched_state();

                match prev_sched_state {
                    SchedState::Running | SchedState::Runnable => {
                        prev.set_sched_state(SchedState::Runnable);
                        Self::push_runqueue_or_panic(cpu_id, &core.run_queue, prev.clone());
                    }
                    SchedState::Parking => {
                        if prev.consume_permit() {
                            prev.set_sched_state(SchedState::Runnable);
                            prev.set_block_reason(BlockReason::None);
                            Self::push_runqueue_or_panic(cpu_id, &core.run_queue, prev.clone());
                        } else {
                            if prev
                                .cas_sched_state(SchedState::Parking, SchedState::Blocked)
                                .is_ok()
                            {
                                if prev.consume_permit() {
                                    if prev
                                        .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                                        .is_ok()
                                    {
                                        prev.set_block_reason(BlockReason::None);
                                        Self::push_runqueue_or_panic(
                                            cpu_id,
                                            &core.run_queue,
                                            prev.clone(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    SchedState::Blocked => {}
                    SchedState::Terminated => {}
                }
            }
        }

        loop {
            let Some(cand) = core.run_queue.pop() else {
                break;
            };

            let cand_state = cand.sched_state();

            match cand_state {
                SchedState::Terminated => continue,
                SchedState::Parking => continue,
                SchedState::Blocked => continue,
                SchedState::Runnable | SchedState::Running => {
                    cand.set_sched_state(SchedState::Running);

                    if let Some(t) = cand.inner.try_read() {
                        t.mark_scheduled_in(cpu_id, now_cycles);
                    }

                    sched_state.current = Some(cand.clone());
                    core.current_ptr
                        .store(Arc::as_ptr(&cand) as *mut TaskRef, Ordering::Release);
                    return Some(cand);
                }
            }
        }

        // TODO: Temp fix for lost wakeups - scan for stranded tasks when going idle.
        // This should be removed once the root cause of lost wakeups is fixed.
        // drop(sched_state);
        // self.rescue_stranded_tasks(cpu_id);
        // let mut sched_state = core.sched_lock.lock();

        // // Check again after rescue - a task may have been enqueued
        // if let Some(cand) = core.run_queue.pop() {
        //     if matches!(
        //         cand.sched_state(),
        //         SchedState::Runnable | SchedState::Running
        //     ) {
        //         cand.set_sched_state(SchedState::Running);
        //         if let Some(t) = cand.inner.try_read() {
        //             t.mark_scheduled_in(cpu_id, now_cycles);
        //         }
        //         sched_state.current = Some(cand.clone());
        //         core.current_ptr
        //             .store(Arc::as_ptr(&cand) as *mut TaskRef, Ordering::Release);
        //         return Some(cand);
        //     }
        // }

        core.idle_task.set_sched_state(SchedState::Running);
        if let Some(t) = core.idle_task.inner.try_read() {
            t.mark_scheduled_in(cpu_id, now_cycles);
        }

        sched_state.current = Some(core.idle_task.clone());
        core.current_ptr.store(
            Arc::as_ptr(&core.idle_task) as *mut TaskRef,
            Ordering::Release,
        );
        Some(core.idle_task.clone())
    }
    #[inline(always)]
    pub fn restore_page_table(&self, task_handle: &TaskHandle) {
        if task_handle.is_kernel_mode.load(Ordering::Relaxed) {
            return;
        }
        let pid = task_handle.inner.read().parent_pid;

        if let Some(program) = PROGRAM_MANAGER.get(pid) {
            unsafe { Cr3::write(program.read().cr3, Cr3::read().1) };
        } else {
            let id = task_handle.task_id();
            let _ = self.delete_task(id);
        }
    }

    pub fn maybe_balance(&self) {
        let current_tick = TIMER.load(Ordering::Relaxed);
        let last = self.last_balance_tick.load(Ordering::Relaxed);

        if current_tick.wrapping_sub(last) < BALANCE_INTERVAL_TICKS {
            return;
        }

        let Some(_guard) = self.balance_lock.try_lock() else {
            return;
        };

        self.last_balance_tick
            .store(current_tick, Ordering::Relaxed);
        self.balance();
    }

    fn balance(&self) {
        let n = self.num_cores.load(Ordering::Acquire);
        if n < 2 {
            return;
        }

        let mut loads: Vec<usize> = Vec::with_capacity(n);
        for i in 0..n {
            loads.push(self.core_load_unlocked(i));
        }

        loop {
            let (mut min_idx, mut min_load) = (0, loads[0]);
            let (mut max_idx, mut max_load) = (0, loads[0]);

            for i in 1..n {
                if loads[i] < min_load {
                    min_load = loads[i];
                    min_idx = i;
                }
                if loads[i] > max_load {
                    max_load = loads[i];
                    max_idx = i;
                }
            }

            if max_load <= min_load + 1 {
                break;
            }

            let task = { self.cores[max_idx].run_queue.pop() };

            let Some(task) = task else {
                loads[max_idx] = 0;
                continue;
            };

            task.set_target_cpu(min_idx);
            {
                Self::push_runqueue_or_panic(min_idx, &self.cores[min_idx].run_queue, task);
            }

            loads[max_idx] = loads[max_idx].saturating_sub(1);
            loads[min_idx] += 1;
        }
    }

    pub fn num_cores(&self) -> usize {
        self.num_cores.load(Ordering::Relaxed)
    }

    pub fn rescue_stranded_tasks(&self, caller_cpu: usize) {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return;
        }

        let max_id = self.next_task_id.load(Ordering::Relaxed);

        for id in 1..max_id {
            let Some(task) = self.all_tasks.get(id) else {
                continue;
            };

            // Only rescue tasks that are assigned to this core
            if task.target_cpu() != caller_cpu {
                continue;
            }

            if task.sched_state() == SchedState::Blocked && task.consume_permit() {
                if task
                    .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                    .is_ok()
                {
                    task.set_block_reason(BlockReason::None);
                    self.enqueue_to_core(caller_cpu, task);
                }
            }
        }
    }
    #[inline(always)]
    pub fn on_ipi(&self, state: *mut State, cpu_id: usize) {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        let core = &self.cores[cpu_id];

        // Only use IPI as an "exit idle / recheck runq" poke.
        let is_idle = {
            let sched_state = core.sched_lock.lock();
            match sched_state.current.as_ref() {
                Some(t) => Arc::ptr_eq(t, &core.idle_task),
                None => false,
            }
        };

        if !is_idle {
            send_eoi(SCHED_IPI_VECTOR);
            return;
        }

        let now_cycles = cpu::get_cycles();

        let next = match self.schedule_next(cpu_id, now_cycles) {
            Some(t) => t,
            None => {
                send_eoi(SCHED_IPI_VECTOR);
                return;
            }
        };

        self.restore_page_table(&next);

        // PER_CORE_SWITCHES
        //     .get(cpu_id)
        //     .unwrap()
        //     .fetch_add(1, Ordering::Relaxed);

        // Must EOI before iretq returns into the (possibly different) task context.
        send_eoi(SCHED_IPI_VECTOR);

        let ctx_guard = next.inner.read();
        unsafe { ctx_guard.context.restore(state) };
    }
}
#[no_mangle]
pub extern "C" fn ipi_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let cpu_id = current_cpu_id() as usize;
    SCHEDULER.on_ipi(state, cpu_id);
}

#[no_mangle]
pub extern "C" fn yield_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let cpu_id = current_cpu_id() as usize;
    SCHEDULER.on_timer_tick(state, cpu_id);
}
#[no_mangle]
pub extern "C" fn ipi_eoi_only() {
    crate::drivers::interrupt_index::send_eoi(SCHED_IPI_VECTOR);
}
#[unsafe(naked)]
#[no_mangle]
pub extern "win64" fn ipi_entry() {
    naked_asm!(
        "/* {upper} {lower} {eoi_only} */",
        "cli",
        "push rax",
        "mov  rax, {upper}",
        "cmp  r10, rax",
        "jne  9f",
        "mov  rax, {lower}",
        "cmp  r11, rax",
        "jne  9f",
        "pop  rax",

        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",

        "mov  rdi, rsp",
        "cld",
        "sub  rsp, 8",
        "call {handler}",
        "add  rsp, 8",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",

        "9:",
        "pop  rax",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",
        "sub  rsp, 8",
        "call {eoi_only}",
        "add  rsp, 8",
        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",

        upper = const IDLE_UUID_UPPER,
        lower = const IDLE_MAGIC_LOWER,
        handler = sym ipi_handler_c,
        eoi_only = sym ipi_eoi_only,
    );
}
#[unsafe(naked)]
pub extern "win64" fn yield_interrupt_entry() {
    naked_asm!(
        "cli",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",

        "mov  rdi, rsp",
        "cld",
        "sub  rsp, 8",
        "call {handler}",
        "add  rsp, 8",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",
        handler = sym yield_handler_c,
    );
}

pub fn kernel_task_end() -> ! {
    interrupts::without_interrupts(|| {
        let task = SCHEDULER
            .get_current_task(current_cpu_id() as usize)
            .unwrap();
        task.terminate();
    });
    loop {
        yield_now();
    }
}
