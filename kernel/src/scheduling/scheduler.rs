use crate::cpu;
use crate::drivers::interrupt_index::current_is_in_interrupt_atomic;
use crate::drivers::interrupt_index::LocalApic;
use crate::drivers::interrupt_index::{
    current_cpu_id, get_current_logical_id, send_eoi, IpiDest, IpiKind, APIC,
};
use crate::drivers::timer_driver::TIMER;
use crate::executable::program::PROGRAM_MANAGER;
use crate::idt::InterruptGuard;
use crate::idt::SCHED_IPI_VECTOR;
use crate::memory::paging::stack::StackSize;
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::state::{BlockReason, SchedState, State};
use crate::scheduling::task::CurrentTask;
use crate::scheduling::task::TaskError;
pub use crate::scheduling::task::TaskHandle;
use crate::scheduling::task::TaskTable;
use crate::scheduling::task::{idle_task, Task, IDLE_MAGIC_LOWER, IDLE_UUID_UPPER};
use crate::scheduling::tls;
use crate::util::KERNEL_INITIALIZED;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_types::irq::IrqSafeRwLock;
use kernel_types::mpmc_ring::{MpmcRing, RingError};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::interrupts;
use x86_64::registers::control::Cr3;

const BALANCE_INTERVAL_TICKS: usize = 150;
const RUNQ_CAP: usize = 4096;
const TASK_TABLE_INITIAL_SLOTS: usize = 4096;
type SchedulerQueue = MpmcRing<TaskHandle, RUNQ_CAP>;

/// Saves the current task's FPU/SIMD state for the duration of a kernel handler.
/// Restores the task selected at handler exit so post-schedule handler code
/// cannot clobber the FPU/SIMD state that will be resumed by `iretq`.
pub struct KernelFpuGuard {
    saved_task: Option<TaskHandle>,
}

impl KernelFpuGuard {
    #[inline(always)]
    pub fn new() -> Self {
        let cpu_id = current_cpu_id();
        let saved_task = if let Some(task) = SCHEDULER.get_current_task(cpu_id) {
            // Avoid blocking inside interrupts; skip if the lock is contended.
            {
                let mut guard = task.inner.try_write().expect(
                    "Failed to acquire task lock for saving FPU state in interrupt handler",
                );
                guard.save_fpu_state();
            }
            Some(task)
        } else {
            None
        };

        Self { saved_task }
    }
}

impl Drop for KernelFpuGuard {
    fn drop(&mut self) {
        self.saved_task.take();

        let cpu_id = current_cpu_id();
        if let Some(current) = SCHEDULER.get_current_task(cpu_id) {
            let mut guard = current
                .inner
                .try_write()
                .expect("Failed to acquire task lock for restoring FPU state in interrupt handler");
            guard.restore_fpu_state();
        }
    }
}

pub struct CoreScheduler {
    sched_lock: IrqSafeRwLock<SchedulerState>,
    run_queue: SchedulerQueue,
    inbound_queue: SchedulerQueue,
    idle_task: TaskHandle,
    current: CurrentTask,
    lapic_id: u8,
    load: AtomicUsize,
}

struct SchedulerState {
    current: Option<TaskHandle>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InboundDrain {
    Available,
    Contended,
}

pub struct Scheduler {
    all_tasks: TaskTable,
    cores: IrqSafeRwLock<Vec<Arc<CoreScheduler>>>,
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
            all_tasks: TaskTable::new(TASK_TABLE_INITIAL_SLOTS),
            cores: IrqSafeRwLock::new(Vec::new()),
            next_task_id: AtomicU64::new(1),
            num_cores: AtomicUsize::new(0),
            last_balance_tick: AtomicUsize::new(0),
            balance_lock: Mutex::new(()),
        }
    }

    #[inline(always)]
    fn core(&self, cpu_id: usize) -> Option<Arc<CoreScheduler>> {
        let cores = self.cores.read();
        cores.get(cpu_id).cloned()
    }

    #[inline(always)]
    fn build_core(&self, cpu_id: usize, lapic_id: u8) -> Arc<CoreScheduler> {
        let idle = Task::new_kernel_mode(idle_task, 0, StackSize::Tiny, "".into(), 0);

        idle.inner.write().context.r10 = 0x1c82f35548bcbe24;
        idle.inner.write().context.r11 = 0x890189d70ecaca7f;

        let _idle_id = self.register_task_no_reap(idle.clone());
        idle.set_target_cpu(cpu_id);

        Arc::new(CoreScheduler {
            sched_lock: IrqSafeRwLock::new(SchedulerState { current: None }),
            run_queue: SchedulerQueue::new(),
            inbound_queue: SchedulerQueue::new(),
            idle_task: idle.clone(),
            current: CurrentTask::new(&idle),
            lapic_id,
            load: AtomicUsize::new(0),
        })
    }

    pub fn init_core(&self, cpu_id: usize) {
        let mut cores = self.cores.write();

        if cpu_id < cores.len() {
            return;
        }

        assert!(
            cpu_id == cores.len(),
            "cpu ids must be contiguous (got {}, expected next {})",
            cpu_id,
            cores.len()
        );

        let lapic_id = get_current_logical_id();
        cores.push(self.build_core(cpu_id, lapic_id));
        self.num_cores.store(cores.len(), Ordering::Release);
    }

    fn register_task(&self, task: TaskHandle) -> u64 {
        if current_is_in_interrupt_atomic().load(Ordering::Relaxed) {
            panic!("attempted to register task from interrupt context");
        }

        self.reap_retired_tasks();

        if let Some(id) = self.all_tasks.insert(&task) {
            self.next_task_id.fetch_add(1, Ordering::Relaxed);
            return id;
        }

        self.reap_retired_tasks();

        let id = self
            .all_tasks
            .insert(&task)
            .unwrap_or_else(|| panic!("fixed task table exhausted"));

        self.next_task_id.fetch_add(1, Ordering::Relaxed);
        id
    }
    fn register_task_no_reap(&self, task: TaskHandle) -> u64 {
        if current_is_in_interrupt_atomic().load(Ordering::Relaxed) {
            panic!("attempted to register task from interrupt context");
        }

        let id = self
            .all_tasks
            .insert(&task)
            .unwrap_or_else(|| panic!("task table exhausted while registering non-reap task"));

        self.next_task_id.fetch_add(1, Ordering::Relaxed);
        id
    }
    #[inline(always)]
    pub fn reap_retired_tasks(&self) {
        if current_is_in_interrupt_atomic().load(Ordering::Relaxed) {
            return;
        }

        self.all_tasks.reap_retired();
    }

    #[inline(always)]
    fn unregister_task(&self, task: &TaskHandle) {
        let id = task.task_id();
        if id != 0 {
            self.all_tasks.retire(id, task);
        }
    }

    pub fn add_task(&self, task: TaskHandle) -> u64 {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return 0;
        }

        let id = self.register_task(task.clone());
        let best_cpu = self.choose_core_for_new_task(n);
        task.set_target_cpu(best_cpu);
        self.enqueue_inbound(best_cpu, task);
        self.kick_remote_core(best_cpu);
        id
    }

    fn enqueue_inbound(&self, cpu: usize, task: TaskHandle) {
        let Some(core) = self.core(cpu) else {
            panic!("enqueue_inbound: cpu {} not initialized", cpu);
        };

        Self::reserve_queue_load_or_panic(cpu, &core.load, "inbound queue");

        if core.inbound_queue.push(task).is_err() {
            core.load.fetch_sub(1, Ordering::Release);
            panic!("inbound queue overflow on cpu {}", cpu);
        }
    }

    fn kick_remote_core(&self, cpu: usize) {
        if cpu == current_cpu_id() || !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        if let Some(core) = self.core(cpu) {
            unsafe {
                if let Some(a) = APIC.lock().as_ref() {
                    a.lapic.send_ipi(
                        IpiDest::ApicId(core.lapic_id),
                        IpiKind::Fixed {
                            vector: SCHED_IPI_VECTOR,
                        },
                    )
                }
            }
        }
    }

    #[inline(always)]
    fn reserve_queue_load_or_panic(cpu: usize, load: &AtomicUsize, queue_name: &str) {
        // Reserve the shadow load slot before publishing to the queue so a
        // concurrent pop cannot decrement a stale zero count and wrap it.
        if load
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .is_err()
        {
            panic!("{queue_name} load overflow on cpu {cpu}");
        }
    }

    #[inline(always)]
    fn push_runqueue_or_panic(
        cpu: usize,
        queue: &SchedulerQueue,
        load: &AtomicUsize,
        task: TaskHandle,
    ) {
        Self::reserve_queue_load_or_panic(cpu, load, "run queue");
        if queue.push(task).is_err() {
            load.fetch_sub(1, Ordering::Release);
            panic!("run queue overflow on cpu {cpu}");
        }
    }

    fn choose_core_for_new_task(&self, n: usize) -> usize {
        let start = (self.next_task_id.load(Ordering::Relaxed) as usize) % n;
        let mut best = start;
        let mut best_load: Option<usize> = None;

        for k in 0..n {
            let i = (start + k) % n;
            let Some(load) = self.core_effective_load(i) else {
                continue;
            };

            if best_load.is_none_or(|b| load < b) {
                best_load = Some(load);
                best = i;
                if load == 0 {
                    break;
                }
            }
        }

        best
    }

    fn core_effective_load(&self, i: usize) -> Option<usize> {
        let core = self.core(i)?;
        let queue_load = core.load.load(Ordering::Acquire);

        if core.current.is_task(&core.idle_task) {
            Some(queue_load)
        } else {
            Some(queue_load.saturating_add(1))
        }
    }

    #[inline(always)]
    pub fn get_task_by_id(&self, id: u64) -> Option<TaskHandle> {
        self.all_tasks.get(id)
    }

    #[inline(always)]
    pub fn get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        self.core(cpu_id)?.current.load()
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

                    //task.set_block_reason(BlockReason::None);

                    let target = task.target_cpu();
                    let best_cpu = if target < n {
                        let target_load = self.core_effective_load(target).unwrap_or(usize::MAX);
                        if target_load == 0 {
                            target
                        } else {
                            self.find_least_loaded_cpu(n, target)
                        }
                    } else {
                        self.find_least_loaded_cpu(n, 0)
                    };
                    task.set_target_cpu(best_cpu);

                    self.enqueue_inbound(best_cpu, task.clone());
                    self.kick_remote_core(best_cpu);

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
        let best = hint % n;

        // Fast path: check hint CPU first
        if let Some(load) = self.core_effective_load(best) {
            if load == 0 {
                return best;
            }
        }

        let mut best = best;
        let mut best_load = self.core_effective_load(best);

        for k in 1..n {
            let i = (hint + k) % n;
            let Some(load) = self.core_effective_load(i) else {
                continue;
            };

            let take = match best_load {
                Some(cur) => load < cur,
                None => true,
            };

            if take {
                best_load = Some(load);
                best = i;
                if load == 0 {
                    break;
                }
            }
        }

        best
    }

    pub fn park_current(&self, _reason: BlockReason) {
        if !x86_64::instructions::interrupts::are_enabled() {
            panic!("Attempt to park with interrupts disabled, this will always cause a deadlock");
        }

        let cpu_id = current_cpu_id();
        let Some(core) = self.core(cpu_id) else {
            return;
        };

        let current = {
            let state = core.sched_lock.read();
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
            let _state = core.sched_lock.write();

            if current.consume_permit() {
                return;
            }

            current.set_sched_state(SchedState::Parking);
        }

        yield_now();
    }

    #[inline(always)]
    pub fn on_timer_tick(&self, state: *mut State, cpu_id: usize) -> Option<TaskHandle> {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return None;
        }
        let Some(core) = self.core(cpu_id) else {
            return None;
        };

        let now_cycles = cpu::get_cycles();

        let mut prev_task = None;

        {
            let sched_state = core.sched_lock.read();
            if let Some(ref cur) = sched_state.current {
                let Some(mut guard) = cur.inner.try_write() else {
                    return None;
                };
                guard.update_from_context(state);

                if !Arc::ptr_eq(cur, &core.idle_task) {
                    prev_task = Some(cur.clone());
                }
            }
        }

        let next = match self.schedule_next(cpu_id, &core, now_cycles, true) {
            Some(task) => task,
            None => return prev_task,
        };

        self.maybe_balance();

        self.restore_page_table(&next);
        self.restore_thread_local_storage(&next);

        let ctx_guard = next.inner.read();
        unsafe { ctx_guard.context.restore(state) };

        prev_task
    }

    fn drain_inbound_to_runqueue(&self, cpu_id: usize, core: &Arc<CoreScheduler>) -> InboundDrain {
        loop {
            if core.run_queue.len_approx() >= RUNQ_CAP {
                return InboundDrain::Available;
            }

            let task = match core.inbound_queue.try_pop() {
                Ok(task) => task,
                Err(RingError::Empty) => return InboundDrain::Available,
                Err(RingError::Contended) => return InboundDrain::Contended,
                Err(RingError::Full | RingError::BadCapacity) => unreachable!(),
            };

            if let Err(task) = core.run_queue.push(task) {
                if core.inbound_queue.push(task).is_err() {
                    panic!("failed to restore inbound task on cpu {}", cpu_id);
                }
                return InboundDrain::Available;
            }
        }
    }

    #[inline(always)]
    fn pop_queued_task(
        core: &Arc<CoreScheduler>,
        inbound_drain: InboundDrain,
    ) -> Option<TaskHandle> {
        if let Some(task) = core.run_queue.pop() {
            core.load.fetch_sub(1, Ordering::Release);
            return Some(task);
        }

        if inbound_drain == InboundDrain::Contended {
            return None;
        }

        match core.inbound_queue.try_pop() {
            Ok(task) => {
                core.load.fetch_sub(1, Ordering::Release);
                Some(task)
            }
            Err(RingError::Empty | RingError::Contended) => None,
            Err(RingError::Full | RingError::BadCapacity) => unreachable!(),
        }
    }

    fn schedule_next(
        &self,
        cpu_id: usize,
        core: &Arc<CoreScheduler>,
        now_cycles: u64,
        prev_fpu_already_saved: bool,
    ) -> Option<TaskHandle> {
        let mut sched_state = core.sched_lock.write();
        let previous = sched_state.current.take();
        let mut requeue_previous = None;

        if let Some(prev) = previous {
            let prev_is_idle = Arc::ptr_eq(&prev, &core.idle_task);

            let mut lock_failed = false;
            if let Some(mut guard) = prev.inner.try_write() {
                if !prev_fpu_already_saved {
                    guard.save_fpu_state();
                }
                if !prev_is_idle {
                    guard.account_switched_out(now_cycles);
                }
            } else {
                lock_failed = true;
            }

            if lock_failed {
                sched_state.current = Some(prev.clone());
                core.current.store(&prev);
                return Some(prev);
            }

            if !prev_is_idle {
                match prev.sched_state() {
                    SchedState::Running | SchedState::Runnable => {
                        prev.set_sched_state(SchedState::Runnable);
                        requeue_previous = Some(prev.clone());
                    }
                    SchedState::Parking => {
                        if prev.consume_permit() {
                            prev.set_sched_state(SchedState::Runnable);
                            //prev.set_block_reason(BlockReason::None);
                            requeue_previous = Some(prev.clone());
                        } else if prev
                            .cas_sched_state(SchedState::Parking, SchedState::Blocked)
                            .is_ok()
                            && prev.consume_permit()
                            && prev
                                .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                                .is_ok()
                        {
                            //prev.set_block_reason(BlockReason::None);
                            requeue_previous = Some(prev.clone());
                        }
                    }
                    SchedState::Blocked => {}
                    SchedState::Terminated => {
                        self.unregister_task(&prev);
                    }
                }
            }
        }

        let inbound_drain = self.drain_inbound_to_runqueue(cpu_id, core);

        if let Some(prev) = requeue_previous {
            Self::push_runqueue_or_panic(cpu_id, &core.run_queue, &core.load, prev);
        }

        loop {
            let cand = match Self::pop_queued_task(core, inbound_drain) {
                Some(task) => task,
                None => break,
            };

            match cand.sched_state() {
                SchedState::Terminated => {
                    self.unregister_task(&cand);
                    continue;
                }
                SchedState::Parking => continue,
                SchedState::Blocked => continue,
                SchedState::Runnable | SchedState::Running => {
                    cand.set_sched_state(SchedState::Running);

                    {
                        let mut guard = cand.inner.write();
                        guard.restore_fpu_state();
                        guard.mark_scheduled_in(cpu_id, now_cycles);
                    }

                    sched_state.current = Some(cand.clone());
                    core.current.store(&cand);
                    return Some(cand);
                }
            }
        }

        core.idle_task.set_sched_state(SchedState::Running);
        {
            let mut guard = core.idle_task.inner.write();
            guard.restore_fpu_state();
            guard.mark_scheduled_in(cpu_id, now_cycles);
        }

        sched_state.current = Some(core.idle_task.clone());
        core.current.store(&core.idle_task);
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

    #[inline(always)]
    pub fn restore_thread_local_storage(&self, task_handle: &TaskHandle) {
        let thread_pointer = if task_handle.is_kernel_mode.load(Ordering::Relaxed) {
            task_handle.tls_thread_pointer.load(Ordering::Relaxed)
        } else {
            0
        };
        tls::activate(thread_pointer);
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

    fn steal_youngest_runnable(
        &self,
        cpu_id: usize,
        core: &Arc<CoreScheduler>,
    ) -> Option<TaskHandle> {
        let _state = core.sched_lock.write();

        loop {
            let len = core.run_queue.len_approx();
            if len == 0 {
                return None;
            }

            let mut rotated = 0usize;
            while rotated + 1 < len {
                let Some(task) = core.run_queue.pop() else {
                    return None;
                };

                if core.run_queue.push(task).is_err() {
                    panic!("run queue rotation overflow on cpu {}", cpu_id);
                }

                rotated += 1;
            }

            let Some(task) = core.run_queue.pop() else {
                return None;
            };

            core.load.fetch_sub(1, Ordering::Release);

            match task.sched_state() {
                SchedState::Terminated => {
                    self.unregister_task(&task);
                }
                SchedState::Parking | SchedState::Blocked => {}
                SchedState::Runnable | SchedState::Running => {
                    return Some(task);
                }
            }
        }
    }

    fn balance(&self) {
        let n = self.num_cores.load(Ordering::Acquire);
        if n < 2 {
            return;
        }

        for i in 0..n {
            if let Some(core) = self.core(i) {
                self.drain_inbound_to_runqueue(i, &core);
            }
        }

        loop {
            let mut min_idx = 0;
            let mut min_load = usize::MAX;

            for i in 0..n {
                let Some(load) = self.core_effective_load(i) else {
                    continue;
                };

                if load < min_load {
                    min_idx = i;
                    min_load = load;
                }
            }

            if min_load == usize::MAX {
                break;
            }

            let mut max_idx = 0;
            let mut max_stealable = 0usize;

            for i in 0..n {
                if i == min_idx {
                    continue;
                }

                let Some(core) = self.core(i) else {
                    continue;
                };

                let stealable = core.run_queue.len_approx();

                if stealable > max_stealable {
                    max_stealable = stealable;
                    max_idx = i;
                }
            }

            if max_stealable == 0 {
                break;
            }

            let Some(max_load) = self.core_effective_load(max_idx) else {
                break;
            };

            if max_load <= min_load + 1 {
                break;
            }

            let Some(max_core) = self.core(max_idx) else {
                break;
            };

            let Some(task) = self.steal_youngest_runnable(max_idx, &max_core) else {
                break;
            };

            let Some(min_core) = self.core(min_idx) else {
                break;
            };

            task.set_target_cpu(min_idx);
            Self::push_runqueue_or_panic(min_idx, &min_core.run_queue, &min_core.load, task);
            self.kick_remote_core(min_idx);
        }
    }

    pub fn num_cores(&self) -> usize {
        self.num_cores.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn on_ipi(&self, state: *mut State, cpu_id: usize) {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        let Some(core) = self.core(cpu_id) else {
            return;
        };

        let is_idle = {
            let sched_state = core.sched_lock.read();
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
        let next = match self.schedule_next(cpu_id, &core, now_cycles, true) {
            Some(t) => t,
            None => {
                send_eoi(SCHED_IPI_VECTOR);
                return;
            }
        };

        self.restore_page_table(&next);
        self.restore_thread_local_storage(&next);

        send_eoi(SCHED_IPI_VECTOR);

        let ctx_guard = next.inner.read();
        unsafe { ctx_guard.context.restore(state) };
    }
}

#[no_mangle]
pub extern "win64" fn ipi_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let guard = InterruptGuard::new();
    let _fpu_guard = KernelFpuGuard::new();
    let cpu_id = current_cpu_id();
    SCHEDULER.on_ipi(state, cpu_id);
}

#[no_mangle]
pub extern "win64" fn yield_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let guard = InterruptGuard::new();
    let _fpu_guard = KernelFpuGuard::new();
    let cpu_id = current_cpu_id();
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

        "mov  rcx, rsp",
        "mov  rbx, rsp",
        "cld",
        "and  rsp, -16",
        "sub  rsp, 32",
        "call {handler}",
        "mov  rsp, rbx",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",
        // TODO: Read the ABI for the caller saved registers
        "9:",
        "pop  rax",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",
        "cld",
        "mov  rbx, rsp",
        "and  rsp, -16",
        "sub  rsp, 32",
        "call {eoi_only}",
        "mov  rsp, rbx",
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

        "mov  rcx, rsp",
        "mov  rbx, rsp",
        "cld",
        "and  rsp, -16",
        "sub  rsp, 32",
        "call {handler}",
        "mov  rsp, rbx",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",
        handler = sym yield_handler_c,
    );
}

#[unsafe(naked)]
pub extern "win64" fn task_return_trampoline() -> ! {
    naked_asm!(
        "cld",
        "sub rsp, 8",
        "mov qword ptr [rsp], 0",
        "jmp {task_end}",
        task_end = sym kernel_task_end,
    );
}

pub extern "win64" fn kernel_task_end() -> ! {
    crate::memory::heap::mimalloc_thread_done();

    interrupts::without_interrupts(|| {
        let task = SCHEDULER.get_current_task(current_cpu_id()).unwrap();
        task.terminate();
    });
    loop {
        yield_now();
    }
}
