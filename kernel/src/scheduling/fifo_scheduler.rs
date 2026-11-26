use crate::idt::interrupt_impl::InterruptGuard;
use crate::platform;
use crate::scheduling::domain::{
    CpuSet, Domain, DomainOps, EnqueueReason, KERNEL_DOMAIN_ID, SchedulerClass, SwitchOutOutcome,
    TaskSchedBinding,
};
use crate::scheduling::scheduler::{RunQueueAccess, scheduler};
use crate::scheduling::state::SchedState;
use crate::scheduling::task::{TaskHandle, TaskUpdate};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_sync::queues::bounded_mpmc::BoundedMpmcQueue;
use spin::Mutex;

pub const RUNQ_CAP: usize = 4096;
const _: () = assert!(RUNQ_CAP.is_power_of_two());
const BALANCE_INTERVAL_TICKS: usize = 150;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FifoPriority {
    Realtime,
    Normal,
    Low,
}

pub struct FifoTaskState {
    priority: FifoPriority,
}

impl FifoTaskState {
    pub(crate) const fn new(priority: FifoPriority) -> Self {
        Self { priority }
    }
}

pub(crate) fn fifo_task_sched_binding(priority: FifoPriority) -> TaskSchedBinding {
    TaskSchedBinding::new(KERNEL_DOMAIN_ID, FifoTaskState::new(priority))
}

pub struct FifoClass {
    last_balance_tick: AtomicUsize,
    balance_lock: Mutex<()>,
}

impl FifoClass {
    fn new() -> Self {
        Self {
            last_balance_tick: AtomicUsize::new(0),
            balance_lock: Mutex::new(()),
        }
    }
}

struct FifoRunQueue {
    slots: Box<[Option<TaskHandle>]>,
    head: usize,
    len: usize,
}

impl FifoRunQueue {
    fn push_back(&mut self, task: TaskHandle) {
        assert!(self.len < RUNQ_CAP);
        let tail = (self.head + self.len) & (RUNQ_CAP - 1);
        assert!(self.slots[tail].is_none());
        self.slots[tail] = Some(task);
        self.len += 1;
    }
}

#[repr(align(64))]
pub struct FifoCpuState {
    cpu_id: usize,
    run_queue: UnsafeCell<FifoRunQueue>,
    inbound_queue: BoundedMpmcQueue<TaskHandle>,
    load: AtomicUsize,
}

unsafe impl Sync for FifoCpuState {}

impl FifoCpuState {
    fn new(cpu_id: usize) -> Self {
        Self {
            cpu_id,
            run_queue: UnsafeCell::new(FifoRunQueue {
                slots: alloc::vec![None; RUNQ_CAP].into_boxed_slice(),
                head: 0,
                len: 0,
            }),
            inbound_queue: BoundedMpmcQueue::new(RUNQ_CAP),
            load: AtomicUsize::new(0),
        }
    }

    fn run_queue<'a>(
        &'a self,
        access: &'a mut RunQueueAccess<'_>,
    ) -> &'a mut FifoRunQueue {
        assert_eq!(access.cpu_id(), self.cpu_id);
        unsafe { &mut *self.run_queue.get() }
    }
}

pub fn build_fifo_domain(name: &'static str, cpus: CpuSet, cpu_count: usize) -> Box<dyn DomainOps> {
    let mut per_cpu = Vec::with_capacity(cpu_count);
    for cpu_id in 0..cpu_count {
        per_cpu.push(Some(FifoCpuState::new(cpu_id)));
    }

    Box::new(Domain::new(
        name,
        cpus,
        FifoClass::new(),
        per_cpu.into_boxed_slice(),
    ))
}

fn enqueue_inbound(cpu: usize, cpu_state: &FifoCpuState, task: &mut TaskUpdate) {
    let _guard = (!platform::current_is_in_interrupt()).then(InterruptGuard::new);
    assert_eq!(cpu, cpu_state.cpu_id);
    cpu_state.load.fetch_add(1, Ordering::AcqRel);
    if cpu_state.inbound_queue.try_push((**task).clone()).is_err() {
        cpu_state.load.fetch_sub(1, Ordering::Release);
        panic!("inbound queue overflow on cpu {}", cpu);
    }
    task.set_target_cpu(cpu);
    task.notify_after_update(cpu);
}

fn drain_inbound_to_runqueue(access: &mut RunQueueAccess<'_>, cpu: &FifoCpuState) {
    let run_queue = cpu.run_queue(access);
    let available = RUNQ_CAP - run_queue.len;
    for _ in 0..available {
        let Ok(task) = cpu.inbound_queue.try_pop_wait_free() else {
            break;
        };
        run_queue.push_back(task);
    }
}

fn pop_queued_task(
    access: &mut RunQueueAccess<'_>,
    cpu: &FifoCpuState,
) -> Option<TaskUpdate> {
    let run_queue = cpu.run_queue(access);
    let queued = run_queue.len;
    for allow_low in [false, true] {
        for _ in 0..queued {
            if run_queue.len == 0 {
                return None;
            }
            let task = run_queue.slots[run_queue.head].take().unwrap();
            run_queue.head = (run_queue.head + 1) & (RUNQ_CAP - 1);
            run_queue.len -= 1;
            let task = match task.try_into_update() {
                Ok(update) => {
                    if allow_low
                        || update.with_class_state(|state: &FifoTaskState| state.priority)
                            != FifoPriority::Low
                    {
                        cpu.load.fetch_sub(1, Ordering::Release);
                        return Some(update);
                    }
                    update.into_handle()
                }
                Err(task) => task,
            };
            run_queue.push_back(task);
        }
    }
    None
}

impl SchedulerClass for FifoClass {
    type CpuState = FifoCpuState;
    type TaskState = FifoTaskState;

    fn enqueue(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        task: &mut TaskUpdate,
        _reason: EnqueueReason,
    ) {
        enqueue_inbound(cpu_id, cpu, task);
    }
    fn select_cpu(
        &self,
        per_cpu: &[Option<Self::CpuState>],
        cpus: &CpuSet,
        _task: &TaskHandle,
        _task_state: &Self::TaskState,
        reason: EnqueueReason,
        hint_cpu: usize,
    ) -> Option<usize> {
        let n = scheduler().num_cores();

        if matches!(
            reason,
            EnqueueReason::NewOnCpu
                | EnqueueReason::Wakeup
                | EnqueueReason::Preempted
                | EnqueueReason::Yielded
                | EnqueueReason::Migrated
        ) {
            if hint_cpu < n
                && cpus.contains(hint_cpu)
                && per_cpu.get(hint_cpu).is_some_and(Option::is_some)
            {
                return Some(hint_cpu);
            }
        }

        let mut best_cpu = None;
        let mut best_weight = 0u128;
        let mut best_total_tasks = 1u128;

        for cpu_id in 0..n {
            if !cpus.contains(cpu_id) {
                continue;
            }

            let Some(Some(cpu)) = per_cpu.get(cpu_id) else {
                continue;
            };

            let total_tasks = self.effective_load(cpu_id, cpu) as u128 + 1;
            let weight = if cpu_id == hint_cpu { 9u128 } else { 8u128 };
            let candidate_score = weight * best_total_tasks;
            let selected_score = best_weight * total_tasks;

            if best_cpu.is_none()
                || candidate_score > selected_score
                || (candidate_score == selected_score && cpu_id == hint_cpu)
            {
                best_cpu = Some(cpu_id);
                best_weight = weight;
                best_total_tasks = total_tasks;
            }
        }

        best_cpu
    }
    fn pick_next(
        &self,
        access: &mut RunQueueAccess<'_>,
        cpu: &Self::CpuState,
        _now_cycles: u64,
    ) -> Option<TaskUpdate> {
        drain_inbound_to_runqueue(access, cpu);
        pop_queued_task(access, cpu)
    }

    fn on_switch_out(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        task: &mut TaskUpdate,
        _now_cycles: u64,
        outcome: SwitchOutOutcome,
    ) {
        if outcome == SwitchOutOutcome::StillRunnable {
            self.enqueue(cpu_id, cpu, task, EnqueueReason::Preempted);
        }
    }

    fn effective_load(&self, cpu_id: usize, cpu: &Self::CpuState) -> usize {
        let queue_load = cpu.load.load(Ordering::Acquire);

        if scheduler().cpu_is_idle(cpu_id) {
            queue_load
        } else {
            queue_load.saturating_add(1)
        }
    }

    fn steal_one(
        &self,
        src_cpu_id: usize,
        src_cpu: &Self::CpuState,
        _dst_cpu_id: usize,
        _dst_cpu: &Self::CpuState,
    ) -> Option<TaskUpdate> {
        let mut access = scheduler().try_core_scheduler(src_cpu_id)?;
        drain_inbound_to_runqueue(&mut access, src_cpu);
        for _ in 0..src_cpu.run_queue(&mut access).len {
            let task = pop_queued_task(&mut access, src_cpu)?;
            match task.sched_state() {
                SchedState::Runnable => return Some(task),
                SchedState::Terminated => scheduler().unregister_task_from_domain(&task),
                SchedState::Running | SchedState::Parking | SchedState::Blocked => {
                    panic!("non-runnable task in run queue");
                }
            }
        }
        None
    }

    fn on_task_exit(&self, _task: &TaskUpdate) {}

    fn should_preempt(&self, _task: &TaskHandle, task_state: &Self::TaskState) -> bool {
        task_state.priority != FifoPriority::Realtime
    }

    fn maybe_balance(&self, per_cpu: &[Option<Self::CpuState>], now_tick: usize) {
        let last = self.last_balance_tick.load(Ordering::Relaxed);

        if now_tick.wrapping_sub(last) < BALANCE_INTERVAL_TICKS {
            return;
        }

        let Some(_guard) = self.balance_lock.try_lock() else {
            return;
        };

        if now_tick.wrapping_sub(self.last_balance_tick.load(Ordering::Relaxed))
            < BALANCE_INTERVAL_TICKS
        {
            return;
        }

        let n = scheduler().num_cores();
        if n < 2 {
            self.last_balance_tick.store(now_tick, Ordering::Relaxed);
            return;
        }

        for _ in 0..RUNQ_CAP {
            let mut min_idx = 0;
            let mut min_load = usize::MAX;

            for i in 0..n {
                let Some(Some(cpu)) = per_cpu.get(i) else {
                    continue;
                };

                let load = self.effective_load(i, cpu);
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

                let Some(Some(cpu)) = per_cpu.get(i) else {
                    continue;
                };

                let stealable = cpu.load.load(Ordering::Acquire);

                if stealable > max_stealable {
                    max_stealable = stealable;
                    max_idx = i;
                }
            }

            if max_stealable == 0 {
                break;
            }

            let Some(Some(max_cpu)) = per_cpu.get(max_idx) else {
                break;
            };

            let max_load = self.effective_load(max_idx, max_cpu);
            if max_load <= min_load + 1 {
                break;
            }

            let Some(Some(min_cpu)) = per_cpu.get(min_idx) else {
                break;
            };

            let Some(mut task) = self.steal_one(max_idx, max_cpu, min_idx, min_cpu) else {
                return;
            };

            enqueue_inbound(min_idx, min_cpu, &mut task);
        }
        self.last_balance_tick.store(now_tick, Ordering::Relaxed);
    }
}
