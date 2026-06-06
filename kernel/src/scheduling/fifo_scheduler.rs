use crate::scheduling::domain::{
    CpuSet, Domain, DomainId, DomainOps, EnqueueReason, SchedulerClass, SwitchOutOutcome,
    TaskSchedBinding,
};
use crate::scheduling::state::SchedState;
use crate::scheduling::task::TaskHandle;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_types::bounded_mpmc::{BoundedMpmcPushError, BoundedMpmcQueue};
use spin::Mutex;

pub const FIFO_DOMAIN_ID: DomainId = DomainId(0);
pub const RUNQ_CAP: usize = 4096;
const BALANCE_INTERVAL_TICKS: usize = 150;

#[derive(Clone, Copy, PartialEq, Eq)]
enum InboundDrain {
    Available,
    Contended,
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

pub struct FifoCpuState {
    pub run_queue: BoundedMpmcQueue<TaskHandle>,
    pub inbound_queue: BoundedMpmcQueue<TaskHandle>,
    pub load: AtomicUsize,
}

impl FifoCpuState {
    fn new() -> Self {
        Self {
            run_queue: BoundedMpmcQueue::new(RUNQ_CAP),
            inbound_queue: BoundedMpmcQueue::new(RUNQ_CAP),
            load: AtomicUsize::new(0),
        }
    }
}

pub struct FifoTaskState {
    pub enqueue_seq: AtomicU64,
}

impl FifoTaskState {
    fn new() -> Self {
        Self {
            enqueue_seq: AtomicU64::new(0),
        }
    }
}

pub fn new_fifo_task_binding() -> TaskSchedBinding {
    TaskSchedBinding::new(FIFO_DOMAIN_ID, FifoTaskState::new())
}

pub fn build_fifo_domain(max_cpus: usize) -> Box<dyn DomainOps> {
    let mut per_cpu = Vec::with_capacity(max_cpus);
    for _ in 0..max_cpus {
        per_cpu.push(Some(FifoCpuState::new()));
    }

    Box::new(Domain::new(
        FIFO_DOMAIN_ID,
        "fifo",
        CpuSet::all(),
        FifoClass::new(),
        per_cpu.into_boxed_slice(),
    ))
}

#[inline(always)]
fn reserve_queue_load_or_panic(cpu: usize, load: &AtomicUsize, queue_name: &str) {
    if load
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .is_err()
    {
        panic!("{queue_name} load overflow on cpu {cpu}");
    }
}

#[inline(always)]
fn push_runqueue_or_panic(cpu: usize, cpu_state: &FifoCpuState, task: TaskHandle) {
    reserve_queue_load_or_panic(cpu, &cpu_state.load, "run queue");

    if cpu_state.run_queue.try_push(task).is_err() {
        cpu_state.load.fetch_sub(1, Ordering::Release);
        panic!("run queue overflow on cpu {cpu}");
    }
}

fn enqueue_inbound(cpu: usize, cpu_state: &FifoCpuState, task: TaskHandle) {
    reserve_queue_load_or_panic(cpu, &cpu_state.load, "inbound queue");

    if cpu_state.inbound_queue.try_push(task).is_err() {
        cpu_state.load.fetch_sub(1, Ordering::Release);
        panic!("inbound queue overflow on cpu {}", cpu);
    }
}

fn drain_inbound_to_runqueue(cpu_id: usize, cpu: &FifoCpuState) -> InboundDrain {
    loop {
        if cpu.run_queue.len() >= RUNQ_CAP {
            return InboundDrain::Available;
        }

        let Ok(task) = cpu.inbound_queue.try_pop_wait_free() else {
            return InboundDrain::Available;
        };

        match cpu.run_queue.try_push(task) {
            Ok(()) => {}
            Err(BoundedMpmcPushError::Full(task)) => {
                if cpu.inbound_queue.try_push(task).is_err() {
                    panic!("failed to restore inbound task on cpu {}", cpu_id);
                }

                return InboundDrain::Available;
            }
            _ => unreachable!(),
        }
    }
}

#[inline(always)]
fn pop_queued_task(cpu: &FifoCpuState, inbound_drain: InboundDrain) -> Option<TaskHandle> {
    if let Ok(task) = cpu.run_queue.try_pop_wait_free() {
        cpu.load.fetch_sub(1, Ordering::Release);
        return Some(task);
    }

    if inbound_drain == InboundDrain::Contended {
        return None;
    }

    if let Ok(task) = cpu.inbound_queue.try_pop_wait_free() {
        cpu.load.fetch_sub(1, Ordering::Release);
        Some(task)
    } else {
        None
    }
}

fn steal_youngest_runnable(src_cpu_id: usize, src_cpu: &FifoCpuState) -> Option<TaskHandle> {
    crate::scheduling::scheduler::SCHEDULER.with_core_sched_lock(src_cpu_id, || loop {
        let len = src_cpu.run_queue.len();

        if len == 0 {
            return None;
        }

        let mut rotated = 0usize;

        while rotated + 1 < len {
            let Ok(task) = src_cpu.run_queue.try_pop_wait_free() else {
                return None;
            };

            if src_cpu.run_queue.try_push(task).is_err() {
                panic!("run queue rotation overflow on cpu {}", src_cpu_id);
            }

            rotated += 1;
        }

        let Ok(task) = src_cpu.run_queue.try_pop_wait_free() else {
            return None;
        };

        src_cpu.load.fetch_sub(1, Ordering::Release);

        match task.sched_state() {
            SchedState::Terminated => {
                crate::scheduling::scheduler::SCHEDULER.unregister_task_from_domain(&task);
            }
            SchedState::Parking | SchedState::Blocked => {}
            SchedState::Runnable | SchedState::Running => {
                return Some(task);
            }
        }
    })?
}

impl SchedulerClass for FifoClass {
    type CpuState = FifoCpuState;
    type TaskState = FifoTaskState;

    fn enqueue(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        task: TaskHandle,
        task_state: &Self::TaskState,
        reason: EnqueueReason,
    ) {
        task_state.enqueue_seq.fetch_add(1, Ordering::Relaxed);

        match reason {
            EnqueueReason::Preempted | EnqueueReason::Yielded | EnqueueReason::Migrated => {
                push_runqueue_or_panic(cpu_id, cpu, task);
            }
            EnqueueReason::New | EnqueueReason::Wakeup => enqueue_inbound(cpu_id, cpu, task),
        }
    }

    fn pick_next(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        _now_cycles: u64,
    ) -> Option<TaskHandle> {
        let inbound_drain = drain_inbound_to_runqueue(cpu_id, cpu);
        pop_queued_task(cpu, inbound_drain)
    }

    fn on_switch_out(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        task: &TaskHandle,
        task_state: &Self::TaskState,
        _now_cycles: u64,
        outcome: SwitchOutOutcome,
    ) {
        if outcome == SwitchOutOutcome::StillRunnable {
            drain_inbound_to_runqueue(cpu_id, cpu);
            self.enqueue(
                cpu_id,
                cpu,
                task.clone(),
                task_state,
                EnqueueReason::Preempted,
            );
        }
    }

    fn effective_load(&self, cpu_id: usize, cpu: &Self::CpuState) -> usize {
        let queue_load = cpu.load.load(Ordering::Acquire);

        if crate::scheduling::scheduler::SCHEDULER.cpu_is_idle(cpu_id) {
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
    ) -> Option<TaskHandle> {
        steal_youngest_runnable(src_cpu_id, src_cpu)
    }

    fn on_task_exit(&self, _task: &TaskHandle, _task_state: &Self::TaskState) {}

    fn maybe_balance(&self, per_cpu: &[Option<Self::CpuState>], now_tick: usize) {
        let last = self.last_balance_tick.load(Ordering::Relaxed);

        if now_tick.wrapping_sub(last) < BALANCE_INTERVAL_TICKS {
            return;
        }

        let Some(_guard) = self.balance_lock.try_lock() else {
            return;
        };

        self.last_balance_tick.store(now_tick, Ordering::Relaxed);

        let n = crate::scheduling::scheduler::SCHEDULER.num_cores();
        if n < 2 {
            return;
        }

        for i in 0..n {
            if let Some(Some(cpu)) = per_cpu.get(i) {
                drain_inbound_to_runqueue(i, cpu);
            }
        }

        loop {
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

                let stealable = cpu.run_queue.len();

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

            let Some(task) = self.steal_one(max_idx, max_cpu, min_idx, min_cpu) else {
                break;
            };

            task.set_target_cpu(min_idx);
            push_runqueue_or_panic(min_idx, min_cpu, task);
            crate::scheduling::scheduler::SCHEDULER.kick_remote_core(min_idx);
        }
    }
}
