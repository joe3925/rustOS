use crate::scheduling::scheduler::RunQueueAccess;
use crate::scheduling::reclaim::{self, ReclaimNode};
use crate::{
    platform::MAX_CPUS,
    scheduling::task::{TaskHandle, TaskUpdate},
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

const CPU_SET_WORD_BITS: usize = u64::BITS as usize;
const CPU_SET_WORDS: usize = (MAX_CPUS + CPU_SET_WORD_BITS - 1) / CPU_SET_WORD_BITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainId(pub u16);

pub const KERNEL_DOMAIN_ID: DomainId = DomainId(0);
pub const USER_DOMAIN_ID: DomainId = DomainId(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueReason {
    New,
    Wakeup,
    Preempted,
    Yielded,
    Migrated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchOutOutcome {
    StillRunnable,
    Blocking,
    Terminated,
    Migrated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSet {
    words: [u64; CPU_SET_WORDS],
}

impl CpuSet {
    pub const fn all() -> Self {
        Self {
            words: [u64::MAX; CPU_SET_WORDS],
        }
    }

    pub const fn empty() -> Self {
        Self {
            words: [0; CPU_SET_WORDS],
        }
    }

    pub fn single(cpu_id: usize) -> Self {
        let mut set = Self::empty();
        set.insert(cpu_id);
        set
    }

    pub fn range(start: usize, end_exclusive: usize) -> Self {
        let mut set = Self::empty();
        let mut cpu = start;
        while cpu < end_exclusive.min(MAX_CPUS) {
            set.insert(cpu);
            cpu += 1;
        }
        set
    }

    pub fn insert(&mut self, cpu_id: usize) {
        if cpu_id >= MAX_CPUS {
            return;
        }

        self.words[cpu_id / CPU_SET_WORD_BITS] |= 1u64 << (cpu_id % CPU_SET_WORD_BITS);
    }

    pub fn remove(&mut self, cpu_id: usize) {
        if cpu_id >= MAX_CPUS {
            return;
        }

        self.words[cpu_id / CPU_SET_WORD_BITS] &= !(1u64 << (cpu_id % CPU_SET_WORD_BITS));
    }

    #[inline(always)]
    pub fn contains(&self, cpu_id: usize) -> bool {
        if cpu_id >= MAX_CPUS {
            return false;
        }

        (self.words[cpu_id / CPU_SET_WORD_BITS] & (1u64 << (cpu_id % CPU_SET_WORD_BITS))) != 0
    }
}

#[cfg_attr(irq_check, irq::context)]
pub trait DomainOps: Send + Sync {
    fn name(&self) -> &'static str;
    fn contains_cpu(&self, cpu_id: usize) -> bool;

    fn enqueue(&self, task: &mut TaskUpdate, reason: EnqueueReason, hint_cpu: usize) -> usize;

    fn on_switch_out(
        &self,
        task: &mut TaskUpdate,
        cpu_id: usize,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    );

    fn pick_next(&self, access: &RunQueueAccess<'_>, now_cycles: u64) -> Option<TaskUpdate>;

    fn should_preempt(&self, task: &TaskUpdate) -> bool;

    fn maybe_balance(&self, now_tick: usize);
}

pub trait SchedulerClass: Send + Sync + 'static {
    type CpuState: Send + Sync + 'static;
    type TaskState: Send + Sync + 'static;

    fn select_cpu(
        &self,
        per_cpu: &[Option<Self::CpuState>],
        cpus: &CpuSet,
        task: &TaskHandle,
        _task_state: &Self::TaskState,
        reason: EnqueueReason,
        hint_cpu: usize,
    ) -> Option<usize>;

    fn enqueue(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        task: &mut TaskUpdate,
        reason: EnqueueReason,
    );

    fn pick_next(
        &self,
        access: &RunQueueAccess<'_>,
        cpu: &Self::CpuState,
        now_cycles: u64,
    ) -> Option<TaskUpdate>;

    fn on_switch_out(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        task: &mut TaskUpdate,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    );

    fn effective_load(&self, cpu_id: usize, cpu: &Self::CpuState) -> usize;

    fn steal_one(
        &self,
        src_cpu_id: usize,
        src_cpu: &Self::CpuState,
        dst_cpu_id: usize,
        dst_cpu: &Self::CpuState,
    ) -> Option<TaskUpdate>;

    fn on_task_exit(&self, task: &TaskUpdate);

    fn should_preempt(&self, _task: &TaskHandle, _task_state: &Self::TaskState) -> bool {
        true
    }

    fn maybe_balance(&self, _per_cpu: &[Option<Self::CpuState>], _now_tick: usize) {}
}

pub struct Domain<C: SchedulerClass> {
    name: &'static str,
    cpus: CpuSet,
    class: C,
    per_cpu: Box<[Option<C::CpuState>]>,
}

impl<C: SchedulerClass> Domain<C> {
    pub fn new(
        name: &'static str,
        cpus: CpuSet,
        class: C,
        per_cpu: Box<[Option<C::CpuState>]>,
    ) -> Self {
        Self {
            name,
            cpus,
            class,
            per_cpu,
        }
    }

    #[inline(always)]
    fn cpu_state(&self, cpu_id: usize) -> &C::CpuState {
        self.per_cpu
            .get(cpu_id)
            .and_then(Option::as_ref)
            .unwrap_or_else(|| panic!("domain {} has no cpu state for cpu {}", self.name, cpu_id))
    }
}

impl<C: SchedulerClass> DomainOps for Domain<C> {
    #[inline(always)]
    fn name(&self) -> &'static str {
        self.name
    }

    #[inline(always)]
    fn contains_cpu(&self, cpu_id: usize) -> bool {
        self.cpus.contains(cpu_id)
    }

    fn enqueue(&self, task: &mut TaskUpdate, reason: EnqueueReason, hint_cpu: usize) -> usize {
        let cpu_id = task.with_class_state(|task_state: &C::TaskState| {
            self.class
                .select_cpu(
                    &self.per_cpu,
                    &self.cpus,
                    &task,
                    task_state,
                    reason,
                    hint_cpu,
                )
                .unwrap_or_else(|| panic!("domain {} has no eligible cpu", self.name))
        });
        task.set_target_cpu(cpu_id);
        self.class
            .enqueue(cpu_id, self.cpu_state(cpu_id), task, reason);
        task.notify_after_update(cpu_id);
        cpu_id
    }

    fn on_switch_out(
        &self,
        task: &mut TaskUpdate,
        cpu_id: usize,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    ) {
        self.class
            .on_switch_out(cpu_id, self.cpu_state(cpu_id), task, now_cycles, outcome);

        if outcome == SwitchOutOutcome::Terminated {
            self.class.on_task_exit(task);
        }
    }

    fn pick_next(&self, access: &RunQueueAccess<'_>, now_cycles: u64) -> Option<TaskUpdate> {
        self.class
            .pick_next(access, self.cpu_state(access.cpu_id()), now_cycles)
    }

    fn should_preempt(&self, task: &TaskUpdate) -> bool {
        task.with_class_state(|task_state: &C::TaskState| {
            self.class.should_preempt(task, task_state)
        })
    }

    fn maybe_balance(&self, now_tick: usize) {
        self.class.maybe_balance(&self.per_cpu, now_tick);
    }
}

#[cfg_attr(irq_check, irq::context)]
pub trait DomainAlgorithm: Send + Sync {
    fn pick_next(
        &self,
        domains: &[DomainEntry],
        per_cpu_cursor: &[AtomicUsize],
        access: &RunQueueAccess<'_>,
        now_cycles: u64,
    ) -> Option<TaskUpdate>;
}
#[derive(Default)]
pub struct RoundRobinDomainAlgorithm;

impl DomainAlgorithm for RoundRobinDomainAlgorithm {
    fn pick_next(
        &self,
        domains: &[DomainEntry],
        per_cpu_cursor: &[AtomicUsize],
        access: &RunQueueAccess<'_>,
        now_cycles: u64,
    ) -> Option<TaskUpdate> {
        let cpu_id = access.cpu_id();
        if domains.is_empty() {
            return None;
        }

        let cursor = per_cpu_cursor
            .get(cpu_id)
            .unwrap_or_else(|| panic!("domain cursor missing for cpu {}", cpu_id));

        let start = cursor.load(Ordering::Relaxed) % domains.len();

        for offset in 0..domains.len() {
            let idx = (start + offset) % domains.len();
            let domain = &domains[idx].ops;

            if !domain.contains_cpu(cpu_id) {
                continue;
            }

            if let Some(task) = domain.pick_next(access, now_cycles) {
                cursor.store((idx + 1) % domains.len(), Ordering::Relaxed);
                return Some(task);
            }
        }

        None
    }
}

pub struct DomainEntry {
    id: DomainId,
    ops: Box<dyn DomainOps>,
}

impl DomainEntry {
    pub fn new(id: DomainId, ops: Box<dyn DomainOps>) -> Self {
        Self { id, ops }
    }
}

pub struct DomainMaster<A>
where
    A: DomainAlgorithm,
{
    domains: Box<[DomainEntry]>,
    per_cpu_cursor: Box<[AtomicUsize]>,
    algorithm: A,
}

impl<A> DomainMaster<A>
where
    A: DomainAlgorithm + Default,
{
    pub fn new(domains: Box<[DomainEntry]>, cpu_count: usize) -> Self {
        let mut per_cpu_cursor = Vec::with_capacity(cpu_count);
        for _ in 0..cpu_count {
            per_cpu_cursor.push(AtomicUsize::new(0));
        }

        Self {
            domains,
            per_cpu_cursor: per_cpu_cursor.into_boxed_slice(),
            algorithm: A::default(),
        }
    }

    fn get(&self, id: DomainId) -> &dyn DomainOps {
        self.domains
            .iter()
            .find(|domain| domain.id == id)
            .map(|domain| domain.ops.as_ref())
            .unwrap_or_else(|| panic!("unknown scheduler domain {:?}", id))
    }

    pub fn enqueue(
        &self,
        id: DomainId,
        task: &mut TaskUpdate,
        reason: EnqueueReason,
        hint_cpu: usize,
    ) -> usize {
        self.get(id).enqueue(task, reason, hint_cpu)
    }

    pub fn on_switch_out(
        &self,
        id: DomainId,
        task: &mut TaskUpdate,
        cpu_id: usize,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    ) {
        self.get(id)
            .on_switch_out(task, cpu_id, now_cycles, outcome);
    }

    pub fn pick_next(&self, access: &RunQueueAccess<'_>, now_cycles: u64) -> Option<TaskUpdate> {
        self.algorithm
            .pick_next(&self.domains, &self.per_cpu_cursor, access, now_cycles)
    }

    pub fn should_preempt(&self, id: DomainId, task: &TaskUpdate) -> bool {
        self.get(id).should_preempt(task)
    }

    pub fn maybe_balance(&self, current_tick: usize) {
        for domain in self.domains.iter() {
            domain.ops.maybe_balance(current_tick);
        }
    }
}

#[derive(Debug)]
pub struct TaskSchedBinding {
    domain: DomainId,
    class_state: NonNull<()>,
    allocation: NonNull<ReclaimNode>,
}

#[repr(C)]
struct ClassState<T> {
    reclaim: ReclaimNode,
    value: T,
}

unsafe impl Send for TaskSchedBinding {}
unsafe impl Sync for TaskSchedBinding {}

impl TaskSchedBinding {
    pub fn new<T: Send + Sync + 'static>(domain: DomainId, class_state: T) -> Self {
        #[cfg_attr(irq_check, irq::forbidden)]
        unsafe fn drop_state<T>(ptr: *mut ReclaimNode) {
            unsafe {
                drop(Box::from_raw(ptr.cast::<ClassState<T>>()));
            }
        }

        let allocation = Box::into_raw(Box::new(ClassState {
            reclaim: ReclaimNode::new(drop_state::<T>),
            value: class_state,
        }));
        let class_state = unsafe {
            NonNull::new_unchecked(core::ptr::addr_of_mut!((*allocation).value)).cast()
        };
        let allocation = unsafe { NonNull::new_unchecked(allocation.cast()) };

        Self {
            domain,
            class_state,
            allocation,
        }
    }

    #[inline(always)]
    pub fn domain_id(&self) -> DomainId {
        self.domain
    }

    #[inline(always)]
    pub fn class_state(&self) -> NonNull<()> {
        self.class_state
    }
}

impl Drop for TaskSchedBinding {
    #[cfg_attr(irq_check, irq::context)]
    fn drop(&mut self) {
        unsafe {
            reclaim::enqueue(self.allocation);
        }
    }
}
