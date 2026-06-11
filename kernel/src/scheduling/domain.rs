use crate::arch::MAX_CPUS;
use crate::scheduling::task::TaskHandle;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

const CPU_SET_WORD_BITS: usize = u64::BITS as usize;
const CPU_SET_WORDS: usize = (MAX_CPUS + CPU_SET_WORD_BITS - 1) / CPU_SET_WORD_BITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainId(pub u16);

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

pub trait DomainOps: Send + Sync {
    fn id(&self) -> DomainId;
    fn name(&self) -> &'static str;
    fn contains_cpu(&self, cpu_id: usize) -> bool;

    fn enqueue(&self, task: TaskHandle, reason: EnqueueReason, hint_cpu: usize) -> usize;

    fn on_switch_out(
        &self,
        task: &TaskHandle,
        cpu_id: usize,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    );

    fn pick_next(&self, cpu_id: usize, now_cycles: u64) -> Option<TaskHandle>;

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
        task: TaskHandle,
        task_state: &Self::TaskState,
        reason: EnqueueReason,
    );

    fn pick_next(&self, cpu_id: usize, cpu: &Self::CpuState, now_cycles: u64)
        -> Option<TaskHandle>;

    fn on_switch_out(
        &self,
        cpu_id: usize,
        cpu: &Self::CpuState,
        task: &TaskHandle,
        task_state: &Self::TaskState,
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
    ) -> Option<TaskHandle>;

    fn on_task_exit(&self, task: &TaskHandle, task_state: &Self::TaskState);

    fn maybe_balance(&self, _per_cpu: &[Option<Self::CpuState>], _now_tick: usize) {}
}

pub struct Domain<C: SchedulerClass> {
    id: DomainId,
    name: &'static str,
    cpus: CpuSet,
    class: C,
    per_cpu: Box<[Option<C::CpuState>]>,
}

impl<C: SchedulerClass> Domain<C> {
    pub fn new(
        id: DomainId,
        name: &'static str,
        cpus: CpuSet,
        class: C,
        per_cpu: Box<[Option<C::CpuState>]>,
    ) -> Self {
        Self {
            id,
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
    fn id(&self) -> DomainId {
        self.id
    }

    #[inline(always)]
    fn name(&self) -> &'static str {
        self.name
    }

    #[inline(always)]
    fn contains_cpu(&self, cpu_id: usize) -> bool {
        self.cpus.contains(cpu_id)
    }

    fn enqueue(&self, task: TaskHandle, reason: EnqueueReason, hint_cpu: usize) -> usize {
        task.with_class_state(self.id, |task_state: &C::TaskState| {
            let cpu_id = self
                .class
                .select_cpu(
                    &self.per_cpu,
                    &self.cpus,
                    &task,
                    task_state,
                    reason,
                    hint_cpu,
                )
                .unwrap_or_else(|| panic!("domain {} has no eligible cpu", self.name));

            task.set_target_cpu(cpu_id);
            self.class.enqueue(
                cpu_id,
                self.cpu_state(cpu_id),
                task.clone(),
                task_state,
                reason,
            );
            cpu_id
        })
    }

    fn on_switch_out(
        &self,
        task: &TaskHandle,
        cpu_id: usize,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    ) {
        task.with_class_state(self.id, |task_state: &C::TaskState| {
            self.class.on_switch_out(
                cpu_id,
                self.cpu_state(cpu_id),
                task,
                task_state,
                now_cycles,
                outcome,
            );

            if outcome == SwitchOutOutcome::Terminated {
                self.class.on_task_exit(task, task_state);
            }
        });
    }

    fn pick_next(&self, cpu_id: usize, now_cycles: u64) -> Option<TaskHandle> {
        self.class
            .pick_next(cpu_id, self.cpu_state(cpu_id), now_cycles)
    }

    fn maybe_balance(&self, now_tick: usize) {
        self.class.maybe_balance(&self.per_cpu, now_tick);
    }
}

pub struct DomainMaster {
    domains: Box<[Box<dyn DomainOps>]>,
    per_cpu_cursor: Box<[AtomicUsize]>,
}

impl DomainMaster {
    pub fn new(domains: Box<[Box<dyn DomainOps>]>, cpu_count: usize) -> Self {
        let mut per_cpu_cursor = Vec::with_capacity(cpu_count);
        for _ in 0..cpu_count {
            per_cpu_cursor.push(AtomicUsize::new(0));
        }

        Self {
            domains,
            per_cpu_cursor: per_cpu_cursor.into_boxed_slice(),
        }
    }

    pub fn get(&self, id: DomainId) -> &dyn DomainOps {
        self.domains
            .iter()
            .find(|domain| domain.id() == id)
            .map(|domain| domain.as_ref())
            .unwrap_or_else(|| panic!("unknown scheduler domain {:?}", id))
    }

    pub fn pick_next(&self, cpu_id: usize, now_cycles: u64) -> Option<TaskHandle> {
        if self.domains.is_empty() {
            return None;
        }

        let cursor = self
            .per_cpu_cursor
            .get(cpu_id)
            .unwrap_or_else(|| panic!("domain cursor missing for cpu {}", cpu_id));
        let start = cursor.load(Ordering::Relaxed) % self.domains.len();

        for offset in 0..self.domains.len() {
            let idx = (start + offset) % self.domains.len();
            let domain = &self.domains[idx];
            if !domain.contains_cpu(cpu_id) {
                continue;
            }

            if let Some(task) = domain.pick_next(cpu_id, now_cycles) {
                cursor.store((idx + 1) % self.domains.len(), Ordering::Relaxed);
                return Some(task);
            }
        }

        None
    }

    pub fn maybe_balance(&self, current_tick: usize) {
        for domain in self.domains.iter() {
            domain.maybe_balance(current_tick);
        }
    }
}

#[derive(Debug)]
pub struct TaskSchedBinding {
    domain: DomainId,
    class_state: NonNull<()>,
    drop_class_state: unsafe fn(NonNull<()>),
}

unsafe impl Send for TaskSchedBinding {}
unsafe impl Sync for TaskSchedBinding {}

impl TaskSchedBinding {
    pub fn new<T: Send + Sync + 'static>(domain: DomainId, class_state: T) -> Self {
        unsafe fn drop_state<T>(ptr: NonNull<()>) {
            drop(Box::from_raw(ptr.cast::<T>().as_ptr()));
        }

        let raw = Box::into_raw(Box::new(class_state));
        let class_state = NonNull::new(raw.cast::<()>()).expect("class state allocation failed");

        Self {
            domain,
            class_state,
            drop_class_state: drop_state::<T>,
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
    fn drop(&mut self) {
        unsafe {
            (self.drop_class_state)(self.class_state);
        }
    }
}
