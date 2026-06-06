use crate::scheduling::task::TaskHandle;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuSet {
    All,
}

impl CpuSet {
    #[inline(always)]
    pub fn contains(&self, _cpu_id: usize) -> bool {
        match self {
            CpuSet::All => true,
        }
    }
}

pub trait DomainOps: Send + Sync {
    fn id(&self) -> DomainId;
    fn name(&self) -> &'static str;
    fn contains_cpu(&self, cpu_id: usize) -> bool;

    fn enqueue_new(&self, task: TaskHandle) -> usize;

    fn enqueue_wakeup(&self, task: TaskHandle, hint_cpu: usize) -> usize;

    fn requeue_preempted(&self, task: TaskHandle, cpu_id: usize, now_cycles: u64);

    fn pick_next(&self, cpu_id: usize, now_cycles: u64) -> Option<TaskHandle>;

    fn maybe_balance(&self, now_tick: usize);

    fn on_task_exit(&self, task: &TaskHandle);
}

pub trait SchedulerClass: Send + Sync + 'static {
    type CpuState: Send + Sync + 'static;
    type TaskState: Send + Sync + 'static;

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

    #[inline(always)]
    fn task_state<'a>(&self, task: &'a TaskHandle) -> &'a C::TaskState {
        assert_eq!(
            task.domain_id(),
            self.id,
            "task scheduled through non-owning domain"
        );

        let ptr = task.class_state();
        unsafe { ptr.cast::<C::TaskState>().as_ref() }
    }

    fn choose_least_loaded_cpu(&self, hint: usize) -> usize {
        let n = crate::scheduling::scheduler::SCHEDULER.num_cores();
        if n == 0 {
            return 0;
        }

        let first = hint % n;
        if self.contains_cpu(first) {
            let cpu = self.cpu_state(first);
            if self.class.effective_load(first, cpu) == 0 {
                return first;
            }
        }

        let mut best = first;
        let mut best_load = None;

        for k in 0..n {
            let i = (hint + k) % n;
            if !self.contains_cpu(i) {
                continue;
            }

            let cpu = self.cpu_state(i);
            let load = self.class.effective_load(i, cpu);
            if best_load.is_none_or(|cur| load < cur) {
                best_load = Some(load);
                best = i;

                if load == 0 {
                    break;
                }
            }
        }

        best
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

    fn enqueue_new(&self, task: TaskHandle) -> usize {
        let start = crate::scheduling::scheduler::SCHEDULER.new_task_placement_start();
        let cpu_id = self.choose_least_loaded_cpu(start);
        task.set_target_cpu(cpu_id);
        self.class.enqueue(
            cpu_id,
            self.cpu_state(cpu_id),
            task.clone(),
            self.task_state(&task),
            EnqueueReason::New,
        );
        cpu_id
    }

    fn enqueue_wakeup(&self, task: TaskHandle, hint_cpu: usize) -> usize {
        let cpu_id = self.choose_least_loaded_cpu(hint_cpu);
        task.set_target_cpu(cpu_id);
        self.class.enqueue(
            cpu_id,
            self.cpu_state(cpu_id),
            task.clone(),
            self.task_state(&task),
            EnqueueReason::Wakeup,
        );
        cpu_id
    }

    fn requeue_preempted(&self, task: TaskHandle, cpu_id: usize, now_cycles: u64) {
        self.class.on_switch_out(
            cpu_id,
            self.cpu_state(cpu_id),
            &task,
            self.task_state(&task),
            now_cycles,
            SwitchOutOutcome::StillRunnable,
        );
    }

    fn pick_next(&self, cpu_id: usize, now_cycles: u64) -> Option<TaskHandle> {
        self.class
            .pick_next(cpu_id, self.cpu_state(cpu_id), now_cycles)
    }

    fn maybe_balance(&self, now_tick: usize) {
        self.class.maybe_balance(&self.per_cpu, now_tick);
    }

    fn on_task_exit(&self, task: &TaskHandle) {
        self.class.on_task_exit(task, self.task_state(task));
    }
}

pub struct DomainMaster {
    domains: Box<[Box<dyn DomainOps>]>,
    per_cpu_cursor: Box<[AtomicUsize]>,
}

impl DomainMaster {
    pub fn new(domains: Box<[Box<dyn DomainOps>]>, max_cpus: usize) -> Self {
        let mut per_cpu_cursor = Vec::with_capacity(max_cpus);
        for _ in 0..max_cpus {
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
