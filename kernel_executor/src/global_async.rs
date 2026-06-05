use crate::platform::{platform, Job};
use crate::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::Arc;
use kernel_types::bounded_mpmc::{BoundedMpmcPushError, BoundedMpmcQueue};
use spin::Once;

#[cfg(test)]
use crate::round_robin::SchedulerPolicy;
#[cfg(test)]
use alloc::boxed::Box;

pub use crate::domain::{
    AdmissionPolicy, DestroyDomainError, DestroyDomainResult, DomainClass, DomainConfig, DomainId,
    DomainState, DomainStats, DomainTable, ExecutorDomain, GlobalExecutorStats, SubmitError,
    SubmitErrorKind, DRIVER_DOMAIN, KERNEL_BACKGROUND_DOMAIN, KERNEL_HIGH_DOMAIN,
    KERNEL_NORMAL_DOMAIN,
};

#[cfg(test)]
pub use crate::round_robin::{SimpleRoundRobinScheduler, WeightedDeficitRoundRobinScheduler};

pub type Trampoline = extern "win64" fn(usize);

#[repr(align(64))]
pub(crate) struct CacheAligned(pub(crate) AtomicUsize);

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct WorkItem {
    pub trampoline: Trampoline,
    pub ctx: usize,
}

const MAX_SHARDS: usize = 32;

struct DomainRunQueue {
    queue: BoundedMpmcQueue<DomainId>,
}

impl DomainRunQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queue: BoundedMpmcQueue::new(capacity.max(1)),
        }
    }

    #[inline]
    fn push(&self, domain_id: DomainId) {
        match self.queue.try_push(domain_id) {
            Ok(()) => {}
            Err(BoundedMpmcPushError::Full(_)) => {
                panic!("executor run queue full; scheduler token invariant is broken")
            }
            _ => unreachable!(),
        }
    }

    #[inline]
    fn pop(&self) -> Option<DomainId> {
        self.queue.try_pop()
    }

    #[inline]
    fn len(&self) -> usize {
        self.queue.len()
    }
}

struct ExecutorRuntime {
    domains: DomainTable,
    run_queue: DomainRunQueue,
}

impl ExecutorRuntime {
    fn new(shards: usize, max_work_items: usize) -> Self {
        Self {
            domains: DomainTable::new(shards, max_work_items),
            run_queue: DomainRunQueue::new(max_work_items),
        }
    }
}

pub struct GlobalAsyncExecutor {
    runtime: Once<ExecutorRuntime>,
    active_pumps: CacheAligned,
    max_pumps: CacheAligned,
    total_submissions: CacheAligned,
    total_rejections: CacheAligned,
    total_pump_runs: CacheAligned,
    run_tick: CacheAligned,
}

impl GlobalAsyncExecutor {
    pub fn global() -> &'static GlobalAsyncExecutor {
        static EXEC: Once<GlobalAsyncExecutor> = Once::new();

        EXEC.call_once(|| GlobalAsyncExecutor {
            runtime: Once::new(),
            active_pumps: CacheAligned(AtomicUsize::new(0)),
            max_pumps: CacheAligned(AtomicUsize::new(1)),
            total_submissions: CacheAligned(AtomicUsize::new(0)),
            total_rejections: CacheAligned(AtomicUsize::new(0)),
            total_pump_runs: CacheAligned(AtomicUsize::new(0)),
            run_tick: CacheAligned(AtomicUsize::new(0)),
        })
    }

    pub fn init(&self, shards: usize, max_work_items: usize) {
        let shards = shards.clamp(1, MAX_SHARDS);
        let max_work_items = max_work_items.max(1);

        self.runtime
            .call_once(|| ExecutorRuntime::new(shards, max_work_items));

        self.max_pumps.0.store(shards, Ordering::Release);

        platform().init_blocking(shards);
        platform().init_runtime(shards, shards);

        if self.runnable_domain_count() != 0 {
            self.try_schedule();
        }
    }

    #[inline]
    fn runtime(&self) -> &ExecutorRuntime {
        self.runtime
            .get()
            .expect("global async executor not initialized")
    }

    #[inline]
    pub fn submit(&self, trampoline: Trampoline, ctx: usize) {
        self.try_submit(trampoline, ctx)
            .expect("failed to submit to executor pool")
    }

    #[inline]
    pub fn try_submit(&self, trampoline: Trampoline, ctx: usize) -> Result<(), WorkItem> {
        self.try_submit_to_domain(KERNEL_NORMAL_DOMAIN, trampoline, ctx)
            .map_err(SubmitError::into_work_item)
    }

    #[inline]
    pub fn submit_to_domain(&self, domain_id: DomainId, trampoline: Trampoline, ctx: usize) {
        self.try_submit_to_domain(domain_id, trampoline, ctx)
            .expect("failed to submit to executor domain")
    }

    pub fn try_submit_to_domain(
        &self,
        domain_id: DomainId,
        trampoline: Trampoline,
        ctx: usize,
    ) -> Result<(), SubmitError> {
        let work_item = WorkItem { trampoline, ctx };

        let runtime = self.runtime.get().ok_or_else(|| {
            SubmitError::new(SubmitErrorKind::ExecutorUninitialized, domain_id, work_item)
        })?;

        let outcome = match runtime.domains.submit_to_domain(domain_id, work_item) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.total_rejections.0.fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        };

        self.total_submissions.0.fetch_add(1, Ordering::Relaxed);

        if let Some(domain) = runtime.domains.get_domain(outcome.domain_id) {
            self.schedule_domain_if_needed(runtime, outcome.domain_id, &domain);
        }

        Ok(())
    }

    pub fn create_domain(&self, config: DomainConfig) -> DomainId {
        self.runtime().domains.create_domain(config)
    }

    pub fn destroy_domain(
        &self,
        domain_id: DomainId,
    ) -> Result<DestroyDomainResult, DestroyDomainError> {
        self.runtime().domains.destroy_domain(domain_id)
    }

    pub fn get_domain(&self, domain_id: DomainId) -> Option<Arc<ExecutorDomain>> {
        self.runtime().domains.get_domain(domain_id)
    }

    pub fn domain_stats(&self, domain_id: DomainId) -> Option<DomainStats> {
        self.get_domain(domain_id).map(|domain| domain.stats())
    }

    pub fn stats(&self) -> GlobalExecutorStats {
        let runtime = self.runtime();

        GlobalExecutorStats {
            active_pumps: self.active_pumps.0.load(Ordering::Acquire),
            max_pumps: self.max_pumps.0.load(Ordering::Acquire),
            runnable_domain_count: runtime.run_queue.len(),
            domain_count: runtime.domains.domain_count(),
            total_submissions: self.total_submissions.0.load(Ordering::Relaxed),
            total_rejections: self.total_rejections.0.load(Ordering::Relaxed),
            total_pump_runs: self.total_pump_runs.0.load(Ordering::Relaxed),
        }
    }

    pub fn runnable_domain_count(&self) -> usize {
        let Some(runtime) = self.runtime.get() else {
            return 0;
        };

        runtime.run_queue.len()
    }

    #[cfg(test)]
    pub(crate) fn replace_scheduler_for_tests(&self, _scheduler: Box<dyn SchedulerPolicy>) {}

    #[inline]
    fn schedule_domain_if_needed(
        &self,
        runtime: &ExecutorRuntime,
        domain_id: DomainId,
        domain: &ExecutorDomain,
    ) {
        if !domain.is_schedulable_for_policy() {
            return;
        }

        if !domain.try_mark_scheduled() {
            return;
        }

        runtime.run_queue.push(domain_id);
        self.try_schedule();
    }

    fn try_schedule(&self) {
        let max = self.max_pumps.0.load(Ordering::Acquire);

        let reserved = self
            .active_pumps
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < max).then_some(active + 1)
            })
            .is_ok();

        if !reserved {
            return;
        }

        if !platform().submit_runtime(Job {
            f: pump_trampoline,
            a: 0,
        }) {
            self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
            panic!("executor reserved more runtime pumps than platform runtime capacity");
        }
    }

    #[inline]
    fn exit_pump(&self) {
        self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
    }

    fn pump(&self) {
        self.total_pump_runs.0.fetch_add(1, Ordering::Relaxed);

        loop {
            let runtime = self.runtime();

            let Some(domain_id) = runtime.run_queue.pop() else {
                break;
            };

            let Some(domain) = runtime.domains.get_domain(domain_id) else {
                continue;
            };

            if !domain.is_schedulable_for_policy() {
                domain.clear_scheduled();
                self.schedule_domain_if_needed(runtime, domain_id, &domain);
                continue;
            }

            if !domain.try_reserve_active() {
                domain.clear_scheduled();
                self.schedule_domain_if_needed(runtime, domain_id, &domain);
                continue;
            }

            domain.record_scheduler_selection();

            let tick = self.run_tick.0.fetch_add(1, Ordering::Relaxed) + 1;
            domain.record_run_started(tick);

            let budget = self.pick_domain_budget(&domain);
            let ran = self.run_domain_batch(&domain, budget);

            domain.release_active();
            domain.maybe_finish_draining();

            self.after_domain_batch(runtime, domain_id, &domain, ran);
        }

        self.exit_pump();

        if self.runnable_domain_count() != 0 {
            self.try_schedule();
        }
    }

    #[inline]
    fn pick_domain_budget(&self, domain: &ExecutorDomain) -> usize {
        let deficit = domain.add_deficit(domain.weight());
        deficit.min(domain.quantum()).max(1)
    }

    fn run_domain_batch(&self, domain: &ExecutorDomain, budget: usize) -> usize {
        let shard_count = domain.shard_count();
        let mut cursor = domain.next_pump_hint() % shard_count;
        let mut ran = 0usize;
        let budget = budget.max(1);

        while ran < budget {
            let item = match domain.pop_work(cursor) {
                Some((x, idx)) => {
                    cursor = (idx + 1) % shard_count;
                    x
                }
                None => break,
            };

            (item.trampoline)(item.ctx);
            domain.record_completed();
            ran += 1;
        }

        ran
    }

    #[inline]
    fn after_domain_batch(
        &self,
        runtime: &ExecutorRuntime,
        domain_id: DomainId,
        domain: &ExecutorDomain,
        ran_count: usize,
    ) {
        if ran_count != 0 || domain.is_runnable_for_policy() {
            domain.spend_deficit(ran_count.max(1));
        }

        domain.clear_scheduled();
        self.schedule_domain_if_needed(runtime, domain_id, domain);
    }
}

#[inline(never)]
pub extern "win64" fn pump_trampoline(_ctx: usize) {
    GlobalAsyncExecutor::global().pump();
}
