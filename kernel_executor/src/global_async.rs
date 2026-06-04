use crate::platform::{platform, Job};
use crate::round_robin::SchedulerPolicy;
use crate::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::{Arc, Mutex};
use alloc::boxed::Box;
use spin::Once;

pub use crate::domain::{
    AdmissionPolicy, DestroyDomainError, DestroyDomainResult, DomainClass, DomainConfig, DomainId,
    DomainStats, DomainState, DomainTable, ExecutorDomain, GlobalExecutorStats, SubmitError,
    SubmitErrorKind, DRIVER_DOMAIN, KERNEL_BACKGROUND_DOMAIN, KERNEL_HIGH_DOMAIN,
    KERNEL_NORMAL_DOMAIN,
};
pub use crate::round_robin::{
    SimpleRoundRobinScheduler, WeightedDeficitRoundRobinScheduler,
};

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

struct ExecutorRuntime {
    domains: DomainTable,
    scheduler: Mutex<Box<dyn SchedulerPolicy>>,
}

impl ExecutorRuntime {
    fn new(shards: usize, max_work_items: usize) -> Self {
        Self {
            domains: DomainTable::new(shards, max_work_items),
            scheduler: Mutex::new(Box::new(WeightedDeficitRoundRobinScheduler::new())),
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

    fn runtime(&self) -> &ExecutorRuntime {
        self.runtime
            .get()
            .expect("global async executor not initialized")
    }

    pub fn submit(&self, trampoline: Trampoline, ctx: usize) {
        self.try_submit(trampoline, ctx)
            .expect("failed to submit to executor pool")
    }

    pub fn try_submit(&self, trampoline: Trampoline, ctx: usize) -> Result<(), WorkItem> {
        self.try_submit_to_domain(KERNEL_NORMAL_DOMAIN, trampoline, ctx)
            .map_err(SubmitError::into_work_item)
    }

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
            Err(error) => return self.reject_submit(runtime, domain_id, error),
        };

        self.total_submissions.0.fetch_add(1, Ordering::AcqRel);

        if outcome.became_runnable {
            runtime.scheduler.lock().on_domain_runnable(outcome.domain_id);
        }

        self.try_schedule();
        Ok(())
    }

    #[cold]
    fn reject_submit(
        &self,
        runtime: &ExecutorRuntime,
        domain_id: DomainId,
        error: SubmitError,
    ) -> Result<(), SubmitError> {
        self.total_rejections.0.fetch_add(1, Ordering::AcqRel);
        runtime.scheduler.lock().on_domain_rejected(domain_id);
        Err(error)
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
            runnable_domain_count: runtime.scheduler.lock().runnable_len(),
            domain_count: runtime.domains.domain_count(),
            total_submissions: self.total_submissions.0.load(Ordering::Acquire),
            total_rejections: self.total_rejections.0.load(Ordering::Acquire),
            total_pump_runs: self.total_pump_runs.0.load(Ordering::Acquire),
        }
    }

    pub fn runnable_domain_count(&self) -> usize {
        let Some(runtime) = self.runtime.get() else {
            return 0;
        };
        runtime.scheduler.lock().runnable_len()
    }

    #[cfg(test)]
    pub(crate) fn replace_scheduler_for_tests(&self, scheduler: Box<dyn SchedulerPolicy>) {
        *self.runtime().scheduler.lock() = scheduler;
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

        platform().submit_runtime(Job {
            f: pump_trampoline,
            a: 0,
        });
    }

    fn exit_pump(&self) {
        self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
    }

    fn pump(&self) {
        self.total_pump_runs.0.fetch_add(1, Ordering::AcqRel);

        loop {
            let scheduled = {
                let runtime = self.runtime();
                runtime
                    .scheduler
                    .lock()
                    .pick_next_domain(&runtime.domains)
            };

            let Some(scheduled) = scheduled else {
                break;
            };

            let Some(domain) = self.get_domain(scheduled.domain_id) else {
                continue;
            };

            if !domain.try_reserve_active() {
                self.after_domain_run(scheduled.domain_id, &domain, 0, domain.has_queued_work());
                continue;
            }

            domain.record_scheduler_selection();
            let tick = self.run_tick.0.fetch_add(1, Ordering::AcqRel) + 1;
            domain.record_run_started(tick);

            let ran = self.run_domain_batch(&domain, scheduled.budget);

            domain.release_active();
            domain.maybe_finish_draining();

            let still_runnable = domain.is_runnable_for_policy();
            self.after_domain_run(scheduled.domain_id, &domain, ran, still_runnable);
        }

        self.exit_pump();

        if self.runnable_domain_count() != 0 {
            self.try_schedule();
        }
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

    fn after_domain_run(
        &self,
        domain_id: DomainId,
        domain: &ExecutorDomain,
        ran_count: usize,
        still_runnable: bool,
    ) {
        let runtime = self.runtime();
        let mut scheduler = runtime.scheduler.lock();

        if ran_count == 0 && !still_runnable {
            scheduler.on_domain_empty(domain_id);
        } else {
            scheduler.on_domain_ran(&runtime.domains, domain_id, ran_count, still_runnable);
        }

        if still_runnable {
            return;
        }

        domain.clear_runnable();
        if domain.is_runnable_for_policy() && domain.mark_runnable() {
            scheduler.on_domain_runnable(domain_id);
        }
    }
}

#[inline(never)]
pub extern "win64" fn pump_trampoline(_ctx: usize) {
    GlobalAsyncExecutor::global().pump();
}
