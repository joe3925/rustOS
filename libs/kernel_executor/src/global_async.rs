use crate::platform::{ExecutorBatchGuard, Job, SlabCache, platform, with_executor_local};
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use alloc::boxed::Box;
use kernel_types::bounded_mpmc::{BoundedMpmcPushError, BoundedMpmcQueue};
use spin::Once;

pub use crate::domain::{
    DRIVER_EXECUTOR_DOMAIN, DestroyExecutorDomainError, DestroyExecutorDomainResult,
    ExecutorDomain, ExecutorDomainClass, ExecutorDomainConfig, ExecutorDomainId,
    ExecutorDomainState, ExecutorDomainStats, ExecutorDomainTable, GlobalExecutorStats,
    KERNEL_BACKGROUND_EXECUTOR_DOMAIN, KERNEL_HIGH_EXECUTOR_DOMAIN, KERNEL_NORMAL_EXECUTOR_DOMAIN,
};

#[repr(align(64))]
pub(crate) struct CacheAligned(pub(crate) AtomicUsize);

const MAX_SHARDS: usize = 32;

struct DomainRunQueue {
    queue: BoundedMpmcQueue<ExecutorDomainId>,
}

impl DomainRunQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queue: BoundedMpmcQueue::new(capacity.max(1)),
        }
    }

    #[inline]
    fn push(&self, domain_id: ExecutorDomainId) {
        match self.queue.try_push(domain_id) {
            Ok(()) => {}
            Err(BoundedMpmcPushError::Full(_)) => {
                panic!("executor run queue full; scheduler token invariant is broken")
            }
            _ => unreachable!(),
        }
    }

    #[inline]
    fn pop(&self) -> Option<ExecutorDomainId> {
        self.queue.try_pop()
    }

    #[inline]
    fn len(&self) -> usize {
        self.queue.len()
    }
}

#[repr(align(64))]
pub(crate) struct WorkerShared {
    claimed: AtomicBool,
    next_task: AtomicUsize,
}

impl WorkerShared {
    fn take_task(&self) -> usize {
        if self.next_task.load(Ordering::Acquire) == 0 {
            0
        } else {
            self.next_task.swap(0, Ordering::AcqRel)
        }
    }
}

struct WorkerGuard<'a> {
    worker: Option<&'a WorkerShared>,
    previous: *const WorkerShared,
}

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        GlobalAsyncExecutor::global().flush_local_task();
        with_executor_local(|tls| tls.worker.set(self.previous));
        if let Some(worker) = self.worker {
            worker.claimed.store(false, Ordering::Release);
        }
    }
}

struct ExecutorRuntime {
    domains: ExecutorDomainTable,
    workers: Box<[WorkerShared]>,
    run_queue: DomainRunQueue,
}

impl ExecutorRuntime {
    fn new(cpu_count: usize) -> Self {
        Self {
            domains: ExecutorDomainTable::new(cpu_count),
            workers: (0..cpu_count)
                .map(|_| WorkerShared {
                    claimed: AtomicBool::new(false),
                    next_task: AtomicUsize::new(0),
                })
                .collect(),
            run_queue: DomainRunQueue::new(crate::runtime::slab::constants::MAX_TASK_SLOTS),
        }
    }
}

pub struct GlobalAsyncExecutor {
    runtime: Once<ExecutorRuntime>,
    active_pumps: CacheAligned,
    max_pumps: CacheAligned,
    total_submissions: CacheAligned,
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
            total_pump_runs: CacheAligned(AtomicUsize::new(0)),
            run_tick: CacheAligned(AtomicUsize::new(0)),
        })
    }

    pub fn init(&self, shards: usize, initial_task_capacity: usize) {
        let shards = shards.clamp(1, MAX_SHARDS);

        crate::runtime::slab::task_slab::init_task_table_with(|config| {
            config.capacity(initial_task_capacity)
        });

        self.runtime.call_once(|| ExecutorRuntime::new(shards));

        self.max_pumps.0.store(shards, Ordering::Release);

        platform().init_blocking(shards);
        platform().init_runtime(shards, shards);

        if self.runnable_executor_domain_count() != 0 {
            self.try_schedule();
        }
    }

    #[inline]
    fn runtime(&self) -> &ExecutorRuntime {
        self.runtime
            .get()
            .expect("global async executor not initialized")
    }

    pub(crate) fn enqueue_task_to_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
        task_id: usize,
    ) {
        self.with_executor_domain(domain_id, |domain| {
            domain.submitted.0.fetch_add(1, Ordering::Relaxed);
            self.total_submissions.0.fetch_add(1, Ordering::Relaxed);
            let local = !crate::platform::in_interrupt_context()
                && with_executor_local(|tls| {
                    if tls.active_domain.get() != domain as *const ExecutorDomain {
                        return false;
                    }
                    let Some(worker) = (unsafe { tls.worker.get().as_ref() }) else {
                        return false;
                    };
                    worker
                        .next_task
                        .compare_exchange(0, task_id, Ordering::Release, Ordering::Relaxed)
                        .is_ok()
                });
            if local {
                if !domain.is_at_active_limit() {
                    self.try_schedule();
                }
            } else {
                assert!(
                    domain.enqueue_task(task_id),
                    "failed to enqueue executor task"
                );
                self.schedule_domain_if_needed(self.runtime(), domain_id, domain);
            }
        })
        .expect("invalid executor domain for task wake");
    }

    pub(crate) fn with_executor_domain<R>(
        &self,
        domain_id: ExecutorDomainId,
        f: impl FnOnce(&ExecutorDomain) -> R,
    ) -> Option<R> {
        if !crate::platform::in_interrupt_context() {
            let cached = with_executor_local(|tls| tls.active_domain.get());
            if let Some(domain) = unsafe { cached.as_ref() } {
                if domain.id() == domain_id && domain.state() != ExecutorDomainState::Dead {
                    return Some(f(domain));
                }
            }
        }
        let domain = self.get_executor_domain(domain_id)?;
        Some(f(&domain))
    }

    pub(crate) fn publish_claimed_task(&self, task_id: usize) {
        if task_id == 0 {
            return;
        }
        let (shard, local, generation) =
            crate::runtime::slab::ptr::decode_slab_task_ptr(task_id).expect("invalid local task");
        let slot = crate::runtime::slab::task_slab::get_task_table()
            .get_slot(shard, local, generation)
            .expect("local task reference lost");
        let domain_id = slot.executor_domain_id().expect("local task domain lost");
        self.with_executor_domain(domain_id, |domain| {
            assert!(domain.enqueue_task(task_id), "failed to publish local task");
            self.schedule_domain_if_needed(self.runtime(), domain_id, domain);
        })
        .expect("local task domain disappeared");
    }

    pub(crate) fn flush_local_task(&self) {
        if crate::platform::in_interrupt_context() {
            return;
        }
        let task = with_executor_local(|tls| {
            unsafe { tls.worker.get().as_ref() }
                .map_or(0, WorkerShared::take_task)
        });
        self.publish_claimed_task(task);
    }

    pub fn create_executor_domain(&self, config: ExecutorDomainConfig) -> ExecutorDomainId {
        self.runtime().domains.create_executor_domain(config)
    }

    pub fn worker_count(&self) -> usize {
        self.max_pumps.0.load(Ordering::Acquire)
    }

    pub fn destroy_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Result<DestroyExecutorDomainResult, DestroyExecutorDomainError> {
        self.runtime().domains.destroy_executor_domain(domain_id)
    }

    pub fn get_executor_domain(&self, domain_id: ExecutorDomainId) -> Option<Arc<ExecutorDomain>> {
        self.runtime().domains.get_executor_domain(domain_id)
    }

    pub fn executor_domain_stats(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Option<ExecutorDomainStats> {
        self.get_executor_domain(domain_id)
            .map(|domain| domain.stats())
    }

    pub fn stats(&self) -> GlobalExecutorStats {
        let runtime = self.runtime();

        GlobalExecutorStats {
            active_pumps: self.active_pumps.0.load(Ordering::Acquire),
            max_pumps: self.max_pumps.0.load(Ordering::Acquire),
            runnable_executor_domain_count: runtime.run_queue.len(),
            domain_count: runtime.domains.domain_count(),
            total_submissions: self.total_submissions.0.load(Ordering::Relaxed),
            total_pump_runs: self.total_pump_runs.0.load(Ordering::Relaxed),
        }
    }

    pub fn runnable_executor_domain_count(&self) -> usize {
        let Some(runtime) = self.runtime.get() else {
            return 0;
        };

        runtime.run_queue.len()
    }

    #[inline]
    fn schedule_domain_if_needed(
        &self,
        runtime: &ExecutorRuntime,
        domain_id: ExecutorDomainId,
        domain: &ExecutorDomain,
    ) {
        if !domain.is_schedulable_for_policy() {
            return;
        }

        while domain.try_reserve_schedule_token() {
            runtime.run_queue.push(domain_id);
            self.try_schedule();
        }
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
            return;
        }
    }

    #[inline]
    fn exit_pump(&self) {
        self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
    }

    fn pump(&self) {
        self.flush_local_task();
        let worker = self
            .runtime()
            .workers
            .iter()
            .enumerate()
            .find(|(_, worker)| {
                worker
                    .claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            });
        let previous = with_executor_local(|tls| {
            if let Some((index, _)) = worker {
                tls.ready_cursor.set(index);
                tls.allocation_cursor.set(index);
            }
            tls.worker
                .replace(worker.map_or(core::ptr::null(), |(_, worker)| worker))
        });
        let worker_guard = WorkerGuard {
            worker: worker.map(|(_, worker)| worker),
            previous,
        };
        self.total_pump_runs.0.fetch_add(1, Ordering::Relaxed);

        loop {
            let runtime = self.runtime();

            let domain_id = match runtime.run_queue.pop() {
                Some(domain_id) => domain_id,
                None => {
                    for worker in &runtime.workers {
                        self.publish_claimed_task(worker.take_task());
                    }
                    let Some(domain_id) = runtime.run_queue.pop() else {
                        break;
                    };
                    domain_id
                }
            };

            let Some(domain) = runtime.domains.get_executor_domain(domain_id) else {
                continue;
            };

            if !domain.is_schedulable_for_policy() {
                domain.release_schedule_token();
                self.schedule_domain_if_needed(runtime, domain_id, &domain);
                continue;
            }

            if !domain.try_reserve_active() {
                domain.release_schedule_token();
                self.schedule_domain_if_needed(runtime, domain_id, &domain);
                continue;
            }

            domain.release_schedule_token();
            domain.record_scheduler_selection();

            let tick = self.run_tick.0.fetch_add(1, Ordering::Relaxed) + 1;
            domain.record_run_started(tick);

            let budget = self.pick_domain_budget(&domain);
            let ran = self.run_domain_batch(&domain, budget);

            domain.release_active();
            domain.maybe_finish_draining();

            self.after_domain_batch(runtime, domain_id, &domain, ran);
        }

        drop(worker_guard);
        self.exit_pump();

        if self.runnable_executor_domain_count() != 0 {
            self.try_schedule();
        }
    }

    #[inline]
    fn pick_domain_budget(&self, domain: &ExecutorDomain) -> usize {
        let deficit = domain.add_deficit(domain.weight());
        deficit.min(domain.quantum()).max(1)
    }

    fn run_domain_batch(&self, domain: &ExecutorDomain, budget: usize) -> usize {
        let (previous_domain, previous_caches) = with_executor_local(|tls| {
            let mut caches = tls.caches.borrow_mut();
            let previous_caches = caches
                .iter()
                .any(|cache| !cache.owner.is_null())
                .then(|| core::mem::replace(&mut *caches, [const { SlabCache::new() }; 8]));
            (tls.active_domain.replace(domain), previous_caches)
        });
        let _batch = ExecutorBatchGuard {
            previous_domain,
            previous_caches,
        };
        let mut ran = 0usize;
        let mut local_runs = 0usize;
        let budget = budget.max(1);

        while ran < budget {
            let local_task = if local_runs < 3 {
                with_executor_local(|tls| {
                    unsafe { tls.worker.get().as_ref() }
                        .map_or(0, WorkerShared::take_task)
                })
            } else {
                0
            };
            let task_id = if local_task != 0 {
                local_runs += 1;
                local_task
            } else {
                local_runs = 0;
                match domain.pop_task() {
                    Some(task_id) => task_id,
                    None => {
                        let task = with_executor_local(|tls| {
                            unsafe { tls.worker.get().as_ref() }
                                .map_or(0, WorkerShared::take_task)
                        });
                        if task == 0 {
                            break;
                        }
                        task
                    }
                }
            };

            crate::runtime::slab::ptr::slab_task_poll_trampoline(task_id);
            domain.record_completed();
            ran += 1;
        }

        ran
    }

    #[inline]
    fn after_domain_batch(
        &self,
        runtime: &ExecutorRuntime,
        domain_id: ExecutorDomainId,
        domain: &ExecutorDomain,
        ran_count: usize,
    ) {
        if ran_count != 0 || domain.is_runnable_for_policy() {
            domain.spend_deficit(ran_count.max(1));
        }

        self.schedule_domain_if_needed(runtime, domain_id, domain);
    }
}

#[inline(never)]
pub extern "C" fn pump_trampoline(_ctx: usize) {
    GlobalAsyncExecutor::global().pump();
}
