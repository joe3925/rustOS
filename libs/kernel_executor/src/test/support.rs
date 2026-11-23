extern crate std;

use crate::platform::{ExecutorPlatform, ExecutorThreadLocal, Job};
use crate::worker_pool::{RuntimePool, WorkerPlatform};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use worker_platform::StdWorkerPlatform;

#[path = "worker_platform.rs"]
mod worker_platform;

const EXECUTOR_MAX_SHARDS: usize = 32;

pub(crate) static RUNTIME_POOL: OnceLock<RuntimePool<StdWorkerPlatform>> = OnceLock::new();
static DEFAULT_DOMAIN: OnceLock<std::sync::Arc<crate::global_async::ExecutorDomain<TestExecutorPlatform>>> = OnceLock::new();
static CANCELLATION_DOMAIN: OnceLock<std::sync::Arc<crate::global_async::ExecutorDomain<TestExecutorPlatform>>> = OnceLock::new();
static BLOCKING_POOL: OnceLock<threadpool::ThreadPool> = OnceLock::new();

pub enum TestExecutorPlatform {}

pub type GlobalAsyncExecutor = crate::global_async::GlobalAsyncExecutor<TestExecutorPlatform>;

std::thread_local! {
    static EXECUTOR_CONTEXT: ExecutorThreadLocal<TestExecutorPlatform> = const { ExecutorThreadLocal::new() };
}

impl ExecutorPlatform for TestExecutorPlatform {
    const PERSISTENT_RUNTIME_WORKERS: bool = true;

    fn global_executor() -> &'static GlobalAsyncExecutor {
        static EXECUTOR: spin::Once<GlobalAsyncExecutor> = spin::Once::new();
        EXECUTOR.call_once(GlobalAsyncExecutor::new)
    }

    fn default_domain() -> &'static crate::global_async::ExecutorDomain<Self> {
        DEFAULT_DOMAIN.get().expect("default domain not initialized").as_ref()
    }

    fn cancellation_domain() -> &'static crate::global_async::ExecutorDomain<Self> {
        CANCELLATION_DOMAIN.get().expect("cancellation domain not initialized").as_ref()
    }

    fn with_executor_local<R>(f: impl FnOnce(&ExecutorThreadLocal<Self>) -> R) -> R {
        EXECUTOR_CONTEXT.with(f)
    }

    fn init_runtime(max_threads: usize, max_jobs: usize) {
        DEFAULT_DOMAIN.get_or_init(|| Self::global_executor().create_executor_domain(
            crate::global_async::ExecutorDomainConfig::default(),
        ));
        CANCELLATION_DOMAIN.get_or_init(|| Self::global_executor().create_executor_domain(
            crate::global_async::ExecutorDomainConfig::default(),
        ));
        let threads = max_threads.max(1);
        let _ = RUNTIME_POOL.set(RuntimePool::new(threads, max_jobs.max(1)));
    }

    fn init_blocking(max_threads: usize) {
        let threads = max_threads.max(1);
        let _ = BLOCKING_POOL.set(threadpool::ThreadPool::new(threads));
    }

    fn submit_runtime(job: Job) -> bool {
        RUNTIME_POOL
            .get()
            .expect("runtime executor pool not initialized")
            .submit(job.f, job.a)
    }

    fn submit_blocking(job: Job) {
        BLOCKING_POOL
            .get()
            .expect("blocking executor pool not initialized")
            .execute(move || (job.f)(job.a));
    }

    fn wake_runtime_worker<const IDLE_ONLY: bool>(active: usize) -> bool {
        RUNTIME_POOL
            .get()
            .is_some_and(|pool| pool.wake(IDLE_ONLY, active))
    }

    fn wait_for_runtime_work(work_pending: impl FnOnce() -> bool) -> bool {
        RUNTIME_POOL.get().unwrap().wait(work_pending)
    }

    fn runtime_search<const START: bool>() -> bool {
        RUNTIME_POOL.get().unwrap().search::<START>()
    }

    fn submit_blocking_many(jobs: &[Job]) {
        let pool = BLOCKING_POOL
            .get()
            .expect("blocking executor pool not initialized");
        for job in jobs.iter().copied() {
            pool.execute(move || (job.f)(job.a));
        }
    }

    fn try_steal_blocking_one() -> bool {
        false
    }

    fn yield_now() {
        std::thread::yield_now();
    }

    fn print(string: &str) {
        std::print!("{string}");
    }

    fn in_interrupt_context() -> bool {
        false
    }
}

pub(crate) fn test_shard_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, EXECUTOR_MAX_SHARDS)
}

pub(crate) fn stress_task_count(multiplier: usize) -> usize {
    test_shard_count() * multiplier
}

pub(crate) fn init_threaded_runtime() {
    GlobalAsyncExecutor::global().init(test_shard_count(), 1024);
}

pub(crate) fn wait_until<F>(timeout: Duration, mut done: F)
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for executor test work to finish"
        );
        std::thread::yield_now();
    }
}

pub(crate) fn global_runtime_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().expect("kernel_executor test runtime lock")
}
