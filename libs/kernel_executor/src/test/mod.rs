extern crate std;

mod blocking;
mod executor;
mod round_robin;
mod runtime;

use crate::platform::{CurrentExecutorContext, ExecutorPlatform, Job};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

std::thread_local! {
    static EXECUTOR_CONTEXT: std::cell::Cell<Option<CurrentExecutorContext>> =
        const { std::cell::Cell::new(None) };
}

const TEST_MAX_WORK_ITEMS: usize = 2_000_000;
const EXECUTOR_MAX_SHARDS: usize = 32;

struct ThreadPoolPlatform {
    runtime_pool: OnceLock<threadpool::ThreadPool>,
    blocking_pool: OnceLock<threadpool::ThreadPool>,
}

impl ThreadPoolPlatform {
    const fn new() -> Self {
        Self {
            runtime_pool: OnceLock::new(),
            blocking_pool: OnceLock::new(),
        }
    }

    fn runtime_pool(&self) -> &threadpool::ThreadPool {
        self.runtime_pool
            .get()
            .expect("runtime executor pool not initialized")
    }

    fn blocking_pool(&self) -> &threadpool::ThreadPool {
        self.blocking_pool
            .get()
            .expect("blocking executor pool not initialized")
    }
}

impl ExecutorPlatform for ThreadPoolPlatform {
    fn init_runtime(&self, max_threads: usize, _max_jobs: usize) {
        let threads = max_threads.max(1);
        let _ = self.runtime_pool.set(threadpool::ThreadPool::new(threads));
    }

    fn init_blocking(&self, max_threads: usize) {
        let threads = max_threads.max(1);
        let _ = self.blocking_pool.set(threadpool::ThreadPool::new(threads));
    }

    fn submit_runtime(&self, job: Job) -> bool {
        self.runtime_pool().execute(move || {
            (job.f)(job.a);
        });
        true
    }

    fn submit_blocking(&self, job: Job) {
        self.blocking_pool().execute(move || {
            (job.f)(job.a);
        });
    }

    fn submit_blocking_many(&self, jobs: &[Job]) {
        for job in jobs.iter().copied() {
            self.submit_blocking(job);
        }
    }

    fn try_steal_blocking_one(&self) -> bool {
        false
    }

    fn yield_now(&self) {
        std::thread::yield_now();
    }

    fn print(&self, string: &str) {
        std::print!("{string}");
    }

    fn swap_executor_context(
        &self,
        context: Option<CurrentExecutorContext>,
    ) -> Option<CurrentExecutorContext> {
        EXECUTOR_CONTEXT.with(|slot| slot.replace(context))
    }

    fn current_executor_context(&self) -> Option<CurrentExecutorContext> {
        EXECUTOR_CONTEXT.with(std::cell::Cell::get)
    }

    fn in_interrupt_context(&self) -> bool {
        false
    }
}

static THREAD_POOL_PLATFORM: ThreadPoolPlatform = ThreadPoolPlatform::new();

fn init_test_platform() {
    crate::platform::init(&THREAD_POOL_PLATFORM);
}

fn test_shard_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, EXECUTOR_MAX_SHARDS)
}

fn stress_task_count(multiplier: usize) -> usize {
    test_shard_count() * multiplier
}

pub(crate) fn init_threaded_runtime() {
    init_test_platform();
    crate::global_async::GlobalAsyncExecutor::global()
        .init(test_shard_count(), TEST_MAX_WORK_ITEMS);
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
