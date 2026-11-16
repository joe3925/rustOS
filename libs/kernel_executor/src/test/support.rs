extern crate std;

use crate::platform::Job;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const EXECUTOR_MAX_SHARDS: usize = 32;

pub(crate) static RUNTIME_POOL: OnceLock<threadpool::ThreadPool> = OnceLock::new();
static BLOCKING_POOL: OnceLock<threadpool::ThreadPool> = OnceLock::new();

#[unsafe(export_name = "__kernel_executor_platform_init_runtime")]
fn init_runtime(max_threads: usize, _max_jobs: usize) {
    let threads = max_threads.max(1);
    let _ = RUNTIME_POOL.set(threadpool::ThreadPool::new(threads));
}

#[unsafe(export_name = "__kernel_executor_platform_init_blocking")]
fn init_blocking(max_threads: usize) {
    let threads = max_threads.max(1);
    let _ = BLOCKING_POOL.set(threadpool::ThreadPool::new(threads));
}

#[unsafe(export_name = "__kernel_executor_platform_submit_runtime")]
fn submit_runtime(job: Job) -> bool {
    RUNTIME_POOL
        .get()
        .expect("runtime executor pool not initialized")
        .execute(move || (job.f)(job.a));
    true
}

#[unsafe(export_name = "__kernel_executor_platform_submit_blocking")]
fn submit_blocking(job: Job) {
    BLOCKING_POOL
        .get()
        .expect("blocking executor pool not initialized")
        .execute(move || (job.f)(job.a));
}

#[unsafe(export_name = "__kernel_executor_platform_submit_blocking_many")]
fn submit_blocking_many(jobs: &[Job]) {
    let pool = BLOCKING_POOL
        .get()
        .expect("blocking executor pool not initialized");
    for job in jobs.iter().copied() {
        pool.execute(move || (job.f)(job.a));
    }
}

#[unsafe(export_name = "__kernel_executor_platform_try_steal_blocking_one")]
fn try_steal_blocking_one() -> bool {
    false
}

#[unsafe(export_name = "__kernel_executor_platform_yield_now")]
fn yield_now() {
    std::thread::yield_now();
}

#[unsafe(export_name = "__kernel_executor_platform_print")]
fn print(string: &str) {
    std::print!("{string}");
}

#[unsafe(export_name = "__kernel_executor_platform_in_interrupt_context")]
fn in_interrupt_context() -> bool {
    false
}

pub(super) fn test_shard_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, EXECUTOR_MAX_SHARDS)
}

pub(super) fn stress_task_count(multiplier: usize) -> usize {
    test_shard_count() * multiplier
}

pub(crate) fn init_threaded_runtime() {
    crate::global_async::GlobalAsyncExecutor::global().init(test_shard_count(), 1024);
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
