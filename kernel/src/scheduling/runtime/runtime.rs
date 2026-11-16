use alloc::sync::Arc;

use kernel_executor::platform::Job;
use spin::Once;

use crate::platform::current_is_in_interrupt;
use crate::sync_platform::{BoundedThreadPool, ThreadPool};

static RUNTIME_POOL: Once<Arc<BoundedThreadPool>> = Once::new();
static BLOCKING_POOL: Once<Arc<ThreadPool>> = Once::new();

#[unsafe(export_name = "__kernel_executor_platform_yield_now")]
pub fn yield_now() {
    crate::platform::request_task_yield();
}

#[unsafe(export_name = "__kernel_executor_platform_init_runtime")]
fn init_runtime(max_threads: usize, max_jobs: usize) {
    let threads = max_threads.max(1);
    let jobs = max_jobs.max(1);
    RUNTIME_POOL.call_once(|| Arc::new(BoundedThreadPool::new(threads, jobs)));
}

#[unsafe(export_name = "__kernel_executor_platform_init_blocking")]
fn init_blocking(max_threads: usize) {
    let threads = max_threads.max(1);
    BLOCKING_POOL.call_once(|| Arc::new(ThreadPool::new_blocking(threads)));
}

#[unsafe(export_name = "__kernel_executor_platform_submit_runtime")]
fn submit_runtime(job: Job) -> bool {
    RUNTIME_POOL
        .get()
        .expect("runtime executor pool not initialized")
        .submit(job.f, job.a)
}

#[unsafe(export_name = "__kernel_executor_platform_submit_blocking")]
fn submit_blocking(job: Job) {
    BLOCKING_POOL
        .get()
        .expect("blocking executor pool not initialized")
        .submit(job.f, job.a);
}

#[unsafe(export_name = "__kernel_executor_platform_submit_blocking_many")]
fn submit_blocking_many(jobs: &[Job]) {
    let pool = BLOCKING_POOL
        .get()
        .expect("blocking executor pool not initialized");
    for job in jobs {
        pool.submit(job.f, job.a);
    }
}

#[unsafe(export_name = "__kernel_executor_platform_try_steal_blocking_one")]
fn try_steal_blocking_one() -> bool {
    BLOCKING_POOL
        .get()
        .expect("blocking executor pool not initialized")
        .try_execute_one()
}

#[unsafe(export_name = "__kernel_executor_platform_print")]
fn print(string: &str) {
    crate::static_handlers::print(string);
}

#[unsafe(export_name = "__kernel_executor_platform_in_interrupt_context")]
#[cfg_attr(irq_check, irq::context)]
fn in_interrupt_context() -> bool {
    current_is_in_interrupt()
}
