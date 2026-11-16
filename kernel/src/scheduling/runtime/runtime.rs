use alloc::sync::Arc;

use kernel_executor::platform::{ExecutorPlatform, ExecutorThreadLocal, Job};
use spin::Once;

use crate::platform::current_is_in_interrupt;
use crate::sync_platform::{BoundedThreadPool, ThreadPool};

static RUNTIME_POOL: Once<Arc<BoundedThreadPool>> = Once::new();
static BLOCKING_POOL: Once<Arc<ThreadPool>> = Once::new();

pub fn yield_now() {
    crate::platform::request_task_yield();
}

pub enum KernelExecutorPlatform {}

pub type GlobalAsyncExecutor =
    kernel_executor::global_async::GlobalAsyncExecutor<KernelExecutorPlatform>;

#[thread_local]
static EXECUTOR_CONTEXT: ExecutorThreadLocal<KernelExecutorPlatform> = ExecutorThreadLocal::new();

impl ExecutorPlatform for KernelExecutorPlatform {
    fn global_executor() -> &'static GlobalAsyncExecutor {
        static EXECUTOR: Once<GlobalAsyncExecutor> = Once::new();
        EXECUTOR.call_once(GlobalAsyncExecutor::new)
    }

    fn with_executor_local<R>(f: impl FnOnce(&ExecutorThreadLocal<Self>) -> R) -> R {
        f(&EXECUTOR_CONTEXT)
    }

    fn init_runtime(max_threads: usize, max_jobs: usize) {
        let threads = max_threads.max(1);
        let jobs = max_jobs.max(1);
        RUNTIME_POOL.call_once(|| Arc::new(BoundedThreadPool::new(threads, jobs)));
    }

    fn init_blocking(max_threads: usize) {
        let threads = max_threads.max(1);
        BLOCKING_POOL.call_once(|| Arc::new(ThreadPool::new_blocking(threads)));
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
            .submit(job.f, job.a);
    }

    fn submit_blocking_many(jobs: &[Job]) {
        let pool = BLOCKING_POOL
            .get()
            .expect("blocking executor pool not initialized");
        for job in jobs {
            pool.submit(job.f, job.a);
        }
    }

    fn try_steal_blocking_one() -> bool {
        BLOCKING_POOL
            .get()
            .expect("blocking executor pool not initialized")
            .try_execute_one()
    }

    fn print(string: &str) {
        crate::static_handlers::print(string);
    }

    #[cfg_attr(irq_check, irq::context)]
    fn in_interrupt_context() -> bool {
        current_is_in_interrupt()
    }

    fn yield_now() {
        crate::platform::request_task_yield();
    }
}
