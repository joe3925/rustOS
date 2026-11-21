use alloc::{boxed::Box, format, sync::Arc};
use core::cell::Cell;

use kernel_executor::global_async::{ExecutorDomain, ExecutorDomainConfig};
use kernel_executor::platform::{ExecutorPlatform, ExecutorThreadLocal, Job};
use kernel_executor::worker_pool::{RuntimePool, WorkerPlatform};
use spin::Once;

use crate::memory::paging::stack::StackSize;
use crate::platform::current_is_in_interrupt;
use crate::scheduling::scheduler::scheduler;
use crate::scheduling::task::{Task, TaskHandle};
use crate::sync_platform::ThreadPool;

static RUNTIME_POOL: Once<RuntimePool<KernelExecutorPlatform>> = Once::new();
static KERNEL_NORMAL: Once<Arc<ExecutorDomain<KernelExecutorPlatform>>> = Once::new();
static DRIVER: Once<Arc<ExecutorDomain<KernelExecutorPlatform>>> = Once::new();
static BLOCKING_POOL: Once<Arc<ThreadPool>> = Once::new();

pub fn yield_now() {
    crate::platform::request_task_yield();
}

pub enum KernelExecutorPlatform {}

pub type GlobalAsyncExecutor =
    kernel_executor::global_async::GlobalAsyncExecutor<KernelExecutorPlatform>;

#[thread_local]
static EXECUTOR_CONTEXT: ExecutorThreadLocal<KernelExecutorPlatform> = ExecutorThreadLocal::new();

#[thread_local]
static WORKER_INDEX: Cell<usize> = Cell::new(usize::MAX);

impl WorkerPlatform for KernelExecutorPlatform {
    type WaitHandle = Once<TaskHandle>;

    fn create_wait_handle() -> Self::WaitHandle {
        Once::new()
    }

    fn init_worker(index: usize, wait_handle: &Self::WaitHandle) {
        WORKER_INDEX.set(index);
        wait_handle.call_once(|| {
            scheduler()
                .get_local_current_task()
                .expect("runtime worker has no scheduler task")
        });
    }

    fn wait(_: &Self::WaitHandle) {
        scheduler().park_current();
    }

    fn signal(wait_handle: &Self::WaitHandle) {
        scheduler().unpark(wait_handle.get().expect("runtime worker not initialized"));
    }

    fn spawn_worker(index: usize, work: impl FnOnce() + Send + 'static) {
        extern "C" fn entry(context: usize) {
            let work = unsafe { Box::from_raw(context as *mut Box<dyn FnOnce() + Send>) };
            work();
        }

        let work: Box<dyn FnOnce() + Send> = Box::new(work);
        let task = Task::new_kernel_mode(
            entry,
            Box::into_raw(Box::new(work)) as usize,
            StackSize::Tiny,
            format!("executor_worker_{index}"),
            0,
        );
        scheduler().add_task_on(task, Some(index % crate::platform::processor_count().max(1)));
    }

    fn worker_index() -> usize {
        WORKER_INDEX.get()
    }

    fn with_scheduler_critical<R>(f: impl FnOnce() -> R) -> R {
        crate::platform::with_interrupts_disabled(f)
    }
}

impl ExecutorPlatform for KernelExecutorPlatform {
    fn scheduler_time_ns() -> u64 {
        let frequency = crate::platform::cycle_counter_frequency_hz();
        assert!(frequency != 0);
        (crate::platform::cycle_counter() as u128 * 1_000_000_000 / frequency as u128) as u64
    }

    fn with_scheduler_critical<R>(f: impl FnOnce() -> R) -> R {
        crate::platform::with_interrupts_disabled(f)
    }

    const PERSISTENT_RUNTIME_WORKERS: bool = true;

    fn global_executor() -> &'static GlobalAsyncExecutor {
        static EXECUTOR: Once<GlobalAsyncExecutor> = Once::new();
        EXECUTOR.call_once(GlobalAsyncExecutor::new)
    }

    fn default_domain() -> &'static ExecutorDomain<Self> {
        KERNEL_NORMAL.get().expect("kernel normal domain not initialized").as_ref()
    }

    fn cancellation_domain() -> &'static ExecutorDomain<Self> {
        DRIVER.get().expect("driver domain not initialized").as_ref()
    }

    fn with_executor_local<R>(f: impl FnOnce(&ExecutorThreadLocal<Self>) -> R) -> R {
        f(&EXECUTOR_CONTEXT)
    }

    fn init_runtime(max_threads: usize, max_jobs: usize) {
        KERNEL_NORMAL.call_once(|| Self::global_executor().create_executor_domain(
            ExecutorDomainConfig { weight: 32 },
        ));
        DRIVER.call_once(|| Self::global_executor().create_executor_domain(
            ExecutorDomainConfig { weight: 48 },
        ));
        let threads = max_threads.max(1);
        let jobs = max_jobs.max(1);
        RUNTIME_POOL.call_once(|| RuntimePool::new(threads, jobs));
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
        pool.submit_many(jobs);
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
