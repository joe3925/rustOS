use alloc::sync::Arc;

use kernel_executor::platform::{self as exec_platform, ExecutorPlatform, Job};
use kernel_executor::runtime::runtime as exec_runtime;
use spin::Once;

use crate::static_handlers::{print, task_yield};
use crate::structs::thread_pool::{BoundedThreadPool, ThreadPool};

struct KernelExecutorPlatform {
    runtime_pool: Once<Arc<BoundedThreadPool>>,
    blocking_pool: Once<Arc<ThreadPool>>,
}

impl KernelExecutorPlatform {
    pub const fn new() -> Self {
        Self {
            runtime_pool: Once::new(),
            blocking_pool: Once::new(),
        }
    }

    fn runtime_pool(&self) -> &Arc<BoundedThreadPool> {
        self.runtime_pool
            .get()
            .expect("runtime executor pool not initialized")
    }

    fn blocking_pool(&self) -> &Arc<ThreadPool> {
        self.blocking_pool
            .get()
            .expect("blocking executor pool not initialized")
    }
}

pub fn yield_now() {
    unsafe { task_yield() };
}

impl ExecutorPlatform for KernelExecutorPlatform {
    fn init_runtime(&self, max_threads: usize, max_jobs: usize) {
        let threads = max_threads.max(1);
        let jobs = max_jobs.max(1);

        self.runtime_pool
            .call_once(|| Arc::new(BoundedThreadPool::new(threads, jobs)));
    }

    fn init_blocking(&self, max_threads: usize) {
        let threads = max_threads.max(1);

        self.blocking_pool
            .call_once(|| Arc::new(ThreadPool::new_blocking(threads)));
    }

    fn submit_runtime(&self, job: Job) -> bool {
        self.runtime_pool().submit(job.f, job.a)
    }

    fn submit_blocking(&self, job: Job) {
        self.blocking_pool().submit(job.f, job.a);
    }

    fn submit_blocking_many(&self, jobs: &[Job]) {
        let pool = self.blocking_pool();

        for job in jobs {
            pool.submit(job.f, job.a);
        }
    }

    fn try_steal_blocking_one(&self) -> bool {
        self.blocking_pool().try_execute_one()
    }

    fn yield_now(&self) {
        yield_now();
    }

    fn print(&self, string: &str) {
        print(string);
    }
}

static PLATFORM: KernelExecutorPlatform = KernelExecutorPlatform::new();

pub fn init_executor_platform() {
    exec_platform::init(&PLATFORM);
}

pub use exec_runtime::block_on;
pub use exec_runtime::spawn;
pub use exec_runtime::spawn_blocking;
pub use exec_runtime::spawn_blocking_many;
pub use exec_runtime::spawn_detached;
pub use exec_runtime::spawn_detached_in_executor_domain;
pub use exec_runtime::try_steal_blocking_one;
pub use exec_runtime::JoinAll;
