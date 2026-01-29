use alloc::sync::Arc;
use alloc::vec::Vec;

use kernel_executor::platform::{self as exec_platform, ExecutorPlatform, Job};
use kernel_executor::runtime::runtime as exec_runtime;

use crate::static_handlers::task_yield;
use crate::structs::thread_pool::{Job as TpJob, ThreadPool};

lazy_static::lazy_static! {
    pub static ref RUNTIME_POOL: Arc<ThreadPool> = Arc::new(ThreadPool::new(6));
    pub static ref BLOCKING_POOL: Arc<ThreadPool> = Arc::new(ThreadPool::new(6));
}

struct KernelExecutorPlatform;

impl ExecutorPlatform for KernelExecutorPlatform {
    fn submit_runtime(&self, job: Job) {
        RUNTIME_POOL.submit(job.f, job.a);
    }

    fn submit_blocking(&self, job: Job) {
        BLOCKING_POOL.submit(job.f, job.a);
    }

    fn submit_blocking_many(&self, jobs: &[Job]) {
        let mut mapped: Vec<TpJob> = Vec::with_capacity(jobs.len());
        for j in jobs {
            mapped.push(TpJob { f: j.f, a: j.a });
        }
        BLOCKING_POOL.submit_many(&mapped);
    }

    fn try_steal_blocking_one(&self) -> bool {
        BLOCKING_POOL.try_execute_one()
    }

    fn yield_now(&self) {
        unsafe { task_yield() };
    }
}

static PLATFORM: KernelExecutorPlatform = KernelExecutorPlatform;

pub fn init_executor_platform() {
    exec_platform::init(&PLATFORM);
}

pub use exec_runtime::block_on;
pub use exec_runtime::spawn;
pub use exec_runtime::spawn_blocking;
pub use exec_runtime::spawn_blocking_many;
pub use exec_runtime::spawn_detached;
pub use exec_runtime::try_steal_blocking_one;
pub use exec_runtime::yield_now;
pub use exec_runtime::{BlockingJoin, JoinAll, JoinHandle};
