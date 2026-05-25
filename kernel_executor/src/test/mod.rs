extern crate std;

mod blocking;
mod runtime;
mod slab;
mod task;

use crate::platform::{ExecutorPlatform, Job};

struct InlinePlatform;

impl ExecutorPlatform for InlinePlatform {
    fn init_runtime(&self, _max_threads: usize, _max_jobs: usize) {}

    fn init_blocking(&self, _max_threads: usize) {}

    fn submit_runtime(&self, job: Job) {
        (job.f)(job.a);
    }

    fn submit_blocking(&self, job: Job) {
        (job.f)(job.a);
    }

    fn submit_blocking_many(&self, jobs: &[Job]) {
        for job in jobs {
            (job.f)(job.a);
        }
    }

    fn try_steal_blocking_one(&self) -> bool {
        false
    }

    fn yield_now(&self) {}

    fn print(&self, _string: &str) {}
}

static INLINE_PLATFORM: InlinePlatform = InlinePlatform;

fn init_inline_platform() {
    crate::platform::init(&INLINE_PLATFORM);
}

fn init_inline_runtime() {
    init_inline_platform();
    crate::global_async::GlobalAsyncExecutor::global().init(1);
}

fn global_runtime_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().expect("kernel_executor test runtime lock")
}
