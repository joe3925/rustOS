use core::cell::Cell;
use spin::Once;

pub type JobFn = extern "C" fn(usize);

#[derive(Clone, Copy)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentExecutorContext {
    pub task_id: usize,
    pub domain_id: u64,
}

#[cfg(not(any(test, loom, feature = "loom")))]
#[thread_local]
static EXECUTOR_CONTEXT: Cell<Option<CurrentExecutorContext>> = const { Cell::new(None) };

#[cfg(any(test, loom, feature = "loom"))]
std::thread_local! {
    static EXECUTOR_CONTEXT: Cell<Option<CurrentExecutorContext>> = const { Cell::new(None) };
}

pub trait ExecutorPlatform: Send + Sync {
    fn init_runtime(&self, max_threads: usize, max_jobs: usize);
    fn init_blocking(&self, max_threads: usize);
    fn submit_runtime(&self, job: Job) -> bool;
    fn submit_blocking(&self, job: Job);
    fn submit_blocking_many(&self, jobs: &[Job]);
    fn try_steal_blocking_one(&self) -> bool;
    fn yield_now(&self);
    fn print(&self, string: &str);
    fn in_interrupt_context(&self) -> bool;
}
pub static PLATFORM: Once<&'static dyn ExecutorPlatform> = Once::new();

pub fn init(platform: &'static dyn ExecutorPlatform) {
    PLATFORM.call_once(|| platform);
}

pub fn platform() -> &'static dyn ExecutorPlatform {
    PLATFORM
        .get()
        .copied()
        .expect("executor platform not initialized")
}

pub fn current_executor_context() -> Option<CurrentExecutorContext> {
    #[cfg(not(any(test, loom, feature = "loom")))]
    {
        EXECUTOR_CONTEXT.get()
    }

    #[cfg(any(test, loom, feature = "loom"))]
    {
        EXECUTOR_CONTEXT.with(Cell::get)
    }
}

pub fn in_interrupt_context() -> bool {
    PLATFORM
        .get()
        .is_some_and(|platform| platform.in_interrupt_context())
}

pub struct CurrentExecutorContextGuard {
    previous: Option<CurrentExecutorContext>,
}

impl CurrentExecutorContextGuard {
    pub fn enter(context: CurrentExecutorContext) -> Self {
        #[cfg(not(any(test, loom, feature = "loom")))]
        let previous = EXECUTOR_CONTEXT.replace(Some(context));

        #[cfg(any(test, loom, feature = "loom"))]
        let previous = EXECUTOR_CONTEXT.with(|slot| slot.replace(Some(context)));

        Self {
            previous,
        }
    }
}

impl Drop for CurrentExecutorContextGuard {
    fn drop(&mut self) {
        #[cfg(not(any(test, loom, feature = "loom")))]
        EXECUTOR_CONTEXT.set(self.previous);

        #[cfg(any(test, loom, feature = "loom"))]
        EXECUTOR_CONTEXT.with(|slot| slot.set(self.previous));
    }
}
