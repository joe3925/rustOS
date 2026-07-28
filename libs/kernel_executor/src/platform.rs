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

pub trait ExecutorPlatform: Send + Sync {
    fn init_runtime(&self, max_threads: usize, max_jobs: usize);
    fn init_blocking(&self, max_threads: usize);
    fn submit_runtime(&self, job: Job) -> bool;
    fn submit_blocking(&self, job: Job);
    fn submit_blocking_many(&self, jobs: &[Job]);
    fn try_steal_blocking_one(&self) -> bool;
    fn yield_now(&self);
    fn print(&self, string: &str);
    fn swap_executor_context(
        &self,
        context: Option<CurrentExecutorContext>,
    ) -> Option<CurrentExecutorContext>;
    fn current_executor_context(&self) -> Option<CurrentExecutorContext>;
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
    platform().current_executor_context()
}

pub struct CurrentExecutorContextGuard {
    previous: Option<CurrentExecutorContext>,
}

impl CurrentExecutorContextGuard {
    pub fn enter(context: CurrentExecutorContext) -> Self {
        Self {
            previous: platform().swap_executor_context(Some(context)),
        }
    }
}

impl Drop for CurrentExecutorContextGuard {
    fn drop(&mut self) {
        let _ = platform().swap_executor_context(self.previous);
    }
}
