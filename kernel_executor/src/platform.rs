use spin::Once;

/// Function pointer type used by the executor to schedule jobs.
pub type JobFn = extern "win64" fn(usize);

/// A job consists of a trampoline function and an opaque context pointer.
#[derive(Clone, Copy)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}

/// Platform hooks the executor needs from the embedding kernel.
pub trait ExecutorPlatform: Send + Sync {
    fn submit_runtime(&self, job: Job);
    fn submit_blocking(&self, job: Job);
    fn submit_blocking_many(&self, jobs: &[Job]);
    fn try_steal_blocking_one(&self) -> bool;
    fn yield_now(&self);
    fn print(&self, string: &str);
}
pub static PLATFORM: Once<&'static dyn ExecutorPlatform> = Once::new();

/// Install the platform callbacks. Must be called exactly once by the kernel.
pub fn init(platform: &'static dyn ExecutorPlatform) {
    PLATFORM.call_once(|| platform);
}

/// Get the installed platform callbacks.
pub fn platform() -> &'static dyn ExecutorPlatform {
    PLATFORM
        .get()
        .copied()
        .expect("executor platform not initialized")
}
