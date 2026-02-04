use spin::Once;

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}

pub trait ExecutorPlatform: Send + Sync {
    fn submit_runtime(&self, job: Job);
    fn submit_blocking(&self, job: Job);
    fn submit_blocking_many(&self, jobs: &[Job]);
    fn try_steal_blocking_one(&self) -> bool;
    fn yield_now(&self);
    fn print(&self, string: &str);
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
