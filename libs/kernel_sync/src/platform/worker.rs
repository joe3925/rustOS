pub trait WorkerPlatform: Send + Sync + 'static {
    type WaitHandle: Send + Sync + 'static;

    const SPIN_LIMIT: usize = 16;

    fn create_wait_handle() -> Self::WaitHandle;
    fn init_worker(index: usize, wait_handle: &Self::WaitHandle);
    fn wait(wait_handle: &Self::WaitHandle);
    fn signal(wait_handle: &Self::WaitHandle);
    fn spawn_worker(index: usize, work: impl FnOnce() + Send + 'static);
    fn worker_index() -> usize;

    fn with_scheduler_critical<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
}
