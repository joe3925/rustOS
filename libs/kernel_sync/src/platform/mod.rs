use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ParkReason {
    None = 0,
    MutexLock = 1,
    ChannelRecv = 2,
    ChannelSend = 3,
    CondvarWait = 4,
    Sleep = 5,
    IoWait = 6,
    FutexWait = 7,
    TaskJoin = 8,
    IrqWait = 9,
}

pub type ThreadEntry = extern "C" fn(usize);

/// Static platform binding used by the sync primitives.
///
/// The primitives are generic over this trait and never store `dyn Platform`,
/// so platform calls are monomorphized by the compiler.
pub trait Platform: Sized + 'static {
    type Task: Clone + Send + Sync + 'static;

    fn current_task() -> Option<Self::Task>;
    fn task_id(task: &Self::Task) -> u64;
    fn same_task(a: &Self::Task, b: &Self::Task) -> bool;

    fn mark_waiting(task: &Self::Task, wait_queue_id: u64) -> bool;
    fn clear_waiting(task: &Self::Task, wait_queue_id: u64) -> bool;
    fn is_waiting(task: &Self::Task, wait_queue_id: u64) -> bool;

    fn unpark(task: &Self::Task);
    fn park_current(reason: ParkReason);

    fn spawn_thread(name: String, entry: ThreadEntry, context: usize);

    #[inline]
    fn prepare_blocking_worker() {}

    #[inline]
    fn spin_loop() {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "std")]
pub mod std;

#[cfg(feature = "std")]
pub use self::std::StdPlatform;

#[cfg(all(feature = "std", windows))]
pub type WindowsPlatform = StdPlatform;
