use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::BlockReason;
use crate::structs::sleep_mutex::SleepMutexGuard;
use crate::structs::wait_queue::WaitQueue;

/// Condition variable for blocking tasks until a predicate is satisfied.
///
/// Works with [`SleepMutex`]; wakeups may be spurious, so callers should loop on
/// the predicate after waking.
pub struct Condvar {
    /// Wait queue for blocked tasks
    waiters: WaitQueue,
}

impl Condvar {
    /// Creates a new condition variable.
    pub fn new() -> Self {
        Self {
            waiters: WaitQueue::new(),
        }
    }

    /// Blocks the current task until this condition variable receives a notification.
    ///
    /// This function will atomically unlock the mutex and block the current task.
    /// When this function returns, the mutex will be re-acquired.
    ///
    /// The current task is enqueued before the mutex is released to avoid lost
    /// wakeups, then the task parks until a notification arrives and re-locks
    /// the mutex before returning.
    pub fn wait<'a, T>(&self, guard: SleepMutexGuard<'a, T>) -> SleepMutexGuard<'a, T> {
        let mutex = guard.mutex();

        // Enqueue before unlocking to avoid missing notifications.
        let enqueued = self.waiters.enqueue_current();

        drop(guard);

        if enqueued {
            SCHEDULER.park_current(BlockReason::CondvarWait);
        }

        // Clear any stale queue membership when a permit was consumed immediately.
        // TODO: figure out why calling this dropped throughput significantly
        let _ = self.waiters.clear_current_if_queued();

        mutex.lock()
    }

    /// Wakes up one task waiting on this condition variable.
    ///
    /// If there are any tasks waiting, one will be woken up. The order
    /// of wakeup is FIFO (first waiter is woken first).
    ///
    /// It is generally recommended to call this while the associated mutex
    /// is held to avoid race conditions on the predicate being waited on.
    pub fn notify_one(&self) {
        if let Some(task) = self.waiters.dequeue_one() {
            SCHEDULER.unpark(&task);
        }
    }

    /// Wakes up all tasks waiting on this condition variable.
    ///
    /// All currently waiting tasks will be woken up. Tasks that start
    /// waiting after this call will not be woken.
    pub fn notify_all(&self) {
        let tasks = self.waiters.dequeue_all();
        for task in tasks {
            SCHEDULER.unpark(&task);
        }
    }

    /// Returns the number of tasks currently waiting on this condvar.
    ///
    /// This is primarily useful for debugging and testing.
    /// Note: This is approximate and may be stale by the time it's used.
    pub fn waiters_count(&self) -> usize {
        self.waiters.len()
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: Condvar uses WaitQueue which handles synchronization internally
unsafe impl Send for Condvar {}
unsafe impl Sync for Condvar {}
