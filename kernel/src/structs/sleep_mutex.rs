use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::BlockReason;
use crate::structs::wait_queue::WaitQueue;

/// Sleepable mutex that blocks tasks via the scheduler instead of spinning.
pub struct SleepMutex<T> {
    locked: AtomicUsize,
    waiters: WaitQueue,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SleepMutex<T> {}
unsafe impl<T: Send> Sync for SleepMutex<T> {}

impl<T> SleepMutex<T> {
    /// Create a new unlocked mutex containing the given value.
    pub fn new(value: T) -> Self {
        Self {
            locked: AtomicUsize::new(0),
            waiters: WaitQueue::new(),
            value: UnsafeCell::new(value),
        }
    }

    /// Try to acquire the mutex without blocking.
    ///
    /// Returns `Some(guard)` if the lock was acquired, `None` if it's held by another task.
    pub fn try_lock(&self) -> Option<SleepMutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SleepMutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// Acquire the mutex, sleeping via the scheduler if it is already held.
    ///
    /// Uses a check-under-lock pattern: try the fast path, otherwise enqueue,
    /// re-check, and only sleep if the mutex is still held.
    pub fn lock(&self) -> SleepMutexGuard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }

            let enqueued = self.waiters.enqueue_current();

            if !enqueued {
                self.waiters.clear_current_if_queued();
                continue;
            }

            if let Some(guard) = self.try_lock() {
                let _ = self.waiters.clear_current_if_queued();
                return guard;
            }

            SCHEDULER.park_current(BlockReason::MutexLock);
        }
    }

    /// Release the mutex and wake one waiting task.
    fn unlock(&self) {
        self.locked.store(0, Ordering::Release);

        if let Some(task) = self.waiters.dequeue_one() {
            SCHEDULER.unpark(&task);
        }
    }
}

/// RAII guard for `SleepMutex`.
///
/// The mutex is released when this guard is dropped.
pub struct SleepMutexGuard<'a, T> {
    mutex: &'a SleepMutex<T>,
}

impl<'a, T> SleepMutexGuard<'a, T> {
    /// Returns a reference to the underlying mutex.
    ///
    /// This is used by [`Condvar::wait`] to re-acquire the mutex after waking.
    #[inline]
    pub fn mutex(&self) -> &'a SleepMutex<T> {
        self.mutex
    }
}

unsafe impl<'a, T: Send> Send for SleepMutexGuard<'a, T> {}

impl<'a, T> Drop for SleepMutexGuard<'a, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

impl<'a, T> Deref for SleepMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.value.get() }
    }
}

impl<'a, T> DerefMut for SleepMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.value.get() }
    }
}
