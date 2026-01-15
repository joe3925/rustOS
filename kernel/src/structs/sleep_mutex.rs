use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::BlockReason;
use crate::structs::wait_queue::WaitQueue;

/// A sleepable mutex that blocks tasks via the scheduler instead of spinning.
///
/// # Correctness guarantees
///
/// This implementation avoids the following common bugs:
///
/// 1. **No stale waiter entries**: Uses intrusive `WaitQueue` where each task can
///    only be in one queue at a time (enforced by CAS on `wait_next`).
///
/// 2. **No lost wakeups**: Uses check-under-lock pattern - the lock state is
///    re-checked while holding the wait queue lock before deciding to sleep.
///
/// 3. **No thundering herd**: Only one waiter is woken per unlock.
///
/// # Usage
///
/// ```ignore
/// let mutex = SleepMutex::new(data);
/// let guard = mutex.lock();
/// // ... use guard ...
/// // guard dropped here, automatically unlocks
/// ```
pub struct SleepMutex<T> {
    /// 0 = unlocked, 1 = locked
    locked: AtomicUsize,
    /// Wait queue for blocked tasks
    waiters: WaitQueue,
    /// The protected value
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
    /// This method uses a check-under-lock pattern to avoid race conditions:
    /// 1. Try to acquire (fast path)
    /// 2. If failed, re-check lock state under wait queue lock
    /// 3. Only enqueue and sleep if still locked
    pub fn lock(&self) -> SleepMutexGuard<'_, T> {
        loop {
            // Fast path: try to acquire without touching wait queue
            if let Some(guard) = self.try_lock() {
                return guard;
            }

            // Slow path: need to wait
            // The WaitQueue::enqueue_current() will fail if we're already queued
            // (prevents duplicate entries)
            let enqueued = self.waiters.enqueue_current();

            if !enqueued {
                // Already queued somewhere (shouldn't happen in normal use, but handle it)
                // Clear our wait_next if it was from a previous incomplete wait
                self.waiters.clear_current_if_queued();
                // Try again
                continue;
            }

            // CRITICAL: Re-check lock state AFTER enqueueing
            // This prevents the race where:
            // 1. We check lock (locked)
            // 2. Another task unlocks and wakes nobody (we weren't queued yet)
            // 3. We enqueue and sleep forever
            //
            // By checking after enqueue, if the lock became free, we can
            // try to acquire it. The unlock() will have already checked
            // the wait queue (finding it empty at that moment), so we
            // won't get a spurious wakeup.
            if let Some(guard) = self.try_lock() {
                // Lock is now free! We acquired it.
                // But we're still in the wait queue - we need to handle this.
                // The next unlock by us will wake someone from the queue,
                // which might be a stale entry (us) or a real waiter.
                //
                // Since we're using intrusive queues with CAS-based enqueue,
                // we're now in the queue with wait_next set. The safest approach
                // is to NOT clear ourselves (we'd need to scan the list), but
                // instead let the unlock logic skip us if we're not blocked.
                //
                // Actually, we should clear our wait_next since we succeeded.
                // But we're in the middle of the list potentially...
            //
            // The correct fix: we must NOT be in the queue if we acquired.
            // Since we can't easily remove ourselves from the middle,
            // we accept that dequeue_one() may pop us and that's okay -
            // unpark on a running task just sets a permit.
            //
            // However, leaving ourselves marked as queued can hand out a
            // stray wake permit later (when unlock pops the stale entry),
            // which in turn can make a future condvar wait skip blocking
            // while still thinking we're queued. Clear our marker now to
            // avoid that stale permit/queue entry.
            let _ = self.waiters.clear_current_if_queued();
            return guard;
        }

            // Lock is still held, park until woken
            SCHEDULER.park_current(BlockReason::MutexLock);

            // After waking, we've been dequeued by unlock().
            // Loop back to try acquiring again.
        }
    }

    /// Release the mutex and wake one waiting task.
    fn unlock(&self) {
        // Release the lock first
        self.locked.store(0, Ordering::Release);

        // Wake one waiter if any
        // dequeue_one() clears the task's wait_next, so it won't be
        // considered "queued" anymore
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
