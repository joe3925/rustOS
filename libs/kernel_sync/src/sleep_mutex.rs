use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::platform::Platform;
use crate::wait_queue::WaitQueue;

pub struct SleepMutex<P: Platform, T> {
    locked: AtomicUsize,
    waiters: WaitQueue<P>,
    value: UnsafeCell<T>,
}

unsafe impl<P: Platform, T: Send> Send for SleepMutex<P, T> {}
unsafe impl<P: Platform, T: Send> Sync for SleepMutex<P, T> {}

impl<P: Platform, T> SleepMutex<P, T> {
    pub fn new(value: T) -> Self {
        Self {
            locked: AtomicUsize::new(0),
            waiters: WaitQueue::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub fn try_lock(&self) -> Option<SleepMutexGuard<'_, P, T>> {
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

    pub fn lock(&self) -> SleepMutexGuard<'_, P, T> {
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

            P::park_current();
        }
    }

    fn unlock(&self) {
        self.locked.store(0, Ordering::Release);

        if let Some(task) = self.waiters.dequeue_one() {
            P::unpark(&task);
        }
    }
}

pub struct SleepMutexGuard<'a, P: Platform, T> {
    mutex: &'a SleepMutex<P, T>,
}

impl<'a, P: Platform, T> SleepMutexGuard<'a, P, T> {
    #[inline]
    pub fn mutex(&self) -> &'a SleepMutex<P, T> {
        self.mutex
    }
}

unsafe impl<'a, P: Platform, T: Send> Send for SleepMutexGuard<'a, P, T> {}

impl<'a, P: Platform, T> Drop for SleepMutexGuard<'a, P, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

impl<'a, P: Platform, T> Deref for SleepMutexGuard<'a, P, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.value.get() }
    }
}

impl<'a, P: Platform, T> DerefMut for SleepMutexGuard<'a, P, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.value.get() }
    }
}
