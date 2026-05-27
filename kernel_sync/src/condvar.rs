use crate::platform::{ParkReason, Platform};
use crate::sleep_mutex::SleepMutexGuard;
use crate::wait_queue::WaitQueue;

pub struct Condvar<P: Platform> {
    waiters: WaitQueue<P>,
}

impl<P: Platform> Condvar<P> {
    pub fn new() -> Self {
        Self {
            waiters: WaitQueue::new(),
        }
    }

    pub fn wait<'a, T>(&self, guard: SleepMutexGuard<'a, P, T>) -> SleepMutexGuard<'a, P, T> {
        let mutex = guard.mutex();
        let enqueued = self.waiters.enqueue_current();

        drop(guard);

        if enqueued {
            P::park_current(ParkReason::CondvarWait);
        }

        let _ = self.waiters.clear_current_if_queued();
        mutex.lock()
    }

    pub fn notify_one(&self) {
        if let Some(task) = self.waiters.dequeue_one() {
            P::unpark(&task);
        }
    }

    pub fn notify_all(&self) {
        let tasks = self.waiters.dequeue_all();
        for task in tasks {
            P::unpark(&task);
        }
    }

    pub fn waiters_count(&self) -> usize {
        self.waiters.len()
    }
}

impl<P: Platform> Default for Condvar<P> {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<P: Platform> Send for Condvar<P> {}
unsafe impl<P: Platform> Sync for Condvar<P> {}
