use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;
use spin::Mutex;

pub(super) struct WritebackNotifier {
    epoch: AtomicU64,
    waiters: Mutex<Vec<Waker>>,
}

impl WritebackNotifier {
    pub(super) fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            waiters: Mutex::new(Vec::new()),
        }
    }

    #[inline]
    pub(super) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub(super) fn register_if_unchanged(&self, observed_epoch: u64, waker: &Waker) -> bool {
        let mut waiters = self.waiters.lock();

        if self.epoch.load(Ordering::Acquire) != observed_epoch {
            return false;
        }

        if waiters.iter().all(|existing| !existing.will_wake(waker)) {
            waiters.push(waker.clone());
        }

        true
    }

    pub(super) fn notify_all(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);

        let waiters = {
            let mut waiters = self.waiters.lock();
            core::mem::take(&mut *waiters)
        };

        for waker in waiters {
            waker.wake();
        }
    }
}
