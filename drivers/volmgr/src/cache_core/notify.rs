use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;
use spin::Mutex;

pub(super) struct WritebackNotifier {
    epoch: AtomicU64,
    waiters: Mutex<Vec<Option<WritebackWaiter>>>,
}

struct WritebackWaiter {
    observed_epoch: u64,
    waker: Waker,
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

        let mut free_slot = None;

        for index in 0..waiters.len() {
            match &mut waiters[index] {
                Some(existing) => {
                    if existing.waker.will_wake(waker) {
                        existing.observed_epoch = observed_epoch;
                        existing.waker.clone_from(waker);
                        return true;
                    }
                }
                None => {
                    if free_slot.is_none() {
                        free_slot = Some(index);
                    }
                }
            }
        }

        let waiter = WritebackWaiter {
            observed_epoch,
            waker: waker.clone(),
        };

        if let Some(index) = free_slot {
            waiters[index] = Some(waiter);
        } else {
            waiters.push(Some(waiter));
        }

        true
    }

    pub(super) fn notify_all(&self) {
        let notified_epoch = self.epoch.fetch_add(1, Ordering::AcqRel);
        let mut cursor = 0;

        loop {
            let waker = {
                let mut waiters = self.waiters.lock();
                let mut found = None;

                while cursor < waiters.len() {
                    let should_wake = match &waiters[cursor] {
                        Some(waiter) => waiter.observed_epoch <= notified_epoch,
                        None => false,
                    };

                    if should_wake {
                        found = Some(cursor);
                        break;
                    }

                    cursor += 1;
                }

                match found {
                    Some(index) => {
                        cursor = index + 1;
                        waiters[index].take().map(|waiter| waiter.waker)
                    }
                    None => None,
                }
            };

            match waker {
                Some(waker) => waker.wake(),
                None => break,
            }
        }
    }
}
