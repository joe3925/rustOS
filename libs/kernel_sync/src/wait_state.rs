use crate::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct WaitState {
    value: AtomicU64,
    none: u64,
}

impl WaitState {
    pub const fn new(none: u64) -> Self {
        Self {
            value: AtomicU64::new(none),
            none,
        }
    }

    pub fn mark(&self, wait_queue_id: u64) -> bool {
        self.value
            .compare_exchange(
                self.none,
                wait_queue_id,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn clear(&self, wait_queue_id: u64) -> bool {
        self.value
            .compare_exchange(
                wait_queue_id,
                self.none,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn is_marked(&self, wait_queue_id: u64) -> bool {
        self.value.load(Ordering::Acquire) == wait_queue_id
    }
}
