use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

pub(crate) struct CachePage {
    pub(super) slot: usize,
    pub(super) valid_mask: AtomicU64,
    pub(super) dirty_mask: AtomicU64,
    pub(super) writeback_mask: AtomicU64,
    pub(super) owner: AtomicU64,
    pub(super) generation: AtomicU64,
    pub(super) wb_generation: AtomicU64,
    pub(super) data_lock: RwLock<()>,
}

impl CachePage {
    pub(super) fn new(slot: usize) -> Self {
        Self {
            slot,
            valid_mask: AtomicU64::new(0),
            dirty_mask: AtomicU64::new(0),
            writeback_mask: AtomicU64::new(0),
            owner: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            wb_generation: AtomicU64::new(0),
            data_lock: RwLock::new(()),
        }
    }

    pub(super) fn reset_for_lba(&self, _lba: u64) {
        self.valid_mask.store(0, Ordering::Release);
        self.dirty_mask.store(0, Ordering::Release);
        self.writeback_mask.store(0, Ordering::Release);
        self.owner.store(0, Ordering::Release);
        self.generation.store(0, Ordering::Release);
        self.wb_generation.store(0, Ordering::Release);
    }

    pub(super) fn is_evictable(&self) -> bool {
        self.dirty_mask.load(Ordering::Acquire) == 0
            && self.writeback_mask.load(Ordering::Acquire) == 0
    }
}
