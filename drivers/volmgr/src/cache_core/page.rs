use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernel_sync::locks::AsyncRwLock;
use spin::Mutex;

pub(super) struct DirtyState {
    pub(super) owners: [(u64, u64); 2],
    pub(super) extra_owners: Vec<(u64, u64)>,
    pub(super) since: [u64; 64],
}

impl DirtyState {
    pub(super) fn owner(&mut self, owner: u64) -> Result<&mut u64, ()> {
        if let Some(index) = self.owners.iter().position(|&(id, _)| id == owner) {
            return Ok(&mut self.owners[index].1);
        }
        if let Some(index) = self.extra_owners.iter().position(|&(id, _)| id == owner) {
            return Ok(&mut self.extra_owners[index].1);
        }
        if let Some(index) = self.owners.iter().position(|&(_, bits)| bits == 0) {
            self.owners[index] = (owner, 0);
            return Ok(&mut self.owners[index].1);
        }
        self.extra_owners.try_reserve(1).map_err(|_| ())?;
        self.extra_owners.push((owner, 0));
        Ok(&mut self.extra_owners.last_mut().unwrap().1)
    }
}

pub(crate) struct CachePage {
    pub(super) slot: usize,
    pub(super) prefetched: AtomicBool,
    pub(super) valid_mask: AtomicU64,
    pub(super) dirty_mask: AtomicU64,
    pub(super) writeback_mask: AtomicU64,
    pub(super) generation: AtomicU64,
    pub(super) dirty_lock: Mutex<DirtyState>,
    pub(super) data_lock: AsyncRwLock<()>,
}

impl CachePage {
    pub(super) fn new(slot: usize) -> Self {
        Self {
            slot,
            prefetched: AtomicBool::new(false),
            valid_mask: AtomicU64::new(0),
            dirty_mask: AtomicU64::new(0),
            writeback_mask: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            dirty_lock: Mutex::new(DirtyState {
                owners: [(0, 0); 2],
                extra_owners: Vec::new(),
                since: [0; 64],
            }),
            data_lock: AsyncRwLock::new(()),
        }
    }

    pub(super) fn reset_for_lba(&self, _lba: u64) {
        self.prefetched.store(false, Ordering::Relaxed);
        self.valid_mask.store(0, Ordering::Release);
        self.dirty_mask.store(0, Ordering::Release);
        self.writeback_mask.store(0, Ordering::Release);
        self.generation.store(0, Ordering::Release);
        let mut dirty = self.dirty_lock.lock();
        dirty.owners = [(0, 0); 2];
        dirty.extra_owners.clear();
        dirty.since.fill(0);
    }

    pub(super) fn is_evictable(&self) -> bool {
        self.dirty_mask.load(Ordering::Acquire) == 0
            && self.writeback_mask.load(Ordering::Acquire) == 0
    }
}
