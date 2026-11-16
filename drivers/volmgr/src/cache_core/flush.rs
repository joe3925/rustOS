use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use kernel_api::request::Write;
use spin::Mutex;

use super::page::CachePage;

pub(super) const MAX_WRITE_CHAIN: usize = 64;

#[derive(Clone, Copy)]
pub(super) enum FlushFilter {
    All,
    Owner(u64),
}

impl FlushFilter {
    pub(super) fn matches(&self, _lba: u64, page: &CachePage) -> bool {
        self.mask(page) != 0
    }

    pub(super) fn mask(&self, page: &CachePage) -> u64 {
        match self {
            FlushFilter::All => page.dirty_mask.load(Ordering::Acquire),
            FlushFilter::Owner(owner) => {
                let dirty = page.dirty_lock.lock();
                dirty
                    .owners
                    .iter()
                    .chain(dirty.extra_owners.iter())
                    .filter(|(id, _)| id == owner)
                    .fold(0, |mask, (_, bits)| mask | bits)
            }
        }
    }
}

pub(super) struct PreparedFlushExtent {
    pub(super) lba: u64,
    pub(super) slot: usize,
    pub(super) page: Arc<CachePage>,
    pub(super) granule_start: usize,
    pub(super) granule_count: usize,
    pub(super) bits: u64,
}

pub(super) struct PreparedRun {
    pub(super) start: usize,
    pub(super) end: usize,
}

pub(super) struct FlushScratch {
    pub(super) targets: Vec<(Arc<CachePage>, u64, u64)>,
    pub(super) keys: Vec<u64>,
    pub(super) prepared: Vec<PreparedFlushExtent>,
    pub(super) runs: Vec<PreparedRun>,
    pub(super) extents: Vec<PreparedRun>,
    pub(super) writes: Option<Box<[Option<Write<'static>>; MAX_WRITE_CHAIN]>>,
}

impl FlushScratch {
    pub(super) fn new(capacity_blocks: usize, prepared_capacity: usize) -> Result<Self, ()> {
        let mut targets = Vec::new();
        targets.try_reserve_exact(capacity_blocks).map_err(|_| ())?;
        let mut keys = Vec::new();
        let mut prepared = Vec::new();
        let mut runs = Vec::new();
        let mut extents = Vec::new();

        keys.try_reserve_exact(capacity_blocks).map_err(|_| ())?;
        prepared
            .try_reserve_exact(prepared_capacity.max(1))
            .map_err(|_| ())?;
        runs.try_reserve_exact(prepared_capacity.max(1))
            .map_err(|_| ())?;
        extents
            .try_reserve_exact(prepared_capacity.max(1))
            .map_err(|_| ())?;

        Ok(Self {
            targets,
            keys,
            prepared,
            runs,
            extents,
            writes: Some(Box::new(core::array::from_fn(|_| None))),
        })
    }
}

pub(super) struct FlushSnapshotLease<'a> {
    pub(super) scratch: &'a Mutex<FlushScratch>,
    pub(super) targets: Vec<(Arc<CachePage>, u64, u64)>,
    pub(super) notifier: &'a super::notify::WritebackNotifier,
}

impl Drop for FlushSnapshotLease<'_> {
    fn drop(&mut self) {
        self.targets.clear();
        let mut scratch = self.scratch.lock();
        if scratch.targets.capacity() < self.targets.capacity() {
            scratch.targets = core::mem::take(&mut self.targets);
        }
        drop(scratch);
        self.notifier.notify_all();
    }
}

pub(super) struct FlushRunScratchLease<'a> {
    pub(super) scratch: &'a Mutex<FlushScratch>,
    pub(super) writes: Option<Box<[Option<Write<'static>>; MAX_WRITE_CHAIN]>>,
}

impl<'a> FlushRunScratchLease<'a> {
    pub(super) fn new(scratch: &'a Mutex<FlushScratch>) -> Self {
        let writes = {
            let mut scratch = scratch.lock();
            scratch
                .writes
                .take()
                .unwrap_or_else(|| Box::new(core::array::from_fn(|_| None)))
        };

        Self {
            scratch,
            writes: Some(writes),
        }
    }
}

impl Drop for FlushRunScratchLease<'_> {
    fn drop(&mut self) {
        let writes = self.writes.take();

        let mut scratch = self.scratch.lock();
        if writes.is_some() && scratch.writes.is_none() {
            scratch.writes = writes;
        }
    }
}
