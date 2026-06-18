use crate::alloc::vec::Vec;
use alloc::sync::Arc;
use core::ops::Range;
use core::sync::atomic::Ordering;
use futures::future::Shared;
use kernel_api::async_ffi::FfiFuture;
use kernel_api::dma::dma_base_page_size;
use kernel_api::kernel_types::dma::IOBUFFER_MAX_FRAME_CAPACITY;
use spin::Mutex;

use super::page::Page;
use crate::cache_traits::CacheError;

pub(super) enum FlushFilter<'a> {
    /// Flush all dirty pages.
    All,
    /// Flush dirty pages within a block range.
    BlockRange(&'a Range<u64>),
    /// Flush dirty pages belonging to the given owner.
    Owner(u64),
}

impl FlushFilter<'_> {
    #[inline]
    pub(super) fn matches<const BLOCK_SIZE: usize>(
        &self,
        lba: u64,
        page: &Page<BLOCK_SIZE>,
    ) -> bool {
        match self {
            FlushFilter::All => true,
            FlushFilter::BlockRange(r) => lba >= r.start && lba < r.end,
            FlushFilter::Owner(owner) => {
                let page_owner = page.owner.load(Ordering::Acquire);
                page_owner == *owner
            }
        }
    }
}

pub(super) struct FlushScratch<const BLOCK_SIZE: usize> {
    pub(super) keys: Vec<u64>,
    pub(super) run: Vec<PreparedFlushPage<BLOCK_SIZE>>,
}

impl<const BLOCK_SIZE: usize> FlushScratch<BLOCK_SIZE> {
    pub(super) fn new(run_hint: usize, cache_capacity_blocks: usize) -> Self {
        let run_hint = run_hint.max(1);
        let frames_per_block = BLOCK_SIZE.div_ceil(dma_base_page_size());
        let scratch_key_capacity = cache_capacity_blocks.max(run_hint);
        let run_capacity = if BLOCK_SIZE.is_multiple_of(dma_base_page_size()) {
            (IOBUFFER_MAX_FRAME_CAPACITY / frames_per_block.max(1))
                .max(1)
                .min(cache_capacity_blocks.saturating_sub(1).max(1))
        } else {
            1
        };

        Self {
            keys: Vec::with_capacity(scratch_key_capacity),
            run: Vec::with_capacity(run_capacity),
        }
    }

    pub(super) fn reset(&mut self) {
        self.keys.clear();
        self.run.clear();
    }
}

pub(super) struct FlushRunScratchLease<'a, const BLOCK_SIZE: usize> {
    scratch: &'a Mutex<FlushScratch<BLOCK_SIZE>>,
    run: Option<Vec<PreparedFlushPage<BLOCK_SIZE>>>,
}

impl<'a, const BLOCK_SIZE: usize> FlushRunScratchLease<'a, BLOCK_SIZE> {
    pub(super) fn new(scratch: &'a Mutex<FlushScratch<BLOCK_SIZE>>) -> Self {
        let run = {
            let mut scratch = scratch.lock();
            core::mem::take(&mut scratch.run)
        };

        Self {
            scratch,
            run: Some(run),
        }
    }

    pub(super) fn run_mut(&mut self) -> &mut Vec<PreparedFlushPage<BLOCK_SIZE>> {
        self.run
            .as_mut()
            .expect("flush run scratch lease used after drop")
    }
}

impl<const BLOCK_SIZE: usize> Drop for FlushRunScratchLease<'_, BLOCK_SIZE> {
    fn drop(&mut self) {
        let Some(mut run) = self.run.take() else {
            return;
        };

        run.clear();

        let mut scratch = self.scratch.lock();
        if scratch.run.capacity() < run.capacity() {
            scratch.run = run;
        }
    }
}
pub(super) struct PreparedFlushPage<const BLOCK_SIZE: usize> {
    pub(super) lba: u64,
    pub(super) page: Arc<Page<BLOCK_SIZE>>,
    pub(super) wb_generation: u64,
}

pub(crate) struct FlushJobHandle<E> {
    pub(super) id: u64,
    pub(super) future: Shared<FfiFuture<()>>,
    pub(super) result: Arc<Mutex<Option<Result<(), CacheError<E>>>>>,
}

// pooled page vectors removed; streaming batching used instead.
