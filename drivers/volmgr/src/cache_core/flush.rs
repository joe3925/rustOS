use crate::alloc::vec::Vec;
use crate::cache_core::core::FlushScratch;

use crate::cache_core::core::MAX_WRITE_CHAIN;
use crate::cache_core::core::PreparedRun;
use alloc::sync::Arc;
use core::ops::Range;
use core::sync::atomic::Ordering;
use futures::future::Shared;
use kernel_api::async_ffi::FfiFuture;
use kernel_api::dma::dma_base_page_size;
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

pub(super) struct FlushRunScratchLease<'a, const BLOCK_SIZE: usize> {
    pub(super) scratch: &'a Mutex<FlushScratch>,
    pub(super) run: Option<Vec<PreparedRun>>,
    pub(super) writes:
        Option<alloc::boxed::Box<[Option<kernel_api::request::Write<'static>>; MAX_WRITE_CHAIN]>>,
}

impl<'a, const BLOCK_SIZE: usize> FlushRunScratchLease<'a, BLOCK_SIZE> {
    pub(super) fn new(scratch: &'a Mutex<FlushScratch>) -> Self {
        let (run, writes) = {
            let mut scratch = scratch.lock();
            (
                core::mem::take(&mut scratch.runs),
                scratch
                    .writes
                    .take()
                    .unwrap_or_else(|| alloc::boxed::Box::new(core::array::from_fn(|_| None))),
            )
        };

        Self {
            scratch,
            run: Some(run),
            writes: Some(writes),
        }
    }

    pub(super) fn run_mut(&mut self) -> &mut Vec<PreparedRun> {
        self.run
            .as_mut()
            .expect("flush run scratch lease used after drop")
    }
}

impl<const BLOCK_SIZE: usize> Drop for FlushRunScratchLease<'_, BLOCK_SIZE> {
    fn drop(&mut self) {
        let writes = self.writes.take();
        let Some(mut run) = self.run.take() else {
            return;
        };

        run.clear();

        let mut scratch = self.scratch.lock();
        if scratch.runs.capacity() < run.capacity() {
            scratch.runs = run;
        }
        if writes.is_some() && scratch.writes.is_none() {
            scratch.writes = writes;
        }
    }
}

pub(crate) struct FlushJobHandle<E> {
    pub(super) id: u64,
    pub(super) future: Shared<FfiFuture<()>>,
    pub(super) result: Arc<Mutex<Option<Result<(), CacheError<E>>>>>,
}
