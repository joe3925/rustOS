use crate::cache::{CacheIndex, CacheIndexFactory, DefaultIndexFactory};
use crate::cache_core::flush::{
    FlushFilter, FlushRunScratchLease, FlushScratch, MAX_WRITE_CHAIN, PreparedFlushExtent,
    PreparedRun,
};
use crate::cache_core::page::CachePage;
use crate::cache_traits::{CacheConfig, CacheError, VolumeCacheBackend, VolumeCacheOps};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::min;
use core::future::Future;
use core::hint::{cold_path, likely, unlikely};
use core::marker::PhantomData;
use core::ops::Range;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use kernel_api::kernel_types::dma::{
    FromDevice, IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc, ToDevice,
};
use kernel_api::memory::{
    PageTableFlags, VirtAddr, allocate_auto_kernel_range_mapped_contiguous,
    deallocate_kernel_range, unmap_range,
};
use kernel_api::println;
use kernel_api::request::Read;
use kernel_api::request::Write;
use kernel_api::runtime::spawn_detached;
use spin::Mutex;

use super::notify::WritebackNotifier;

const FLUSH_WRITE_CHAIN: usize = MAX_WRITE_CHAIN;
const CACHE_GRANULE: usize = 1024;

struct FlushActiveGuard<'a> {
    active: &'a AtomicBool,
    notifier: &'a WritebackNotifier,
}

impl Drop for FlushActiveGuard<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.notifier.notify_all();
    }
}

struct Shard<I> {
    index: I,
    target_capacity: usize,
}

impl<I> Shard<I> {
    fn new(index: I, target_capacity: usize) -> Self {
        Self {
            index,
            target_capacity,
        }
    }
}

enum WriteAcquire {
    Cached(Arc<CachePage>),
    Direct,
}

enum WritebackWaitResult {
    Clean,
    NeedsFlush,
}

enum FilteredWritebackState {
    Clean,
    NeedsFlush,
    ActiveWriteback,
}

struct WritebackProgressWait<'cache, 'filter, B, const BLOCK_SIZE: usize, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    cache: &'cache VolumeCache<B, BLOCK_SIZE, F>,
    filter: &'filter FlushFilter,
}

impl<'cache, 'filter, B, const BLOCK_SIZE: usize, F> Future
    for WritebackProgressWait<'cache, 'filter, B, BLOCK_SIZE, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    type Output = WritebackWaitResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let observed_epoch = this.cache.writeback_notifier.epoch();

            match this.cache.filtered_writeback_state(this.filter) {
                FilteredWritebackState::Clean => return Poll::Ready(WritebackWaitResult::Clean),
                FilteredWritebackState::NeedsFlush => {
                    return Poll::Ready(WritebackWaitResult::NeedsFlush);
                }
                FilteredWritebackState::ActiveWriteback => {
                    if this
                        .cache
                        .writeback_notifier
                        .register_if_unchanged(observed_epoch, cx.waker())
                    {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}
struct FlushSlotWait<'cache, B, const BLOCK_SIZE: usize, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    cache: &'cache VolumeCache<B, BLOCK_SIZE, F>,
}

impl<'cache, B, const BLOCK_SIZE: usize, F> Future for FlushSlotWait<'cache, B, BLOCK_SIZE, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let cache = self.cache;

        loop {
            if cache
                .flush_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Poll::Ready(());
            }

            let observed_epoch = cache.writeback_notifier.epoch();

            if cache
                .flush_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Poll::Ready(());
            }

            if cache
                .writeback_notifier
                .register_if_unchanged(observed_epoch, cx.waker())
            {
                return Poll::Pending;
            }
        }
    }
}
pub(crate) struct VolumeCache<B, const BLOCK_SIZE: usize, F = DefaultIndexFactory>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    backend: Arc<B>,
    shards: Vec<Mutex<Shard<F::Index>>>,
    free_pages: Mutex<Vec<Arc<CachePage>>>,
    direct_page: Mutex<Option<Arc<CachePage>>>,
    flush_scratch: Mutex<FlushScratch>,
    cache_base: VirtAddr,
    cache_bytes: usize,
    cache_backing: Option<IoBufferBacking<'static>>,
    cfg: CacheConfig,
    dirty_pages: Arc<AtomicUsize>,
    writeback_notifier: WritebackNotifier,
    background_writeback_active: AtomicBool,
    flush_active: AtomicBool,
    closed: AtomicBool,
    _index_factory: PhantomData<F>,
}

impl<B, const BLOCK_SIZE: usize> VolumeCache<B, BLOCK_SIZE, DefaultIndexFactory>
where
    B: VolumeCacheBackend,
{
    pub async fn new(backend: Arc<B>, cfg: CacheConfig) -> Result<Self, CacheError<B::Error>> {
        Self::new_with_index(backend, cfg, DefaultIndexFactory).await
    }
}

impl<B, const BLOCK_SIZE: usize, F> VolumeCache<B, BLOCK_SIZE, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    pub async fn new_with_index(
        backend: Arc<B>,
        mut cfg: CacheConfig,
        factory: F,
    ) -> Result<Self, CacheError<B::Error>> {
        if unlikely(
            BLOCK_SIZE == 0
                || cfg.capacity_blocks == 0
                || BLOCK_SIZE % CACHE_GRANULE != 0
                || BLOCK_SIZE / CACHE_GRANULE > 64,
        ) {
            cold_path();
            return Err(CacheError::InvalidConfig);
        }

        if unlikely(cfg.shards == 0) {
            cold_path();
            cfg.shards = 1;
        }

        if unlikely(cfg.flush_parallelism == 0) {
            cold_path();
            cfg.flush_parallelism = 1;
        }

        if cfg.dirty_high_watermark_blocks == 0
            || cfg.dirty_high_watermark_blocks > cfg.capacity_blocks
        {
            cfg.dirty_high_watermark_blocks = cfg.capacity_blocks;
        }

        if cfg.dirty_low_watermark_blocks > cfg.dirty_high_watermark_blocks {
            cfg.dirty_low_watermark_blocks = cfg.dirty_high_watermark_blocks;
        }

        let backing_blocks = cfg
            .capacity_blocks
            .checked_add(1)
            .ok_or(CacheError::InvalidConfig)?;

        let cache_bytes = backing_blocks
            .checked_mul(BLOCK_SIZE)
            .ok_or(CacheError::InvalidConfig)?;

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let cache_base = allocate_auto_kernel_range_mapped_contiguous(cache_bytes as u64, flags)
            .map_err(|_| CacheError::InsufficientResources)?;

        unsafe {
            core::ptr::write_bytes(cache_base.as_u64() as *mut u8, 0, cache_bytes);
        }

        let cache_slice: &'static mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(cache_base.as_u64() as *mut u8, cache_bytes) };

        let mut backing_cfg = IoBufferBackingConfig::worst_case_for_len(cache_bytes);
        backing_cfg.lease_capacity = backing_cfg.lease_capacity.max(backing_blocks);
        backing_cfg.dma_record_capacity = backing_cfg.dma_record_capacity.max(backing_blocks);

        let mut cache_backing =
            match IoBufferBacking::new(IoBufferBackingDesc::SliceMut(cache_slice), backing_cfg) {
                Ok(backing) => backing,
                Err(e) => {
                    unsafe {
                        unmap_range(cache_base, cache_bytes as u64);
                    }

                    unsafe { deallocate_kernel_range(cache_base, cache_bytes as u64) };
                    return Err(CacheError::InvalidIoBuffer(e));
                }
            };

        if cfg.dma_map_entire_cache {
            if let Err(e) = backend.dma_map_cache(&mut cache_backing).await {
                drop(cache_backing);

                unsafe {
                    unmap_range(cache_base, cache_bytes as u64);
                }

                unsafe { deallocate_kernel_range(cache_base, cache_bytes as u64) };
                return Err(CacheError::Backend(e));
            }
        }

        let shard_count = cfg.shards;
        let per_shard = (cfg.capacity_blocks + shard_count - 1) / shard_count;
        let index_reserve = cfg.capacity_blocks;

        let mut shards = Vec::new();
        if shards.try_reserve_exact(shard_count).is_err() {
            drop(cache_backing);

            unsafe {
                unmap_range(cache_base, cache_bytes as u64);
            }

            unsafe { deallocate_kernel_range(cache_base, cache_bytes as u64) };
            return Err(CacheError::InsufficientResources);
        }

        let mut i = 0usize;
        while i < shard_count {
            let mut index = factory.build(index_reserve);
            index.reserve_or_panic(index_reserve);
            shards.push(Mutex::new(Shard::new(index, per_shard)));
            i += 1;
        }

        let mut free_pages = Vec::new();
        if free_pages.try_reserve_exact(cfg.capacity_blocks).is_err() {
            drop(shards);
            drop(cache_backing);

            unsafe {
                unmap_range(cache_base, cache_bytes as u64);
            }

            unsafe { deallocate_kernel_range(cache_base, cache_bytes as u64) };
            return Err(CacheError::InsufficientResources);
        }

        let mut slot = cfg.capacity_blocks;
        while slot != 0 {
            slot -= 1;
            free_pages.push(Arc::new(CachePage::new(slot)));
        }

        let direct_page = Arc::new(CachePage::new(cfg.capacity_blocks));

        let flush_scratch = match FlushScratch::new(cfg.capacity_blocks, FLUSH_WRITE_CHAIN) {
            Ok(scratch) => scratch,
            Err(_) => {
                drop(direct_page);
                drop(free_pages);
                drop(shards);
                drop(cache_backing);

                unsafe {
                    unmap_range(cache_base, cache_bytes as u64);
                }

                unsafe { deallocate_kernel_range(cache_base, cache_bytes as u64) };
                return Err(CacheError::InsufficientResources);
            }
        };

        Ok(Self {
            backend,
            shards,
            free_pages: Mutex::new(free_pages),
            direct_page: Mutex::new(Some(direct_page)),
            flush_scratch: Mutex::new(flush_scratch),
            cache_base,
            cache_bytes,
            cache_backing: Some(cache_backing),
            cfg,
            dirty_pages: Arc::new(AtomicUsize::new(0)),
            writeback_notifier: WritebackNotifier::new(),
            background_writeback_active: AtomicBool::new(false),
            flush_active: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            _index_factory: PhantomData,
        })
    }

    #[inline]
    fn block_size_u64() -> u64 {
        BLOCK_SIZE as u64
    }

    #[inline]
    fn page_offset(slot: usize) -> usize {
        slot * BLOCK_SIZE
    }

    #[inline]
    fn granules_per_block() -> usize {
        BLOCK_SIZE / CACHE_GRANULE
    }

    #[inline]
    fn full_granule_mask() -> u64 {
        let granules = Self::granules_per_block();
        if granules == 64 {
            u64::MAX
        } else {
            (1u64 << granules) - 1
        }
    }

    #[inline]
    fn granule_mask(granule_start: usize, granule_count: usize) -> u64 {
        if granule_count == 64 {
            u64::MAX
        } else {
            ((1u64 << granule_count) - 1) << granule_start
        }
    }

    #[inline]
    fn granule_mask_for_range(block_off: usize, len: usize) -> Result<u64, CacheError<B::Error>> {
        if unlikely(len == 0) {
            cold_path();
            return Ok(0);
        }

        let end = block_off
            .checked_add(len)
            .ok_or(CacheError::OffsetOverflow)?;
        let granule_start = block_off / CACHE_GRANULE;
        let granule_end = (end + CACHE_GRANULE - 1) / CACHE_GRANULE;
        let granule_count = granule_end
            .checked_sub(granule_start)
            .ok_or(CacheError::OffsetOverflow)?;

        Ok(Self::granule_mask(granule_start, granule_count))
    }

    #[inline]
    fn range_covers_whole_granules(block_off: usize, len: usize) -> bool {
        block_off % CACHE_GRANULE == 0 && len % CACHE_GRANULE == 0
    }

    #[inline]
    fn first_mask_run(mask: u64) -> Option<(usize, usize, u64)> {
        if mask == 0 {
            return None;
        }

        let start = mask.trailing_zeros() as usize;
        let shifted = mask >> start;
        let count = (!shifted).trailing_zeros() as usize;
        let bits = Self::granule_mask(start, count);
        Some((start, count, bits))
    }

    #[inline]
    fn cache_backing(&self) -> Result<&IoBufferBacking<'static>, CacheError<B::Error>> {
        self.cache_backing.as_ref().ok_or(CacheError::InvalidConfig)
    }

    #[inline]
    unsafe fn page_slice(&self, page: &CachePage) -> &[u8] {
        let ptr = (self.cache_base.as_u64() as usize + Self::page_offset(page.slot)) as *const u8;
        unsafe { core::slice::from_raw_parts(ptr, BLOCK_SIZE) }
    }

    #[inline]
    unsafe fn page_slice_mut(&self, page: &CachePage) -> &mut [u8] {
        let ptr = (self.cache_base.as_u64() as usize + Self::page_offset(page.slot)) as *mut u8;
        unsafe { core::slice::from_raw_parts_mut(ptr, BLOCK_SIZE) }
    }

    fn create_cache_from_device_buffer_at<'a>(
        &'a self,
        page: &CachePage,
        block_off: usize,
        len: usize,
    ) -> Result<IoBuffer<'a, 'a, FromDevice>, CacheError<B::Error>> {
        let start = Self::page_offset(page.slot)
            .checked_add(block_off)
            .ok_or(CacheError::OffsetOverflow)?;

        self.cache_backing()?
            .create_from_device(start, len)
            .map_err(|err| {
                cold_path();
                CacheError::InvalidIoBuffer(err)
            })
    }

    fn create_cache_from_device_buffer<'a>(
        &'a self,
        page: &CachePage,
        len: usize,
    ) -> Result<IoBuffer<'a, 'a, FromDevice>, CacheError<B::Error>> {
        self.create_cache_from_device_buffer_at(page, 0, len)
    }

    fn create_cache_to_device_buffer_at<'a>(
        &'a self,
        page: &CachePage,
        block_off: usize,
        len: usize,
    ) -> Result<IoBuffer<'a, 'a, ToDevice>, CacheError<B::Error>> {
        let start = Self::page_offset(page.slot)
            .checked_add(block_off)
            .ok_or(CacheError::OffsetOverflow)?;

        self.cache_backing()?
            .create_to_device(start, len)
            .map_err(|err| {
                cold_path();
                CacheError::InvalidIoBuffer(err)
            })
    }

    fn create_cache_to_device_buffer<'a>(
        &'a self,
        page: &CachePage,
        len: usize,
    ) -> Result<IoBuffer<'a, 'a, ToDevice>, CacheError<B::Error>> {
        self.create_cache_to_device_buffer_at(page, 0, len)
    }

    async fn write_buffer_to_backend<'buffer>(
        &self,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(buffer.is_empty()) {
            cold_path();
            return Ok(());
        }

        let len = buffer.len();

        let mut req = Write::new(offset, len, false, owner, Some(buffer));

        let status = self.backend.write_request(&mut req).await;
        drop(req);

        status.map_err(CacheError::Backend)?;
        Ok(())
    }

    fn take_to_device_buffer_range<'buffer>(
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        offset: usize,
        len: usize,
    ) -> Result<
        (
            IoBuffer<'buffer, 'buffer, ToDevice>,
            Option<IoBuffer<'buffer, 'buffer, ToDevice>>,
        ),
        CacheError<B::Error>,
    > {
        let end = offset.checked_add(len).ok_or(CacheError::OffsetOverflow)?;
        if unlikely(end > buffer.len()) {
            cold_path();
            return Err(CacheError::InvalidConfig);
        }

        let range_and_tail = if offset == 0 {
            buffer
        } else {
            match buffer.split_at(offset) {
                Ok((prefix, range_and_tail)) => {
                    drop(prefix);
                    range_and_tail
                }
                Err((_buffer, err)) => {
                    cold_path();
                    return Err(CacheError::InvalidIoBuffer(err));
                }
            }
        };

        if len == range_and_tail.len() {
            return Ok((range_and_tail, None));
        }

        match range_and_tail.split_at(len) {
            Ok((range, tail)) => Ok((range, Some(tail))),
            Err((_buffer, err)) => {
                cold_path();
                Err(CacheError::InvalidIoBuffer(err))
            }
        }
    }

    fn check_open(&self) -> Result<(), CacheError<B::Error>> {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return Err(CacheError::Closed);
        }
        Ok(())
    }

    async fn wait_for_flush_slot(&self) {
        FlushSlotWait { cache: self }.await
    }

    fn mark_cached_page_dirty_range(&self, page: &CachePage, owner: u64, bits: u64) {
        if unlikely(bits == 0) {
            cold_path();
            return;
        }

        page.owner.store(owner, Ordering::Release);
        page.valid_mask.fetch_or(bits, Ordering::AcqRel);
        page.generation.fetch_add(1, Ordering::AcqRel);

        if page.dirty_mask.fetch_or(bits, Ordering::AcqRel) == 0 {
            self.dirty_pages.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn clear_cached_page_dirty_range(&self, page: &CachePage, bits: u64) {
        if unlikely(bits == 0) {
            cold_path();
            return;
        }

        let mut old = page.dirty_mask.load(Ordering::Acquire);
        loop {
            let new = old & !bits;
            if new == old {
                return;
            }

            match page.dirty_mask.compare_exchange_weak(
                old,
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if old != 0 && new == 0 {
                        self.dirty_pages.fetch_sub(1, Ordering::AcqRel);
                    }
                    return;
                }
                Err(cur) => old = cur,
            }
        }
    }

    fn end_offset(offset: u64, len: usize) -> Result<u64, CacheError<B::Error>> {
        offset
            .checked_add(len as u64)
            .ok_or(CacheError::OffsetOverflow)
    }

    fn block_range_from_bytes(offset: u64, len: usize) -> Result<Range<u64>, CacheError<B::Error>> {
        let end = Self::end_offset(offset, len)?;
        let bs = Self::block_size_u64();
        let start_block = offset / bs;
        let end_block = if end == offset {
            start_block
        } else {
            ((end - 1) / bs) + 1
        };
        Ok(start_block..end_block)
    }

    fn shard_index(&self, lba: u64) -> usize {
        (lba as usize) % self.shards.len()
    }

    async fn try_get_page(&self, lba: u64) -> Option<Arc<CachePage>> {
        let idx = self.shard_index(lba);
        let mut shard = self.shards[idx].lock();
        shard.index.get(&lba).map(|page| Arc::clone(&*page))
    }

    fn page_can_be_reclaimed(page: &Arc<CachePage>) -> bool {
        page.is_evictable() && Arc::strong_count(page) == 1
    }

    fn page_can_be_flushed_for_reclaim(page: &Arc<CachePage>) -> bool {
        page.dirty_mask.load(Ordering::Acquire) != 0
            && page.writeback_mask.load(Ordering::Acquire) == 0
            && Arc::strong_count(page) == 1
    }

    fn recycle_or_drop_page(&self, page: Arc<CachePage>) {
        if Arc::strong_count(&page) == 1 {
            page.reset_for_lba(0);
            self.free_pages.lock().push(page);
        }
    }

    fn reclaim_page_from_shard_locked(
        &self,
        shard: &mut Shard<F::Index>,
    ) -> Option<Arc<CachePage>> {
        let reclaim_key = shard
            .index
            .oldest_matching(|_, page| Self::page_can_be_reclaimed(page));

        if let Some(lba) = reclaim_key {
            let Some(page) = shard.index.remove(&lba) else {
                return None;
            };
            page.reset_for_lba(0);
            return Some(page);
        }

        None
    }

    fn try_reclaim_cache_page(&self, preferred_idx: usize) -> Option<Arc<CachePage>> {
        {
            let mut shard = self.shards[preferred_idx].lock();
            if let Some(page) = self.reclaim_page_from_shard_locked(&mut shard) {
                return Some(page);
            }
        }

        let mut idx = 0usize;
        while idx < self.shards.len() {
            if idx != preferred_idx {
                let mut shard = self.shards[idx].lock();
                if let Some(page) = self.reclaim_page_from_shard_locked(&mut shard) {
                    return Some(page);
                }
            }
            idx += 1;
        }

        None
    }

    fn oldest_dirty_reclaim_candidate_in_shard(
        &self,
        shard_idx: usize,
    ) -> Option<(u64, Arc<CachePage>)> {
        let shard = self.shards[shard_idx].lock();
        let lba = shard
            .index
            .oldest_matching(|_, page| Self::page_can_be_flushed_for_reclaim(page))?;
        let page = shard.index.peek(&lba)?;
        Some((lba, Arc::clone(page)))
    }

    fn oldest_dirty_reclaim_candidate(
        &self,
        preferred_idx: usize,
    ) -> Option<(u64, Arc<CachePage>)> {
        if let Some(candidate) = self.oldest_dirty_reclaim_candidate_in_shard(preferred_idx) {
            return Some(candidate);
        }

        let mut idx = 0usize;
        while idx < self.shards.len() {
            if idx != preferred_idx {
                if let Some(candidate) = self.oldest_dirty_reclaim_candidate_in_shard(idx) {
                    return Some(candidate);
                }
            }
            idx += 1;
        }

        None
    }

    async fn flush_oldest_dirty_reclaim_candidate(
        &self,
        preferred_idx: usize,
    ) -> Result<bool, CacheError<B::Error>> {
        let Some((lba, page)) = self.oldest_dirty_reclaim_candidate(preferred_idx) else {
            return Ok(false);
        };

        let dirty = page.dirty_mask.load(Ordering::Acquire)
            & !page.writeback_mask.load(Ordering::Acquire)
            & Self::full_granule_mask();
        let Some((granule_start, granule_count, bits)) = Self::first_mask_run(dirty) else {
            return Ok(true);
        };

        let Some(prepared) =
            Self::prepare_flush_extent(lba, page, granule_start, granule_count, bits)
        else {
            return Ok(true);
        };

        let prepared = [prepared];
        let (mut runs, mut extents) = {
            let mut scratch = self.flush_scratch.lock();
            (
                core::mem::take(&mut scratch.runs),
                core::mem::take(&mut scratch.extents),
            )
        };
        runs.clear();
        extents.clear();

        let result = self
            .flush_prepared_pages_chained_with_runs(&prepared, &mut runs, &mut extents)
            .await;

        runs.clear();
        extents.clear();
        {
            let mut scratch = self.flush_scratch.lock();
            if scratch.runs.capacity() < runs.capacity() {
                scratch.runs = runs;
            }
            if scratch.extents.capacity() < extents.capacity() {
                scratch.extents = extents;
            }
        }

        result?;
        Ok(true)
    }

    fn trim_shard_locked(&self, shard: &mut Shard<F::Index>) {
        while shard.index.len() > shard.target_capacity {
            if let Some(page) = self.reclaim_page_from_shard_locked(shard) {
                self.recycle_or_drop_page(page);
            } else {
                break;
            }
        }
    }

    async fn acquire_cache_page(&self, lba: u64) -> Result<Arc<CachePage>, CacheError<B::Error>> {
        if let Some(page) = self.free_pages.lock().pop() {
            page.reset_for_lba(lba);
            return Ok(page);
        }

        let preferred_idx = self.shard_index(lba);
        if let Some(page) = self.try_reclaim_cache_page(preferred_idx) {
            page.reset_for_lba(lba);
            return Ok(page);
        }

        if self.cfg.direct_io_on_no_free_pages {
            cold_path();
            return Err(CacheError::NoFreePages);
        }

        let mut attempts = self.shards.len().saturating_mul(2).max(1);
        while attempts != 0 {
            if !self
                .flush_oldest_dirty_reclaim_candidate(preferred_idx)
                .await?
            {
                break;
            }

            if let Some(page) = self.try_reclaim_cache_page(preferred_idx) {
                page.reset_for_lba(lba);
                return Ok(page);
            }

            attempts -= 1;
        }

        Err(CacheError::NoFreePages)
    }

    async fn insert_page_or_get_existing(&self, lba: u64, page: Arc<CachePage>) -> Arc<CachePage> {
        let idx = self.shard_index(lba);
        let mut shard = self.shards[idx].lock();

        if let Some(existing) = shard.index.get(&lba) {
            cold_path();
            let existing = Arc::clone(&*existing);
            drop(shard);
            self.recycle_or_drop_page(page);
            return existing;
        }

        self.trim_shard_locked(&mut shard);

        let _ = shard.index.insert(lba, Arc::clone(&page));
        page
    }

    async fn read_extent_into_page(
        &self,
        lba: u64,
        page: &Arc<CachePage>,
        block_off: usize,
        len: usize,
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(len == 0) {
            cold_path();
            return Ok(());
        }

        let offset = lba
            .checked_mul(BLOCK_SIZE as u64)
            .and_then(|base| base.checked_add(block_off as u64))
            .ok_or(CacheError::OffsetOverflow)?;

        let bits = Self::granule_mask_for_range(block_off, len)?;

        {
            let _data_guard = page.data_lock.write();

            if page.valid_mask.load(Ordering::Acquire) & bits == bits {
                return Ok(());
            }

            let io_buf = self.create_cache_from_device_buffer_at(page, block_off, len)?;
            let mut req = Read::new(offset, len, false, Some(io_buf));
            self.backend
                .read_request(&mut req)
                .await
                .map_err(CacheError::Backend)?;

            page.valid_mask.fetch_or(bits, Ordering::AcqRel);
        }

        Ok(())
    }

    async fn read_block_into_page(
        &self,
        lba: u64,
        page: &Arc<CachePage>,
    ) -> Result<(), CacheError<B::Error>> {
        let bytes_read = {
            let _data_guard = page.data_lock.write();
            let io_buf = self.create_cache_from_device_buffer(page, BLOCK_SIZE)?;
            self.backend
                .read_phys_framed(lba, 1, io_buf)
                .await
                .map_err(CacheError::Backend)?
        };

        if unlikely(bytes_read > BLOCK_SIZE) {
            cold_path();
            return Err(CacheError::OffsetOverflow);
        }

        if unlikely(bytes_read < BLOCK_SIZE) {
            cold_path();
            let _data_guard = page.data_lock.write();
            unsafe {
                self.page_slice_mut(page)[bytes_read..].fill(0);
            }
        }

        page.valid_mask
            .store(Self::full_granule_mask(), Ordering::Release);
        Ok(())
    }

    async fn ensure_page_range_valid(
        &self,
        lba: u64,
        page: &Arc<CachePage>,
        block_off: usize,
        len: usize,
    ) -> Result<(), CacheError<B::Error>> {
        let needed = Self::granule_mask_for_range(block_off, len)?;
        let mut missing = needed & !page.valid_mask.load(Ordering::Acquire);

        while missing != 0 {
            let Some((granule_start, granule_count, bits)) = Self::first_mask_run(missing) else {
                break;
            };

            let read_off = granule_start
                .checked_mul(CACHE_GRANULE)
                .ok_or(CacheError::OffsetOverflow)?;
            let read_len = granule_count
                .checked_mul(CACHE_GRANULE)
                .ok_or(CacheError::OffsetOverflow)?;

            self.read_extent_into_page(lba, page, read_off, read_len)
                .await?;

            missing = needed & !page.valid_mask.load(Ordering::Acquire);
            missing &= !bits;
        }

        Ok(())
    }

    async fn load_cache_page_from_backend(
        &self,
        lba: u64,
    ) -> Result<Arc<CachePage>, CacheError<B::Error>> {
        let page = self.acquire_cache_page(lba).await?;
        match self.read_block_into_page(lba, &page).await {
            Ok(()) => Ok(page),
            Err(e) => {
                self.recycle_or_drop_page(page);
                Err(e)
            }
        }
    }

    async fn get_or_create_read_page(
        &self,
        lba: u64,
    ) -> Result<Arc<CachePage>, CacheError<B::Error>> {
        if let Some(page) = self.try_get_page(lba).await {
            return Ok(page);
        }

        cold_path();

        if unlikely(!self.cfg.read_allocate) {
            cold_path();
            return Err(CacheError::NoFreePages);
        }

        let loaded = self.load_cache_page_from_backend(lba).await?;
        Ok(self.insert_page_or_get_existing(lba, loaded).await)
    }

    async fn get_or_create_write_page(
        &self,
        lba: u64,
    ) -> Result<WriteAcquire, CacheError<B::Error>> {
        if let Some(page) = self.try_get_page(lba).await {
            return Ok(WriteAcquire::Cached(page));
        }

        cold_path();

        if !self.cfg.write_allocate {
            return Ok(WriteAcquire::Direct);
        }

        let page = self.acquire_cache_page(lba).await?;
        let page = self.insert_page_or_get_existing(lba, page).await;
        Ok(WriteAcquire::Cached(page))
    }

    async fn read_block_into_direct_page(
        &self,
        lba: u64,
        page: &Arc<CachePage>,
    ) -> Result<usize, CacheError<B::Error>> {
        let bytes_read = {
            let _data_guard = page.data_lock.write();
            let io_buf = self.create_cache_from_device_buffer(page, BLOCK_SIZE)?;
            self.backend
                .read_phys_framed(lba, 1, io_buf)
                .await
                .map_err(CacheError::Backend)?
        };

        if unlikely(bytes_read > BLOCK_SIZE) {
            cold_path();
            return Err(CacheError::OffsetOverflow);
        }

        if unlikely(bytes_read < BLOCK_SIZE) {
            cold_path();
            let _data_guard = page.data_lock.write();
            unsafe {
                self.page_slice_mut(page)[bytes_read..].fill(0);
            }
        }

        page.valid_mask
            .store(Self::full_granule_mask(), Ordering::Release);
        Ok(bytes_read)
    }

    async fn write_block_from_direct_page(
        &self,
        lba: u64,
        page: &Arc<CachePage>,
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        let buffer = self.create_cache_to_device_buffer(page, BLOCK_SIZE)?;

        let mut req = Write::new(
            lba * BLOCK_SIZE as u64,
            BLOCK_SIZE,
            false,
            owner,
            Some(buffer),
        );

        let status = self.backend.write_request(&mut req).await;
        drop(req);

        status.map_err(CacheError::Backend)?;
        Ok(())
    }

    fn take_direct_page(&self) -> Result<Arc<CachePage>, CacheError<B::Error>> {
        self.direct_page
            .lock()
            .take()
            .ok_or(CacheError::NoFreePages)
    }

    fn restore_direct_page(&self, page: Arc<CachePage>) {
        page.reset_for_lba(0);
        *self.direct_page.lock() = Some(page);
    }

    async fn direct_read_at(
        &self,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(out.is_empty()) {
            cold_path();
            return Ok(());
        }

        let page = self.take_direct_page()?;
        let mut result = Ok(());
        let mut dst_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = Self::block_size_u64();

        while dst_pos < out.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, out.len() - dst_pos);

            if let Err(err) = self.read_block_into_direct_page(lba, &page).await {
                result = Err(err);
                break;
            }

            self.ensure_page_range_valid(lba, &page, block_off, take)
                .await?;

            {
                let _guard = page.data_lock.read();
                unsafe {
                    out[dst_pos..dst_pos + take]
                        .copy_from_slice(&self.page_slice(&page)[block_off..block_off + take]);
                }
            }

            dst_pos += take;
            cur_off += take as u64;
        }

        self.restore_direct_page(page);
        result
    }

    async fn direct_write_at<'buffer>(
        &self,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        len: usize,
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(len == 0) {
            cold_path();
            return Ok(());
        }
        if unlikely(buffer.len() < len) {
            cold_path();
            return Err(CacheError::InvalidConfig);
        }

        let page = self.take_direct_page()?;
        let mut result = Ok(());
        let mut remaining = Some(buffer);
        let mut buffer_offset = 0usize;
        let mut written = 0usize;
        let mut cur_off = offset;
        let bs_u64 = Self::block_size_u64();

        while written < len {
            let block_off = (cur_off % bs_u64) as usize;

            if block_off == 0 {
                let bytes_left = len - written;
                let direct_len = bytes_left - (bytes_left % BLOCK_SIZE);

                if direct_len != 0 {
                    let source = remaining.take().expect("direct write buffer disappeared");
                    let (direct_buffer, tail) = match Self::take_to_device_buffer_range(
                        source,
                        buffer_offset,
                        direct_len,
                    ) {
                        Ok(parts) => parts,
                        Err(err) => {
                            result = Err(err);
                            break;
                        }
                    };

                    if let Err(err) = self
                        .write_buffer_to_backend(cur_off, direct_buffer, owner)
                        .await
                    {
                        result = Err(err);
                        break;
                    }

                    remaining = tail;
                    buffer_offset = 0;
                    written += direct_len;
                    cur_off += direct_len as u64;
                    continue;
                }
            }

            let lba = cur_off / bs_u64;
            let take = min(BLOCK_SIZE - block_off, len - written);

            if block_off != 0 || take != BLOCK_SIZE {
                if let Err(err) = self.read_block_into_direct_page(lba, &page).await {
                    result = Err(err);
                    break;
                }
            }

            {
                let _guard = page.data_lock.write();
                let destination =
                    unsafe { &mut self.page_slice_mut(&page)[block_off..block_off + take] };
                if let Err(err) = remaining
                    .as_ref()
                    .expect("direct write buffer disappeared")
                    .copy_to_slice(buffer_offset, destination)
                {
                    result = Err(CacheError::InvalidIoBuffer(err));
                    break;
                }
            }

            if let Err(err) = self.write_block_from_direct_page(lba, &page, owner).await {
                result = Err(err);
                break;
            }

            buffer_offset += take;
            written += take;
            cur_off += take as u64;
        }

        self.restore_direct_page(page);
        result
    }

    fn prepare_flush_extent(
        lba: u64,
        page: Arc<CachePage>,
        granule_start: usize,
        granule_count: usize,
        bits: u64,
    ) -> Option<PreparedFlushExtent> {
        if unlikely(page.dirty_mask.load(Ordering::Acquire) & bits == 0) {
            cold_path();
            return None;
        }

        let mut old = page.writeback_mask.load(Ordering::Acquire);
        loop {
            if unlikely(old & bits != 0) {
                cold_path();
                return None;
            }

            match page.writeback_mask.compare_exchange_weak(
                old,
                old | bits,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(cur) => old = cur,
            }
        }

        if unlikely(page.dirty_mask.load(Ordering::Acquire) & bits == 0) {
            cold_path();
            page.writeback_mask.fetch_and(!bits, Ordering::AcqRel);
            return None;
        }

        let wb_generation = page.generation.load(Ordering::Acquire);
        page.wb_generation.store(wb_generation, Ordering::Release);

        Some(PreparedFlushExtent {
            lba,
            slot: page.slot,
            page,
            granule_start,
            granule_count,
            bits,
            wb_generation,
        })
    }

    fn finish_prepared_flush_extents(&self, extents: &[PreparedFlushExtent], success: bool) {
        let mut completed_writebacks = 0usize;

        for prepared in extents {
            if likely(success) {
                let cur_gen = prepared.page.generation.load(Ordering::Acquire);
                if cur_gen == prepared.wb_generation {
                    self.clear_cached_page_dirty_range(&prepared.page, prepared.bits);
                }
            } else if prepared
                .page
                .dirty_mask
                .fetch_or(prepared.bits, Ordering::AcqRel)
                == 0
            {
                self.dirty_pages.fetch_add(1, Ordering::AcqRel);
            }

            prepared
                .page
                .writeback_mask
                .fetch_and(!prepared.bits, Ordering::AcqRel);
            completed_writebacks += 1;
        }

        if completed_writebacks != 0 {
            self.writeback_notifier.notify_all();
        }
    }

    #[inline]
    fn prepared_extent_starts_new_extent(
        prepared: &[PreparedFlushExtent],
        lba: u64,
        slot: usize,
        granule_start: usize,
    ) -> bool {
        let Some(prev) = prepared.last() else {
            return true;
        };

        let prev_logical_end = prev
            .lba
            .saturating_mul(BLOCK_SIZE as u64)
            .saturating_add(((prev.granule_start + prev.granule_count) * CACHE_GRANULE) as u64);
        let cur_logical_start = lba
            .saturating_mul(BLOCK_SIZE as u64)
            .saturating_add((granule_start * CACHE_GRANULE) as u64);

        let prev_cache_end = Self::page_offset(prev.slot)
            .saturating_add((prev.granule_start + prev.granule_count) * CACHE_GRANULE);
        let cur_cache_start = Self::page_offset(slot).saturating_add(granule_start * CACHE_GRANULE);

        prev_logical_end != cur_logical_start || prev_cache_end != cur_cache_start
    }

    fn collect_prepared_runs_into(
        pages: &[PreparedFlushExtent],
        runs: &mut Vec<PreparedRun>,
    ) -> Result<(), CacheError<B::Error>> {
        runs.clear();

        if pages.is_empty() {
            return Ok(());
        }

        if runs.capacity() < pages.len() {
            cold_path();
            return Err(CacheError::InsufficientResources);
        }

        let mut start = 0usize;
        let mut i = 1usize;

        while i <= pages.len() {
            let split = if i == pages.len() {
                true
            } else {
                Self::prepared_extent_starts_new_extent(
                    &pages[..i],
                    pages[i].lba,
                    pages[i].slot,
                    pages[i].granule_start,
                )
            };

            if split {
                runs.push(PreparedRun { start, end: i });
                start = i;
            }

            i += 1;
        }

        Ok(())
    }

    fn collect_cache_slot_extents_into(
        _pages: &[PreparedFlushExtent],
        logical_runs: &[PreparedRun],
        extents: &mut Vec<PreparedRun>,
    ) -> Result<(), CacheError<B::Error>> {
        extents.clear();

        if extents.capacity() < logical_runs.len() {
            cold_path();
            return Err(CacheError::InsufficientResources);
        }

        for run in logical_runs {
            extents.push(PreparedRun {
                start: run.start,
                end: run.end,
            });
        }

        Ok(())
    }

    fn extent_byte_len(
        pages: &[PreparedFlushExtent],
        extent: &PreparedRun,
    ) -> Result<usize, CacheError<B::Error>> {
        if unlikely(extent.start >= extent.end) {
            cold_path();
            return Ok(0);
        }

        let first = &pages[extent.start];
        let last = &pages[extent.end - 1];
        let start = Self::page_offset(first.slot)
            .checked_add(first.granule_start * CACHE_GRANULE)
            .ok_or(CacheError::OffsetOverflow)?;
        let end = Self::page_offset(last.slot)
            .checked_add((last.granule_start + last.granule_count) * CACHE_GRANULE)
            .ok_or(CacheError::OffsetOverflow)?;

        end.checked_sub(start).ok_or(CacheError::OffsetOverflow)
    }

    async fn write_cache_extents_chain_to_backend(
        &self,
        pages: &[PreparedFlushExtent],
        extents: &[PreparedRun],
        writes: &mut [Option<Write<'static>>; MAX_WRITE_CHAIN],
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(extents.is_empty()) {
            cold_path();
            return Ok(());
        }

        debug_assert!(extents.len() <= FLUSH_WRITE_CHAIN);

        let first_extent = &extents[0];
        let first_page = &pages[first_extent.start];

        let first_block_off = first_page
            .granule_start
            .checked_mul(CACHE_GRANULE)
            .ok_or(CacheError::OffsetOverflow)?;

        let first_len = Self::extent_byte_len(pages, first_extent)?;

        let first_offset = first_page
            .lba
            .checked_mul(BLOCK_SIZE as u64)
            .and_then(|base| base.checked_add(first_block_off as u64))
            .ok_or(CacheError::OffsetOverflow)?;

        let first_buffer =
            self.create_cache_to_device_buffer_at(&first_page.page, first_block_off, first_len)?;

        let mut req = Write::new(
            first_offset,
            first_len,
            false,
            first_page.page.owner.load(Ordering::Acquire),
            Some(first_buffer),
        );

        let mut initialized = 0usize;
        let mut result = Ok(());

        {
            let req_write = &req;

            let mut chain_idx = 1usize;
            while chain_idx < extents.len() {
                let extent = &extents[chain_idx];
                let first_page = &pages[extent.start];

                let block_off = match first_page.granule_start.checked_mul(CACHE_GRANULE) {
                    Some(block_off) => block_off,
                    None => {
                        result = Err(CacheError::OffsetOverflow);
                        break;
                    }
                };

                let byte_len = match Self::extent_byte_len(pages, extent) {
                    Ok(byte_len) => byte_len,
                    Err(err) => {
                        result = Err(err);
                        break;
                    }
                };

                let offset = match first_page
                    .lba
                    .checked_mul(BLOCK_SIZE as u64)
                    .and_then(|base| base.checked_add(block_off as u64))
                {
                    Some(offset) => offset,
                    None => {
                        result = Err(CacheError::OffsetOverflow);
                        break;
                    }
                };

                let buffer = match self.create_cache_to_device_buffer_at(
                    &first_page.page,
                    block_off,
                    byte_len,
                ) {
                    Ok(buffer) => buffer,
                    Err(err) => {
                        result = Err(err);
                        break;
                    }
                };

                let write = Write::new(
                    offset,
                    byte_len,
                    false,
                    first_page.page.owner.load(Ordering::Acquire),
                    Some(buffer),
                );

                let write_static: Write<'static> = unsafe { core::mem::transmute(write) };

                let slot = chain_idx - 1;
                writes[slot] = Some(write_static);
                initialized += 1;

                let curr_write_ptr = writes[slot].as_mut().expect("flush write slot disappeared")
                    as *mut Write<'static> as *mut Write<'_>;

                unsafe {
                    req_write.append_next(curr_write_ptr);
                }

                chain_idx += 1;
            }
        }

        if result.is_ok() {
            result = self
                .backend
                .write_request(&mut req)
                .await
                .map_err(CacheError::Backend);
        }

        drop(req);

        let mut i = 0usize;
        while i < initialized {
            writes[i] = None;
            i += 1;
        }

        result
    }

    fn page_for_flush_key(&self, lba: u64, filter: &FlushFilter) -> Option<Arc<CachePage>> {
        let shard_idx = self.shard_index(lba);
        let shard = self.shards[shard_idx].lock();
        let page: &Arc<CachePage> = shard.index.peek(&lba)?;

        if likely(page.dirty_mask.load(Ordering::Acquire) != 0 && filter.matches(lba, page)) {
            Some(Arc::clone(page))
        } else {
            cold_path();
            None
        }
    }

    fn prepare_flush_chain_from_keys(
        &self,
        filter: &FlushFilter,
        keys: &[u64],
        key_cursor: &mut usize,
        prepared: &mut Vec<PreparedFlushExtent>,
    ) -> Result<bool, CacheError<B::Error>> {
        prepared.clear();

        let mut extent_count = 0usize;

        while *key_cursor < keys.len() {
            let lba = keys[*key_cursor];

            let Some(page) = self.page_for_flush_key(lba, filter) else {
                *key_cursor += 1;
                continue;
            };

            let mut dirty = page.dirty_mask.load(Ordering::Acquire)
                & !page.writeback_mask.load(Ordering::Acquire)
                & Self::full_granule_mask();

            while dirty != 0 {
                let Some((granule_start, granule_count, bits)) = Self::first_mask_run(dirty) else {
                    break;
                };

                let starts_new_extent = Self::prepared_extent_starts_new_extent(
                    prepared,
                    lba,
                    page.slot,
                    granule_start,
                );

                if starts_new_extent && extent_count == FLUSH_WRITE_CHAIN {
                    return Ok(!prepared.is_empty());
                }

                if prepared.len() == prepared.capacity() {
                    if prepared.is_empty() {
                        cold_path();
                        return Err(CacheError::InsufficientResources);
                    }

                    return Ok(true);
                }

                if let Some(prepared_extent) = Self::prepare_flush_extent(
                    lba,
                    Arc::clone(&page),
                    granule_start,
                    granule_count,
                    bits,
                ) {
                    if starts_new_extent {
                        extent_count += 1;
                    }

                    prepared.push(prepared_extent);
                }

                dirty &= !bits;
            }

            *key_cursor += 1;
        }

        Ok(!prepared.is_empty())
    }

    async fn flush_prepared_pages_chained_with_runs(
        &self,
        pages: &[PreparedFlushExtent],
        logical_runs: &mut Vec<PreparedRun>,
        extents: &mut Vec<PreparedRun>,
    ) -> Result<usize, CacheError<B::Error>> {
        if pages.is_empty() {
            return Ok(0);
        }

        Self::collect_prepared_runs_into(pages, logical_runs)?;
        Self::collect_cache_slot_extents_into(pages, logical_runs, extents)?;

        if unlikely(extents.len() > FLUSH_WRITE_CHAIN) {
            cold_path();
            self.finish_prepared_flush_extents(pages, false);
            return Err(CacheError::InsufficientResources);
        }
        let mut lease = FlushRunScratchLease::new(&self.flush_scratch);

        let writes = lease
            .writes
            .as_mut()
            .expect("flush write scratch lease used after drop");

        let status = self
            .write_cache_extents_chain_to_backend(pages, extents, writes)
            .await;

        match status {
            Ok(()) => {
                self.finish_prepared_flush_extents(pages, true);
                Ok(pages.len())
            }
            Err(err) => {
                cold_path();
                self.finish_prepared_flush_extents(pages, false);
                Err(err)
            }
        }
    }

    async fn flush_sorted_candidate_keys_batched(
        &self,
        filter: &FlushFilter,
        keys: &[u64],
    ) -> Result<usize, CacheError<B::Error>> {
        if unlikely(keys.is_empty()) {
            cold_path();
            return Ok(0);
        }

        let (mut prepared, mut runs, mut extents) = {
            let mut scratch = self.flush_scratch.lock();
            let prepared = core::mem::take(&mut scratch.prepared);
            let runs = core::mem::take(&mut scratch.runs);
            let extents = core::mem::take(&mut scratch.extents);
            (prepared, runs, extents)
        };

        prepared.clear();
        runs.clear();
        extents.clear();

        let mut key_cursor = 0usize;
        let mut total_flushed = 0usize;
        let mut result = Ok(());

        while key_cursor < keys.len() {
            prepared.clear();
            runs.clear();
            extents.clear();

            let has_chain = match self.prepare_flush_chain_from_keys(
                filter,
                keys,
                &mut key_cursor,
                &mut prepared,
            ) {
                Ok(has_chain) => has_chain,
                Err(err) => {
                    result = Err(err);
                    break;
                }
            };

            if !has_chain {
                continue;
            }

            match self
                .flush_prepared_pages_chained_with_runs(&prepared, &mut runs, &mut extents)
                .await
            {
                Ok(flushed) => {
                    total_flushed += flushed;
                }
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }

        prepared.clear();
        runs.clear();
        extents.clear();

        {
            let mut scratch = self.flush_scratch.lock();

            if scratch.prepared.capacity() < prepared.capacity() {
                scratch.prepared = prepared;
            }

            if scratch.runs.capacity() < runs.capacity() {
                scratch.runs = runs;
            }

            if scratch.extents.capacity() < extents.capacity() {
                scratch.extents = extents;
            }
        }

        result.map(|()| total_flushed)
    }
    async fn flush_filtered_batched(
        &self,
        filter: &FlushFilter,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        let mut keys = {
            let mut scratch = self.flush_scratch.lock();
            core::mem::take(&mut scratch.keys)
        };

        keys.clear();

        let mut shard_idx = 0usize;
        while shard_idx < self.shards.len() {
            let shard = self.shards[shard_idx].lock();
            shard.index.for_each(|lba, page| {
                if page.dirty_mask.load(Ordering::Acquire) != 0 && filter.matches(lba, page) {
                    keys.push(lba);
                }
            });
            shard_idx += 1;
        }

        keys.sort_unstable();
        let matched = keys.len();

        let writebacks = self
            .flush_sorted_candidate_keys_batched(filter, &keys)
            .await;

        keys.clear();

        {
            let mut scratch = self.flush_scratch.lock();

            if scratch.keys.capacity() < keys.capacity() {
                scratch.keys = keys;
            }
        }

        writebacks.map(|writebacks| (matched, writebacks))
    }

    fn filtered_writeback_state(&self, filter: &FlushFilter) -> FilteredWritebackState {
        let mut has_dirty = false;
        let mut has_active_writeback = false;
        let mut shard_idx = 0usize;

        while shard_idx < self.shards.len() {
            let shard = self.shards[shard_idx].lock();

            shard.index.for_each(|lba, page| {
                if page.dirty_mask.load(Ordering::Acquire) != 0 && filter.matches(lba, page) {
                    has_dirty = true;
                    if page.writeback_mask.load(Ordering::Acquire) != 0 {
                        has_active_writeback = true;
                    }
                }
            });

            if has_active_writeback {
                return FilteredWritebackState::ActiveWriteback;
            }

            shard_idx += 1;
        }

        if has_dirty {
            FilteredWritebackState::NeedsFlush
        } else {
            FilteredWritebackState::Clean
        }
    }

    fn wait_for_writeback_progress<'cache, 'filter>(
        &'cache self,
        filter: &'filter FlushFilter,
    ) -> WritebackProgressWait<'cache, 'filter, B, BLOCK_SIZE, F> {
        WritebackProgressWait {
            cache: self,
            filter,
        }
    }

    async fn flush_until_clean(&self) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::All, true)
            .await
    }

    async fn flush_internal_filtered(
        &self,
        filter: &FlushFilter,
        force_device_flush: bool,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        self.check_open()?;
        self.wait_for_flush_slot().await;

        let _flush_guard = FlushActiveGuard {
            active: &self.flush_active,
            notifier: &self.writeback_notifier,
        };

        let (matched, writebacks) = self.flush_filtered_batched(filter).await?;

        if writebacks != 0 || (force_device_flush && matched == 0) {
            self.backend
                .flush_device()
                .await
                .map_err(CacheError::Backend)?;
        }

        Ok((matched, writebacks))
    }

    async fn flush_until_filtered_clean(
        &self,
        filter: &FlushFilter,
        force_device_flush: bool,
    ) -> Result<(), CacheError<B::Error>> {
        loop {
            let dirty_before = self.dirty_pages.load(Ordering::Acquire);

            let (_, writebacks) = self
                .flush_internal_filtered(filter, force_device_flush)
                .await?;

            if matches!(
                self.filtered_writeback_state(filter),
                FilteredWritebackState::Clean
            ) {
                break;
            }

            if writebacks == 0 {
                if matches!(
                    self.wait_for_writeback_progress(filter).await,
                    WritebackWaitResult::Clean
                ) {
                    break;
                }

                continue;
            }

            let dirty_after = self.dirty_pages.load(Ordering::Acquire);

            if dirty_after >= dirty_before {
                let (_, retry_writebacks) = self
                    .flush_internal_filtered(filter, force_device_flush)
                    .await?;

                if retry_writebacks == 0
                    && matches!(
                        self.wait_for_writeback_progress(filter).await,
                        WritebackWaitResult::Clean
                    )
                {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn flush_internal_all(&self) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::All, true)
            .await
    }

    async fn flush_internal_owner_to_backend(
        &self,
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::Owner(owner), false)
            .await
    }

    fn should_start_background_writeback(&self) -> bool {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return false;
        }

        let dirty = self.dirty_pages.load(Ordering::Acquire);
        dirty != 0 && dirty >= self.cfg.dirty_high_watermark_blocks
    }

    async fn background_writeback_loop(&self) {
        loop {
            if unlikely(self.closed.load(Ordering::Acquire)) {
                cold_path();
                break;
            }

            let dirty_before = self.dirty_pages.load(Ordering::Acquire);
            if dirty_before <= self.cfg.dirty_low_watermark_blocks {
                break;
            }

            let (matched, writebacks) =
                match self.flush_internal_filtered(&FlushFilter::All, false).await {
                    Ok(pass) => pass,
                    Err(err) => {
                        cold_path();
                        println!(
                            "volmgr: VolumeCache::background_writeback_loop failed: {:?}",
                            err
                        );
                        break;
                    }
                };

            let dirty_after = self.dirty_pages.load(Ordering::Acquire);

            if matched == 0 || writebacks == 0 || dirty_after >= dirty_before {
                break;
            }
        }
    }

    fn maybe_start_background_writeback(cache: &Arc<Self>) {
        if likely(!cache.should_start_background_writeback()) {
            return;
        }

        if cache
            .background_writeback_active
            .swap(true, Ordering::AcqRel)
        {
            cold_path();
            return;
        }
        let cache_for_task = Arc::clone(cache);

        spawn_detached(async move {
            cache_for_task.background_writeback_loop().await;
            cache_for_task
                .background_writeback_active
                .store(false, Ordering::Release);

            if cache_for_task.should_start_background_writeback()
                && !cache_for_task
                    .background_writeback_active
                    .swap(true, Ordering::AcqRel)
            {
                let cache_for_followup = Arc::clone(&cache_for_task);

                spawn_detached(async move {
                    cache_for_followup.background_writeback_loop().await;
                    cache_for_followup
                        .background_writeback_active
                        .store(false, Ordering::Release);
                });
            }
        });
    }

    pub(crate) fn flush_owner_background(cache: &Arc<Self>, owner: u64) {
        if unlikely(cache.closed.load(Ordering::Acquire)) {
            cold_path();
            return;
        }

        let cache = Arc::clone(cache);

        spawn_detached(async move {
            if let Err(err) = cache.flush_internal_owner_to_backend(owner).await {
                cold_path();
                println!(
                    "volmgr: VolumeCache::flush_owner_background owner {} failed: {:?}",
                    owner, err
                );
            }
        });
    }

    pub async fn close_and_flush(&self) -> Result<(), CacheError<B::Error>> {
        self.flush_until_clean().await?;
        self.closed.store(true, Ordering::Release);
        Ok(())
    }

    async fn direct_write_miss_len(
        cache: &Arc<Self>,
        offset: u64,
        remaining_len: usize,
    ) -> Result<usize, CacheError<B::Error>> {
        let bs_u64 = Self::block_size_u64();
        let mut len = 0usize;
        let mut cur_off = offset;

        while len < remaining_len {
            let lba = cur_off / bs_u64;

            if len != 0 && cache.try_get_page(lba).await.is_some() {
                break;
            }

            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, remaining_len - len);
            len += take;
            cur_off += take as u64;
        }

        Ok(len)
    }

    async fn write_at_inner<'buffer>(
        cache: &Arc<Self>,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        len: usize,
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        cache.check_open()?;
        let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, len)?;

        if unlikely(len == 0) {
            cold_path();
            return Ok(());
        }
        if unlikely(buffer.len() < len) {
            cold_path();
            return Err(CacheError::InvalidConfig);
        }

        let mut remaining = Some(buffer);
        let mut buffer_offset = 0usize;
        let mut written = 0usize;
        let mut cur_off = offset;
        let bs_u64 = VolumeCache::<B, BLOCK_SIZE, F>::block_size_u64();
        let mut no_free_flush_started = false;

        while written < len {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, len - written);

            let acquired = match cache.get_or_create_write_page(lba).await {
                Ok(acquired) => acquired,
                Err(CacheError::NoFreePages) if cache.cfg.direct_io_on_no_free_pages => {
                    cold_path();

                    if !no_free_flush_started {
                        Self::maybe_start_background_writeback(cache);
                        no_free_flush_started = true;
                    }
                    WriteAcquire::Direct
                }
                Err(err) => {
                    cold_path();
                    return Err(err);
                }
            };

            match acquired {
                WriteAcquire::Cached(page) => {
                    let bits = Self::granule_mask_for_range(block_off, take)?;

                    while page.writeback_mask.load(Ordering::Acquire) & bits != 0 {
                        match cache.wait_for_writeback_progress(&FlushFilter::All).await {
                            WritebackWaitResult::Clean | WritebackWaitResult::NeedsFlush => break,
                        }
                    }

                    if !Self::range_covers_whole_granules(block_off, take) {
                        cache
                            .ensure_page_range_valid(lba, &page, block_off, take)
                            .await?;
                    }

                    {
                        let _guard = page.data_lock.write();
                        let destination = unsafe {
                            &mut cache.page_slice_mut(&page)[block_off..block_off + take]
                        };
                        remaining
                            .as_ref()
                            .expect("write buffer disappeared")
                            .copy_to_slice(buffer_offset, destination)
                            .map_err(CacheError::InvalidIoBuffer)?;
                        cache.mark_cached_page_dirty_range(&page, owner, bits);
                    }
                }
                WriteAcquire::Direct => {
                    cold_path();

                    let direct_len =
                        Self::direct_write_miss_len(cache, cur_off, len - written).await?;

                    let source = remaining.take().expect("write buffer disappeared");
                    let (direct_buffer, tail) =
                        Self::take_to_device_buffer_range(source, buffer_offset, direct_len)?;
                    cache
                        .direct_write_at(cur_off, direct_buffer, direct_len, owner)
                        .await?;

                    remaining = tail;
                    buffer_offset = 0;
                    written += direct_len;
                    cur_off += direct_len as u64;
                    continue;
                }
            }

            buffer_offset += take;
            written += take;
            cur_off += take as u64;
        }

        Ok(())
    }

    async fn read_at(
        self: &Arc<Self>,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), CacheError<B::Error>> {
        self.check_open()?;
        let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, out.len())?;

        if unlikely(out.is_empty()) {
            cold_path();
            return Ok(());
        }

        let mut dst_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = VolumeCache::<B, BLOCK_SIZE, F>::block_size_u64();
        let mut no_free_flush_started = false;

        while dst_pos < out.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, out.len() - dst_pos);

            let page = match self.get_or_create_read_page(lba).await {
                Ok(page) => page,
                Err(CacheError::NoFreePages) if self.cfg.direct_io_on_no_free_pages => {
                    cold_path();

                    if !no_free_flush_started {
                        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self);
                        no_free_flush_started = true;
                    }

                    self.direct_read_at(cur_off, &mut out[dst_pos..dst_pos + take])
                        .await?;

                    dst_pos += take;
                    cur_off += take as u64;
                    continue;
                }
                Err(err) => {
                    cold_path();
                    return Err(err);
                }
            };

            self.ensure_page_range_valid(lba, &page, block_off, take)
                .await?;

            {
                let _guard = page.data_lock.read();
                unsafe {
                    out[dst_pos..dst_pos + take]
                        .copy_from_slice(&self.page_slice(&page)[block_off..block_off + take]);
                }
            }

            dst_pos += take;
            cur_off += take as u64;
        }

        Ok(())
    }
}

impl<B, const BLOCK_SIZE: usize, F> Drop for VolumeCache<B, BLOCK_SIZE, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    fn drop(&mut self) {
        drop(self.cache_backing.take());

        if self.cache_bytes != 0 {
            unsafe {
                unmap_range(self.cache_base, self.cache_bytes as u64);
            }

            unsafe { deallocate_kernel_range(self.cache_base, self.cache_bytes as u64) };
            self.cache_bytes = 0;
        }
    }
}

impl<B, const BLOCK_SIZE: usize, F> VolumeCacheOps for Arc<VolumeCache<B, BLOCK_SIZE, F>>
where
    B: VolumeCacheBackend,
    B::Error: Clone,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    type Error = CacheError<B::Error>;
    async fn read_request<'req, 'data>(&self, req: &mut Read<'data>) -> Result<(), Self::Error> {
        self.check_open()?;

        let (offset, len_req, no_buffer, req_data_len) = {
            let r = &*req;
            (
                r.offset,
                r.len,
                r.no_buffer,
                r.buffer.as_ref().map_or(0, |buffer| buffer.len()),
            )
        };

        let len = if no_buffer {
            len_req
        } else {
            core::cmp::min(len_req, req_data_len)
        };

        let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, len)?;

        if unlikely(len == 0) {
            cold_path();
            return Ok(());
        }

        if no_buffer {
            {
                let w = &mut *req;
                w.len = len;
            }

            self.backend
                .read_request(req)
                .await
                .map_err(CacheError::Backend)?;
            return Ok(());
        }

        if (offset as usize) % BLOCK_SIZE == 0 && len % BLOCK_SIZE == 0 {
            let block_range = VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
            let mut has_cached_page = false;
            let mut lba = block_range.start;

            while lba < block_range.end {
                if self.try_get_page(lba).await.is_some() {
                    has_cached_page = true;
                    break;
                }

                lba += 1;
            }

            if !has_cached_page && self.free_pages.lock().is_empty() {
                req.len = len;

                self.backend
                    .read_request(req)
                    .await
                    .map_err(CacheError::Backend)?;

                return Ok(());
            }
        }

        let contiguous_dst = req
            .buffer
            .as_mut()
            .and_then(|buffer| buffer.try_as_mut_slice())
            .map(|slice| slice.as_mut_ptr() as usize);
        if let Some(dst) = contiguous_dst {
            let dst = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, len) };
            return self.read_at(offset, dst).await;
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| CacheError::InsufficientResources)?;
        bytes.resize(len, 0);
        self.read_at(offset, &mut bytes).await?;

        let buffer = req.buffer.as_mut().ok_or(CacheError::InvalidConfig)?;
        buffer
            .copy_from_slice(0, &bytes)
            .map_err(CacheError::InvalidIoBuffer)
    }

    async fn write_request<'req, 'data>(&self, req: &mut Write<'data>) -> Result<(), Self::Error> {
        self.check_open()?;

        let (offset, len_req, no_buffer, owner, req_data_len) = {
            let r = &*req;
            (
                r.offset,
                r.len,
                r.no_buffer,
                r.owner,
                r.buffer.as_ref().map_or(0, |buffer| buffer.len()),
            )
        };

        let len = if no_buffer {
            len_req
        } else {
            core::cmp::min(len_req, req_data_len)
        };

        let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, len)?;

        if unlikely(len == 0) {
            cold_path();
            return Ok(());
        }

        if no_buffer {
            {
                let w = &mut *req;
                w.len = len;
            }

            self.backend
                .write_request(req)
                .await
                .map_err(CacheError::Backend)?;
            return Ok(());
        }

        if (offset as usize) % BLOCK_SIZE == 0 && len % BLOCK_SIZE == 0 {
            let block_range = VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
            let mut has_cached_page = false;
            let mut lba = block_range.start;

            while lba < block_range.end {
                if self.try_get_page(lba).await.is_some() {
                    has_cached_page = true;
                    break;
                }

                lba += 1;
            }

            if !has_cached_page && self.free_pages.lock().is_empty() {
                req.len = len;

                self.backend
                    .write_request(req)
                    .await
                    .map_err(CacheError::Backend)?;

                VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self);
                return Ok(());
            }
        }

        let buffer = req.buffer.take().ok_or(CacheError::InvalidConfig)?;

        VolumeCache::<B, BLOCK_SIZE, F>::write_at_inner(self, offset, buffer, len, owner).await?;
        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self);
        Ok(())
    }
    async fn flush(&self) -> Result<(), Self::Error> {
        self.flush_internal_all().await
    }

    async fn flush_owner(&self, owner: u64) -> Result<(), Self::Error> {
        self.flush_internal_owner_to_backend(owner).await
    }

    fn flush_background_pass(&self) {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return;
        }

        let cache = Arc::clone(self);

        spawn_detached(async move {
            let _ = cache.flush_internal_all().await;
        });
    }
}
