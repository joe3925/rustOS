use crate::cache::{CacheIndex, CacheIndexFactory, DefaultIndexFactory};
use crate::cache_traits::{
    CacheConfig, CacheError, CacheStats, VolumeCacheBackend, VolumeCacheOps,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::min;
use core::future::Future;
use core::hint::{cold_path, likely, unlikely};
use core::marker::PhantomData;
use core::ops::Range;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use kernel_api::kernel_types::dma::{
    Described, FromDevice, IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc,
    ToDevice,
};
use kernel_api::memory::{
    PageTableFlags, VirtAddr, allocate_auto_kernel_range_mapped_contiguous,
    deallocate_kernel_range, unmap_range,
};
use kernel_api::println;
use kernel_api::request::{RequestHandle, TraversalPolicy, Write};
use kernel_api::runtime::spawn_detached;
use spin::{Mutex, RwLock};

use super::notify::WritebackNotifier;

pub const MAX_WRITE_CHAIN: usize = 64;

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

struct StatsInner {
    read_hits: AtomicU64,
    read_misses: AtomicU64,
    write_hits: AtomicU64,
    write_misses: AtomicU64,
    backend_reads: AtomicU64,
    backend_writes: AtomicU64,
    flush_attempts: AtomicU64,
    flush_success: AtomicU64,
    flush_skipped_clean: AtomicU64,
    flush_skipped_busy: AtomicU64,
    evictions: AtomicU64,
    failed_evictions: AtomicU64,
    oversubscribe_inserts: AtomicU64,
    direct_writebacks: AtomicU64,
}

impl StatsInner {
    fn new() -> Self {
        Self {
            read_hits: AtomicU64::new(0),
            read_misses: AtomicU64::new(0),
            write_hits: AtomicU64::new(0),
            write_misses: AtomicU64::new(0),
            backend_reads: AtomicU64::new(0),
            backend_writes: AtomicU64::new(0),
            flush_attempts: AtomicU64::new(0),
            flush_success: AtomicU64::new(0),
            flush_skipped_clean: AtomicU64::new(0),
            flush_skipped_busy: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            failed_evictions: AtomicU64::new(0),
            oversubscribe_inserts: AtomicU64::new(0),
            direct_writebacks: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> CacheStats {
        CacheStats {
            read_hits: self.read_hits.load(Ordering::Relaxed),
            read_misses: self.read_misses.load(Ordering::Relaxed),
            write_hits: self.write_hits.load(Ordering::Relaxed),
            write_misses: self.write_misses.load(Ordering::Relaxed),
            backend_reads: self.backend_reads.load(Ordering::Relaxed),
            backend_writes: self.backend_writes.load(Ordering::Relaxed),
            flush_attempts: self.flush_attempts.load(Ordering::Relaxed),
            flush_success: self.flush_success.load(Ordering::Relaxed),
            flush_skipped_clean: self.flush_skipped_clean.load(Ordering::Relaxed),
            flush_skipped_busy: self.flush_skipped_busy.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            failed_evictions: self.failed_evictions.load(Ordering::Relaxed),
            oversubscribe_inserts: self.oversubscribe_inserts.load(Ordering::Relaxed),
            direct_writebacks: self.direct_writebacks.load(Ordering::Relaxed),
        }
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

struct CachePage {
    slot: usize,
    dirty: AtomicBool,
    writeback: AtomicBool,
    owner: AtomicU64,
    generation: AtomicU64,
    wb_generation: AtomicU64,
    data_lock: RwLock<()>,
}

impl CachePage {
    fn new(slot: usize) -> Self {
        Self {
            slot,
            dirty: AtomicBool::new(false),
            writeback: AtomicBool::new(false),
            owner: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            wb_generation: AtomicU64::new(0),
            data_lock: RwLock::new(()),
        }
    }

    fn reset_for_lba(&self, _lba: u64) {
        self.dirty.store(false, Ordering::Release);
        self.writeback.store(false, Ordering::Release);
        self.owner.store(0, Ordering::Release);
        self.generation.store(0, Ordering::Release);
        self.wb_generation.store(0, Ordering::Release);
    }

    fn is_evictable(&self) -> bool {
        !self.dirty.load(Ordering::Acquire) && !self.writeback.load(Ordering::Acquire)
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

enum FlushFilter<'a> {
    All,
    BlockRange(&'a Range<u64>),
    Owner(u64),
}

impl FlushFilter<'_> {
    fn matches(&self, lba: u64, page: &CachePage) -> bool {
        match self {
            FlushFilter::All => true,
            FlushFilter::BlockRange(range) => lba >= range.start && lba < range.end,
            FlushFilter::Owner(owner) => {
                *owner != 0 && page.owner.load(Ordering::Acquire) == *owner
            }
        }
    }
}

struct PreparedFlushPage {
    lba: u64,
    slot: usize,
    page: Arc<CachePage>,
    wb_generation: u64,
}

struct PreparedRun {
    start: usize,
    end: usize,
}

struct FlushScratch {
    keys: Vec<u64>,
    prepared: Vec<PreparedFlushPage>,
    runs: Vec<PreparedRun>,
}

impl FlushScratch {
    fn new(capacity_blocks: usize) -> Result<Self, ()> {
        let mut keys = Vec::new();
        let mut prepared = Vec::new();
        let mut runs = Vec::new();

        keys.try_reserve_exact(capacity_blocks).map_err(|_| ())?;
        prepared
            .try_reserve_exact(capacity_blocks)
            .map_err(|_| ())?;
        runs.try_reserve_exact(capacity_blocks).map_err(|_| ())?;

        Ok(Self {
            keys,
            prepared,
            runs,
        })
    }
}

struct WritebackProgressWait<'cache, 'filter, 'range, B, const BLOCK_SIZE: usize, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    cache: &'cache VolumeCache<B, BLOCK_SIZE, F>,
    filter: &'filter FlushFilter<'range>,
}

impl<'cache, 'filter, 'range, B, const BLOCK_SIZE: usize, F> Future
    for WritebackProgressWait<'cache, 'filter, 'range, B, BLOCK_SIZE, F>
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
    stats: Arc<StatsInner>,
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
    pub fn new(backend: Arc<B>, cfg: CacheConfig) -> Result<Self, CacheError<B::Error>> {
        Self::new_with_index(backend, cfg, DefaultIndexFactory)
    }
}

impl<B, const BLOCK_SIZE: usize, F> VolumeCache<B, BLOCK_SIZE, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<CachePage>>,
{
    pub fn new_with_index(
        backend: Arc<B>,
        mut cfg: CacheConfig,
        factory: F,
    ) -> Result<Self, CacheError<B::Error>> {
        if unlikely(BLOCK_SIZE == 0 || cfg.capacity_blocks == 0) {
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

        let cache_backing =
            match IoBufferBacking::new(IoBufferBackingDesc::SliceMut(cache_slice), backing_cfg) {
                Ok(backing) => backing,
                Err(e) => {
                    unsafe {
                        unmap_range(cache_base, cache_bytes as u64);
                    }
                    deallocate_kernel_range(cache_base, cache_bytes as u64);
                    return Err(CacheError::InvalidIoBuffer(e));
                }
            };

        let shard_count = cfg.shards;
        let per_shard = (cfg.capacity_blocks + shard_count - 1) / shard_count;
        let mut shards = Vec::with_capacity(shard_count);

        let mut i = 0usize;
        while i < shard_count {
            let mut index = factory.build(per_shard);
            index.reserve_or_panic(per_shard);
            shards.push(Mutex::new(Shard::new(index, per_shard)));
            i += 1;
        }

        let mut free_pages = Vec::new();
        free_pages
            .try_reserve_exact(cfg.capacity_blocks)
            .map_err(|_| CacheError::InsufficientResources)?;

        let mut slot = cfg.capacity_blocks;
        while slot != 0 {
            slot -= 1;
            free_pages.push(Arc::new(CachePage::new(slot)));
        }

        let direct_page = Arc::new(CachePage::new(cfg.capacity_blocks));
        let flush_scratch = FlushScratch::new(cfg.capacity_blocks)
            .map_err(|_| CacheError::InsufficientResources)?;

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
            stats: Arc::new(StatsInner::new()),
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
    fn cache_backing(&self) -> Result<&IoBufferBacking<'static>, CacheError<B::Error>> {
        self.cache_backing.as_ref().ok_or(CacheError::InvalidConfig)
    }

    #[inline]
    unsafe fn page_slice(&self, page: &CachePage) -> &[u8] {
        let ptr = (self.cache_base.as_u64() as usize + Self::page_offset(page.slot)) as *const u8;
        core::slice::from_raw_parts(ptr, BLOCK_SIZE)
    }

    #[inline]
    unsafe fn page_slice_mut(&self, page: &CachePage) -> &mut [u8] {
        let ptr = (self.cache_base.as_u64() as usize + Self::page_offset(page.slot)) as *mut u8;
        core::slice::from_raw_parts_mut(ptr, BLOCK_SIZE)
    }

    fn create_cache_from_device_buffer<'a>(
        &'a self,
        page: &CachePage,
        len: usize,
    ) -> Result<IoBuffer<'a, 'a, Described, FromDevice>, CacheError<B::Error>> {
        let start = Self::page_offset(page.slot);

        self.cache_backing()?
            .create_from_device(start, len)
            .map_err(|err| {
                cold_path();
                CacheError::InvalidIoBuffer(err)
            })
    }

    fn create_cache_to_device_buffer<'a>(
        &'a self,
        page: &CachePage,
        len: usize,
    ) -> Result<IoBuffer<'a, 'a, Described, ToDevice>, CacheError<B::Error>> {
        let start = Self::page_offset(page.slot);

        self.cache_backing()?
            .create_to_device(start, len)
            .map_err(|err| {
                cold_path();
                CacheError::InvalidIoBuffer(err)
            })
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

    fn mark_cached_page_dirty(&self, page: &CachePage, owner: u64) {
        page.owner.store(owner, Ordering::Release);
        page.generation.fetch_add(1, Ordering::AcqRel);

        if !page.dirty.swap(true, Ordering::AcqRel) {
            self.dirty_pages.fetch_add(1, Ordering::AcqRel);
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
        page.dirty.load(Ordering::Acquire)
            && !page.writeback.load(Ordering::Acquire)
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

        if reclaim_key.is_none() && shard.index.len() != 0 {
            self.stats.failed_evictions.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(lba) = reclaim_key {
            let Some(page) = shard.index.remove(&lba) else {
                return None;
            };
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
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

        let Some(prepared) = Self::prepare_flush_page(&self.stats, lba, page) else {
            return Ok(true);
        };

        let prepared = [prepared];
        let mut runs = {
            let mut scratch = self.flush_scratch.lock();
            core::mem::take(&mut scratch.runs)
        };
        runs.clear();

        let result = self
            .flush_prepared_pages_chained_with_runs(&prepared, &mut runs)
            .await;

        runs.clear();
        {
            let mut scratch = self.flush_scratch.lock();
            if scratch.runs.capacity() < runs.capacity() {
                scratch.runs = runs;
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

        if shard.index.len() >= shard.target_capacity {
            self.stats
                .oversubscribe_inserts
                .fetch_add(1, Ordering::Relaxed);
        }

        let _ = shard.index.insert(lba, Arc::clone(&page));
        page
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

        self.stats.backend_reads.fetch_add(1, Ordering::Relaxed);
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
            self.stats.read_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(page);
        }

        cold_path();
        self.stats.read_misses.fetch_add(1, Ordering::Relaxed);

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
        block_off: usize,
        write_len: usize,
        src_for_full: &[u8],
    ) -> Result<WriteAcquire, CacheError<B::Error>> {
        if let Some(page) = self.try_get_page(lba).await {
            self.stats.write_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(WriteAcquire::Cached(page));
        }

        cold_path();
        self.stats.write_misses.fetch_add(1, Ordering::Relaxed);

        let is_full_block = block_off == 0 && write_len == BLOCK_SIZE;

        if !self.cfg.write_allocate {
            return Ok(WriteAcquire::Direct);
        }

        let page = self.acquire_cache_page(lba).await?;
        if is_full_block {
            {
                let _guard = page.data_lock.write();
                unsafe {
                    self.page_slice_mut(&page).copy_from_slice(src_for_full);
                }
            }
        } else if let Err(e) = self.read_block_into_page(lba, &page).await {
            self.recycle_or_drop_page(page);
            return Err(e);
        }

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

        self.stats.backend_reads.fetch_add(1, Ordering::Relaxed);
        Ok(bytes_read)
    }

    async fn write_block_from_direct_page(
        &self,
        lba: u64,
        page: &Arc<CachePage>,
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        let buffer = self.create_cache_to_device_buffer(page, BLOCK_SIZE)?;

        let mut req = RequestHandle::new(Write {
            offset: lba * BLOCK_SIZE as u64,
            len: BLOCK_SIZE,
            no_buffer: false,
            owner,
            buffer: Some(buffer),
            next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        });

        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        let status = self.backend.write_request(&mut req).await;
        drop(req);

        status.map_err(CacheError::Backend)?;
        self.stats.backend_writes.fetch_add(1, Ordering::Relaxed);
        self.stats.direct_writebacks.fetch_add(1, Ordering::Relaxed);
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

    async fn direct_write_at(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(data.is_empty()) {
            cold_path();
            return Ok(());
        }

        let page = self.take_direct_page()?;
        let mut result = Ok(());
        let mut src_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = Self::block_size_u64();

        while src_pos < data.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, data.len() - src_pos);

            if block_off != 0 || take != BLOCK_SIZE {
                if let Err(err) = self.read_block_into_direct_page(lba, &page).await {
                    result = Err(err);
                    break;
                }
            }

            {
                let _guard = page.data_lock.write();
                unsafe {
                    if block_off == 0 && take == BLOCK_SIZE {
                        self.page_slice_mut(&page)
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    } else {
                        self.page_slice_mut(&page)[block_off..block_off + take]
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    }
                }
            }

            if let Err(err) = self.write_block_from_direct_page(lba, &page, owner).await {
                result = Err(err);
                break;
            }

            src_pos += take;
            cur_off += take as u64;
        }

        self.restore_direct_page(page);
        result
    }

    fn prepare_flush_page(
        stats: &StatsInner,
        lba: u64,
        page: Arc<CachePage>,
    ) -> Option<PreparedFlushPage> {
        stats.flush_attempts.fetch_add(1, Ordering::Relaxed);

        if unlikely(!page.dirty.load(Ordering::Acquire)) {
            cold_path();
            stats.flush_skipped_clean.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        if unlikely(page.writeback.swap(true, Ordering::AcqRel)) {
            cold_path();
            stats.flush_skipped_busy.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        if unlikely(!page.dirty.load(Ordering::Acquire)) {
            cold_path();
            page.writeback.store(false, Ordering::Release);
            stats.flush_skipped_clean.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let wb_generation = page.generation.load(Ordering::Acquire);
        page.wb_generation.store(wb_generation, Ordering::Release);

        Some(PreparedFlushPage {
            lba,
            slot: page.slot,
            page,
            wb_generation,
        })
    }

    fn finish_prepared_flush_pages(&self, pages: &[PreparedFlushPage], success: bool) {
        let mut completed_writebacks = 0usize;

        for prepared in pages {
            if likely(success) {
                let cur_gen = prepared.page.generation.load(Ordering::Acquire);
                if cur_gen == prepared.wb_generation
                    && prepared.page.dirty.swap(false, Ordering::AcqRel)
                {
                    self.dirty_pages.fetch_sub(1, Ordering::AcqRel);
                }
                self.stats.flush_success.fetch_add(1, Ordering::Relaxed);
            } else if !prepared.page.dirty.swap(true, Ordering::AcqRel) {
                cold_path();
                self.dirty_pages.fetch_add(1, Ordering::AcqRel);
            }

            prepared.page.writeback.store(false, Ordering::Release);
            completed_writebacks += 1;
        }

        if completed_writebacks != 0 {
            self.writeback_notifier.notify_all();
        }
    }

    fn collect_prepared_runs_into(
        pages: &[PreparedFlushPage],
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
                pages[i].lba != pages[i - 1].lba + 1 || pages[i].slot != pages[i - 1].slot + 1
            };

            if split {
                runs.push(PreparedRun { start, end: i });
                start = i;
            }

            i += 1;
        }

        Ok(())
    }

    async fn flush_prepared_pages_chained_with_runs(
        &self,
        pages: &[PreparedFlushPage],
        runs: &mut Vec<PreparedRun>,
    ) -> Result<usize, CacheError<B::Error>> {
        if pages.is_empty() {
            return Ok(0);
        }

        Self::collect_prepared_runs_into(pages, runs)?;

        let mut total_flushed = 0usize;
        let mut run_base = 0usize;

        while run_base < runs.len() {
            let run_end = min(run_base + MAX_WRITE_CHAIN, runs.len());
            let chain_runs = &runs[run_base..run_end];

            let first_run = &chain_runs[0];
            let first_page = &pages[first_run.start];
            let first_blocks = first_run.end - first_run.start;
            let first_len = first_blocks
                .checked_mul(BLOCK_SIZE)
                .ok_or(CacheError::OffsetOverflow)?;

            let first_buffer = self.create_cache_to_device_buffer(&first_page.page, first_len)?;

            let mut req = RequestHandle::new(Write {
                offset: first_page.lba * BLOCK_SIZE as u64,
                len: first_len,
                no_buffer: false,
                owner: first_page.page.owner.load(Ordering::Acquire),
                buffer: Some(first_buffer),
                next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            });

            let mut extra_writes = Vec::new();

            if chain_runs.len() > 1 {
                extra_writes
                    .try_reserve_exact(chain_runs.len() - 1)
                    .map_err(|_| CacheError::InsufficientResources)?;
            }

            {
                let mut req_write = req.write();
                let mut prev_write_ptr: *mut Write<'_> = &mut req_write.body;

                let mut chain_idx = 1usize;
                while chain_idx < chain_runs.len() {
                    let run = &chain_runs[chain_idx];
                    let page = &pages[run.start];
                    let blocks = run.end - run.start;
                    let byte_len = blocks
                        .checked_mul(BLOCK_SIZE)
                        .ok_or(CacheError::OffsetOverflow)?;

                    let buffer = self.create_cache_to_device_buffer(&page.page, byte_len)?;

                    extra_writes.push(Write {
                        offset: page.lba * BLOCK_SIZE as u64,
                        len: byte_len,
                        no_buffer: false,
                        owner: page.page.owner.load(Ordering::Acquire),
                        buffer: Some(buffer),
                        next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    });

                    let curr_ptr = extra_writes.last_mut().unwrap() as *mut Write<'_>;

                    unsafe {
                        (*prev_write_ptr)
                            .next
                            .store(curr_ptr, core::sync::atomic::Ordering::Release);
                    }

                    prev_write_ptr = curr_ptr;
                    chain_idx += 1;
                }
            }

            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = self.backend.write_request(&mut req).await;

            drop(req);
            drop(extra_writes);

            let page_start = chain_runs[0].start;
            let page_end = chain_runs[chain_runs.len() - 1].end;
            let flushed_pages = &pages[page_start..page_end];

            match status {
                Ok(()) => {
                    self.stats
                        .backend_writes
                        .fetch_add(flushed_pages.len() as u64, Ordering::Relaxed);
                    self.finish_prepared_flush_pages(flushed_pages, true);
                    total_flushed += flushed_pages.len();
                }
                Err(err) => {
                    cold_path();
                    self.finish_prepared_flush_pages(flushed_pages, false);
                    return Err(CacheError::Backend(err));
                }
            }

            run_base = run_end;
        }

        Ok(total_flushed)
    }

    fn page_for_flush_key(&self, lba: u64, filter: &FlushFilter<'_>) -> Option<Arc<CachePage>> {
        let shard_idx = self.shard_index(lba);
        let shard = self.shards[shard_idx].lock();
        let page: &Arc<CachePage> = shard.index.peek(&lba)?;

        if likely(page.dirty.load(Ordering::Acquire) && filter.matches(lba, page)) {
            Some(Arc::clone(page))
        } else {
            cold_path();
            None
        }
    }

    async fn flush_sorted_candidate_keys_batched(
        &self,
        filter: &FlushFilter<'_>,
        keys: &[u64],
    ) -> Result<usize, CacheError<B::Error>> {
        if unlikely(keys.is_empty()) {
            cold_path();
            return Ok(0);
        }

        let (mut prepared, mut runs) = {
            let mut scratch = self.flush_scratch.lock();
            let prepared = core::mem::take(&mut scratch.prepared);
            let runs = core::mem::take(&mut scratch.runs);
            (prepared, runs)
        };

        prepared.clear();
        runs.clear();

        let result = if prepared.capacity() < keys.len() {
            cold_path();
            Err(CacheError::InsufficientResources)
        } else {
            for lba in keys {
                let Some(page) = self.page_for_flush_key(*lba, filter) else {
                    continue;
                };

                if let Some(page) = Self::prepare_flush_page(&self.stats, *lba, page) {
                    prepared.push(page);
                }
            }

            self.flush_prepared_pages_chained_with_runs(&prepared, &mut runs)
                .await
        };

        prepared.clear();
        runs.clear();

        {
            let mut scratch = self.flush_scratch.lock();

            if scratch.prepared.capacity() < prepared.capacity() {
                scratch.prepared = prepared;
            }

            if scratch.runs.capacity() < runs.capacity() {
                scratch.runs = runs;
            }
        }

        result
    }

    async fn flush_filtered_batched(
        &self,
        filter: &FlushFilter<'_>,
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
                if page.dirty.load(Ordering::Acquire) && filter.matches(lba, page) {
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

    fn filtered_writeback_state(&self, filter: &FlushFilter<'_>) -> FilteredWritebackState {
        let mut has_dirty = false;
        let mut has_active_writeback = false;
        let mut shard_idx = 0usize;

        while shard_idx < self.shards.len() {
            let shard = self.shards[shard_idx].lock();

            shard.index.for_each(|lba, page| {
                if page.dirty.load(Ordering::Acquire) && filter.matches(lba, page) {
                    has_dirty = true;
                    if page.writeback.load(Ordering::Acquire) {
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

    fn wait_for_writeback_progress<'cache, 'filter, 'range>(
        &'cache self,
        filter: &'filter FlushFilter<'range>,
    ) -> WritebackProgressWait<'cache, 'filter, 'range, B, BLOCK_SIZE, F> {
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
        filter: &FlushFilter<'_>,
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
        filter: &FlushFilter<'_>,
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

    async fn flush_internal_range_to_backend(
        &self,
        block_range: Range<u64>,
    ) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::BlockRange(&block_range), false)
            .await
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
            if unlikely(dirty_before == 0) {
                cold_path();
                break;
            }

            if dirty_before < self.cfg.dirty_high_watermark_blocks {
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

            if dirty_after <= self.cfg.dirty_low_watermark_blocks
                && !self.should_start_background_writeback()
            {
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

    async fn invalidate_blocks_after_flush(
        &self,
        block_range: Range<u64>,
    ) -> Result<usize, CacheError<B::Error>> {
        self.flush_internal_range_to_backend(block_range.clone())
            .await?;

        let mut removed = 0usize;
        let mut shard_idx = 0usize;

        while shard_idx < self.shards.len() {
            loop {
                let remove_key = {
                    let shard = self.shards[shard_idx].lock();
                    let mut found = None;

                    shard.index.for_each(|k, page| {
                        if found.is_none()
                            && k >= block_range.start
                            && k < block_range.end
                            && Self::page_can_be_reclaimed(page)
                        {
                            found = Some(k);
                        }
                    });

                    found
                };

                let Some(key) = remove_key else {
                    break;
                };

                let mut shard = self.shards[shard_idx].lock();

                if let Some(page) = shard.index.remove(&key) {
                    self.recycle_or_drop_page(page);
                    removed += 1;
                }
            }

            shard_idx += 1;
        }

        Ok(removed)
    }

    pub async fn close_and_flush(&self) -> Result<(), CacheError<B::Error>> {
        self.flush_until_clean().await?;
        self.closed.store(true, Ordering::Release);
        Ok(())
    }

    pub fn prefetch_range(self: &Arc<Self>, offset: u64, len: usize) {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return;
        }

        let range = match Self::block_range_from_bytes(offset, len) {
            Ok(r) => r,
            Err(_) => {
                cold_path();
                return;
            }
        };

        if unlikely(!self.cfg.read_allocate) {
            cold_path();
            return;
        }

        let cache = Arc::clone(self);

        spawn_detached(async move {
            let mut lba = range.start;

            while lba < range.end {
                if cache.try_get_page(lba).await.is_none() {
                    match cache.load_cache_page_from_backend(lba).await {
                        Ok(page) => {
                            let _ = cache.insert_page_or_get_existing(lba, page).await;
                        }
                        Err(err) => {
                            cold_path();
                            println!(
                                "volmgr: VolumeCache::prefetch_range failed at lba {}: {:?}",
                                lba, err
                            );
                        }
                    }
                }

                lba += 1;
            }
        });
    }

    async fn write_at_inner(
        cache: &Arc<Self>,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        cache.check_open()?;
        let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, data.len())?;

        if unlikely(data.is_empty()) {
            cold_path();
            return Ok(());
        }

        let mut src_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = VolumeCache::<B, BLOCK_SIZE, F>::block_size_u64();
        let mut no_free_flush_started = false;

        while src_pos < data.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, data.len() - src_pos);

            let acquired = match cache
                .get_or_create_write_page(lba, block_off, take, &data[src_pos..src_pos + take])
                .await
            {
                Ok(acquired) => acquired,
                Err(CacheError::NoFreePages) if cache.cfg.direct_io_on_no_free_pages => {
                    cold_path();

                    if !no_free_flush_started {
                        Self::maybe_start_background_writeback(cache);
                        no_free_flush_started = true;
                    }

                    cache
                        .direct_write_at(cur_off, &data[src_pos..src_pos + take], owner)
                        .await?;

                    src_pos += take;
                    cur_off += take as u64;
                    continue;
                }
                Err(err) => {
                    cold_path();
                    return Err(err);
                }
            };

            match acquired {
                WriteAcquire::Cached(page) => {
                    while page.writeback.load(Ordering::Acquire) {
                        match cache.wait_for_writeback_progress(&FlushFilter::All).await {
                            WritebackWaitResult::Clean | WritebackWaitResult::NeedsFlush => break,
                        }
                    }

                    {
                        let _guard = page.data_lock.write();
                        unsafe {
                            cache.page_slice_mut(&page)[block_off..block_off + take]
                                .copy_from_slice(&data[src_pos..src_pos + take]);
                        }
                    }

                    cache.mark_cached_page_dirty(&page, owner);
                }
                WriteAcquire::Direct => {
                    cold_path();

                    cache
                        .direct_write_at(cur_off, &data[src_pos..src_pos + take], owner)
                        .await?;
                }
            }

            src_pos += take;
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

            deallocate_kernel_range(self.cache_base, self.cache_bytes as u64);
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

    async fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<(), Self::Error> {
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

    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
        VolumeCache::<B, BLOCK_SIZE, F>::write_at_inner(self, offset, data, 0).await?;
        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self);
        Ok(())
    }

    async fn write_at_owned(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), Self::Error> {
        VolumeCache::<B, BLOCK_SIZE, F>::write_at_inner(self, offset, data, owner).await?;
        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self);
        Ok(())
    }

    async fn write_through_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
        VolumeCache::<B, BLOCK_SIZE, F>::write_at_inner(self, offset, data, 0).await?;
        let block_range =
            VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, data.len())?;
        self.flush_internal_range_to_backend(block_range).await
    }

    async fn write_through_at_owned(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), Self::Error> {
        VolumeCache::<B, BLOCK_SIZE, F>::write_at_inner(self, offset, data, owner).await?;
        let block_range =
            VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, data.len())?;
        self.flush_internal_range_to_backend(block_range).await
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        self.flush_internal_all().await
    }

    async fn flush_owner(&self, owner: u64) -> Result<(), Self::Error> {
        self.flush_internal_owner_to_backend(owner).await
    }

    async fn flush_range(&self, offset: u64, len: usize) -> Result<(), Self::Error> {
        let block_range = VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
        self.flush_internal_range_to_backend(block_range).await
    }

    async fn invalidate_range(&self, offset: u64, len: usize) -> Result<usize, Self::Error> {
        let block_range = VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
        self.invalidate_blocks_after_flush(block_range).await
    }

    async fn drop_clean(&self) -> Result<usize, Self::Error> {
        self.check_open()?;

        let mut removed = 0usize;
        let mut shard_idx = 0usize;

        while shard_idx < self.shards.len() {
            loop {
                let remove_key = {
                    let shard = self.shards[shard_idx].lock();
                    let mut found = None;

                    shard.index.for_each(|k, page| {
                        if found.is_none()
                            && VolumeCache::<B, BLOCK_SIZE, F>::page_can_be_reclaimed(page)
                        {
                            found = Some(k);
                        }
                    });

                    found
                };

                let Some(key) = remove_key else {
                    break;
                };

                let mut shard = self.shards[shard_idx].lock();

                if let Some(page) = shard.index.remove(&key) {
                    self.recycle_or_drop_page(page);
                    removed += 1;
                    self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }

            shard_idx += 1;
        }

        Ok(removed)
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

    async fn flush_async(&self) {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return;
        }

        let _ = self.flush_internal_all().await;
    }

    async fn stats(&self) -> CacheStats {
        self.stats.snapshot()
    }

    async fn cached_blocks(&self) -> usize {
        let mut total = 0usize;
        let mut i = 0usize;

        while i < self.shards.len() {
            let shard = self.shards[i].lock();
            total += shard.index.len();
            i += 1;
        }

        total
    }
}
