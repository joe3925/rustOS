use super::cache::{
    CacheConfig, CacheError, CacheIndex, CacheIndexFactory, CacheStats, DefaultIndexFactory,
    VolumeCacheBackend, VolumeCacheOps,
};
use crate::alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cmp::min;
use core::marker::PhantomData;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use futures::future::{FutureExt as FuturesFutureExt, Shared};
use kernel_api::async_ffi::FfiFuture;
use kernel_api::kernel_types::dma::{Described, IoBuffer, ToDevice};
use kernel_api::kernel_types::request::RequestData;
use kernel_api::println;
use kernel_api::request::{BorrowedHandle, RequestHandle, RequestType, TraversalPolicy};
use kernel_api::runtime::spawn;
use kernel_api::runtime::spawn_detached;
use spin::{Mutex, RwLock};
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

struct PageBuf<const BLOCK_SIZE: usize> {
    bytes: Box<[u8; BLOCK_SIZE]>,
}

impl<const BLOCK_SIZE: usize> PageBuf<BLOCK_SIZE> {
    fn zeroed() -> Self {
        Self {
            bytes: Box::new([0u8; BLOCK_SIZE]),
        }
    }
}

struct Page<const BLOCK_SIZE: usize> {
    data: RwLock<PageBuf<BLOCK_SIZE>>,
    dirty: AtomicBool,
    writeback: AtomicBool,
    generation: AtomicU64,
    wb_generation: AtomicU64,
    active_ops: AtomicUsize,
    /// File-level owner tag. 0 = unowned (included in all targeted flushes).
    owner: AtomicU64,
}

impl<const BLOCK_SIZE: usize> Page<BLOCK_SIZE> {
    fn new_zeroed() -> Self {
        Self {
            data: RwLock::new(PageBuf::zeroed()),
            dirty: AtomicBool::new(false),
            writeback: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            wb_generation: AtomicU64::new(0),
            active_ops: AtomicUsize::new(0),
            owner: AtomicU64::new(0),
        }
    }

    fn mark_dirty(&self) -> bool {
        self.owner.store(0, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        !self.dirty.swap(true, Ordering::AcqRel)
    }

    fn mark_dirty_with_owner(&self, owner: u64) -> bool {
        self.owner.store(owner, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        !self.dirty.swap(true, Ordering::AcqRel)
    }

    fn enter_use(&self) {
        self.active_ops.fetch_add(1, Ordering::AcqRel);
    }

    fn leave_use(&self) {
        self.active_ops.fetch_sub(1, Ordering::AcqRel);
    }

    fn reset_for_reuse(&self) {
        self.dirty.store(false, Ordering::Release);
        self.writeback.store(false, Ordering::Release);
        self.generation.store(0, Ordering::Release);
        self.wb_generation.store(0, Ordering::Release);
        self.active_ops.store(0, Ordering::Release);
        self.owner.store(0, Ordering::Release);
    }

    fn is_evictable(&self) -> bool {
        !self.dirty.load(Ordering::Acquire)
            && !self.writeback.load(Ordering::Acquire)
            && self.active_ops.load(Ordering::Acquire) == 0
    }
}

struct PageUseGuard<'a, const BLOCK_SIZE: usize> {
    page: &'a Page<BLOCK_SIZE>,
}

impl<'a, const BLOCK_SIZE: usize> PageUseGuard<'a, BLOCK_SIZE> {
    fn new(page: &'a Page<BLOCK_SIZE>) -> Self {
        page.enter_use();
        Self { page }
    }
}

impl<'a, const BLOCK_SIZE: usize> Drop for PageUseGuard<'a, BLOCK_SIZE> {
    fn drop(&mut self) {
        self.page.leave_use();
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

struct PagePool<const BLOCK_SIZE: usize> {
    free: Mutex<Vec<Arc<Page<BLOCK_SIZE>>>>,
}

impl<const BLOCK_SIZE: usize> PagePool<BLOCK_SIZE> {
    fn new(capacity: usize) -> Self {
        let mut free = Vec::with_capacity(capacity);
        let mut i = 0usize;
        while i < capacity {
            free.push(Arc::new(Page::new_zeroed()));
            i += 1;
        }

        Self {
            free: Mutex::new(free),
        }
    }

    fn pop(&self) -> Option<Arc<Page<BLOCK_SIZE>>> {
        self.free.lock().pop()
    }

    fn push(&self, mut page: Arc<Page<BLOCK_SIZE>>) {
        if let Some(inner) = Arc::get_mut(&mut page) {
            inner.reset_for_reuse();
            self.free.lock().push(page);
        }
    }
}

enum WriteAcquire<const BLOCK_SIZE: usize> {
    Cached(Arc<Page<BLOCK_SIZE>>),
    Direct(Arc<Page<BLOCK_SIZE>>),
}

/// Filter predicate for flush operations.
enum FlushFilter<'a> {
    /// Flush all dirty pages.
    All,
    /// Flush dirty pages within a block range.
    BlockRange(&'a Range<u64>),
    /// Flush dirty pages belonging to the given owner.
    Owner(u64),
}

impl FlushFilter<'_> {
    #[inline]
    fn matches<const BLOCK_SIZE: usize>(&self, lba: u64, page: &Page<BLOCK_SIZE>) -> bool {
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

struct FlushScratch<const BLOCK_SIZE: usize> {
    batch: Vec<(u64, Arc<Page<BLOCK_SIZE>>)>,
    joins: Vec<FfiFuture<()>>,
}

impl<const BLOCK_SIZE: usize> FlushScratch<BLOCK_SIZE> {
    fn new(join_cap: usize) -> Self {
        let capacity = if join_cap == 0 { 1 } else { join_cap };
        Self {
            batch: Vec::new(),
            joins: Vec::with_capacity(capacity),
        }
    }

    fn reset(&mut self) {
        self.batch.clear();
        self.joins.clear();
    }

    fn ensure_join_capacity(&mut self, requested: usize) {
        let target = if requested == 0 { 1 } else { requested };
        if self.joins.capacity() < target {
            self.joins.reserve(target - self.joins.capacity());
        }
    }
}

pub(crate) struct FlushJobHandle<E> {
    id: u64,
    future: Shared<FfiFuture<()>>,
    result: Arc<Mutex<Option<Result<(), CacheError<E>>>>>,
}

// pooled page vectors removed; streaming batching used instead.

pub struct VolumeCache<B, const BLOCK_SIZE: usize, F = DefaultIndexFactory>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<Page<BLOCK_SIZE>>>,
{
    backend: Arc<B>,
    shards: Vec<Mutex<Shard<F::Index>>>,
    page_pool: Option<PagePool<BLOCK_SIZE>>,
    cfg: CacheConfig,
    stats: Arc<StatsInner>,
    dirty_pages: Arc<AtomicUsize>,
    background_writeback_active: AtomicBool,
    closed: AtomicBool,
    flush_job: Mutex<Option<Arc<FlushJobHandle<B::Error>>>>,
    flush_job_id: AtomicU64,
    flush_scratch: Mutex<FlushScratch<BLOCK_SIZE>>,
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
    F: CacheIndexFactory<Arc<Page<BLOCK_SIZE>>>,
{
    pub fn new_with_index(
        backend: Arc<B>,
        mut cfg: CacheConfig,
        factory: F,
    ) -> Result<Self, CacheError<B::Error>> {
        if BLOCK_SIZE == 0 || cfg.capacity_blocks == 0 {
            return Err(CacheError::InvalidConfig);
        }

        if cfg.shards == 0 {
            cfg.shards = 1;
        }

        if cfg.flush_parallelism == 0 {
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

        let shard_count = cfg.shards;
        let per_shard = (cfg.capacity_blocks + shard_count - 1) / shard_count;
        let mut shards = Vec::with_capacity(shard_count);

        let mut i = 0usize;
        while i < shard_count {
            let mut index = factory.build(per_shard);
            if !cfg.lazy_index_allocation {
                index.reserve_or_panic(per_shard);
            }
            shards.push(Mutex::new(Shard::new(index, per_shard)));
            i += 1;
        }

        let page_pool = if cfg.lazy_page_allocation {
            None
        } else {
            Some(PagePool::new(cfg.capacity_blocks))
        };

        Ok(Self {
            backend,
            shards,
            page_pool,
            cfg,
            stats: Arc::new(StatsInner::new()),
            dirty_pages: Arc::new(AtomicUsize::new(0)),
            background_writeback_active: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            flush_job: Mutex::new(None),
            flush_job_id: AtomicU64::new(0),
            flush_scratch: Mutex::new(FlushScratch::new(cfg.flush_parallelism)),
            _index_factory: PhantomData,
        })
    }

    fn block_size_u64() -> u64 {
        BLOCK_SIZE as u64
    }

    fn check_open(&self) -> Result<(), CacheError<B::Error>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CacheError::Closed);
        }
        Ok(())
    }

    fn mark_cached_page_dirty(&self, page: &Page<BLOCK_SIZE>, owner: u64) {
        let became_dirty = if owner == 0 {
            page.mark_dirty()
        } else {
            page.mark_dirty_with_owner(owner)
        };

        if became_dirty {
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

    async fn try_get_page(&self, lba: u64) -> Option<Arc<Page<BLOCK_SIZE>>> {
        let idx = self.shard_index(lba);
        let mut shard = self.shards[idx].lock();
        shard.index.get(&lba).map(|page| Arc::clone(&*page))
    }

    fn page_can_be_reclaimed(page: &Arc<Page<BLOCK_SIZE>>) -> bool {
        page.is_evictable() && Arc::strong_count(page) == 1
    }

    fn page_can_be_flushed_for_reclaim(page: &Arc<Page<BLOCK_SIZE>>) -> bool {
        page.dirty.load(Ordering::Acquire)
            && !page.writeback.load(Ordering::Acquire)
            && page.active_ops.load(Ordering::Acquire) == 0
    }

    fn recycle_or_drop_page(&self, page: Arc<Page<BLOCK_SIZE>>) {
        if let Some(pool) = &self.page_pool {
            pool.push(page);
        }
    }

    /// Reclaims clean pages using the shard's least-recently-used clean page.
    fn reclaim_page_from_shard_locked(
        &self,
        shard: &mut Shard<F::Index>,
    ) -> Option<Arc<Page<BLOCK_SIZE>>> {
        let reclaim_key = shard
            .index
            .oldest_matching(|_, page| Self::page_can_be_reclaimed(page));

        if reclaim_key.is_none() && shard.index.len() != 0 {
            self.stats.failed_evictions.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(lba) = reclaim_key {
            let Some(mut page) = shard.index.remove(&lba) else {
                return None;
            };
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
            if let Some(inner) = Arc::get_mut(&mut page) {
                inner.reset_for_reuse();
                return Some(page);
            }
        }

        None
    }

    fn try_reclaim_cache_page(&self, preferred_idx: usize) -> Option<Arc<Page<BLOCK_SIZE>>> {
        // The cache is sharded, so eviction is approximate LRU: prefer the
        // target shard's oldest clean page, then fall back to other shards.
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
    ) -> Option<(u64, Arc<Page<BLOCK_SIZE>>)> {
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
    ) -> Option<(u64, Arc<Page<BLOCK_SIZE>>)> {
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

        Self::flush_page_task(
            Arc::clone(&self.backend),
            Arc::clone(&self.stats),
            Arc::clone(&self.dirty_pages),
            lba,
            page,
        )
        .await?;

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

    async fn acquire_cache_page(
        &self,
        lba: u64,
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        if self.cfg.lazy_page_allocation {
            return Ok(Arc::new(Page::new_zeroed()));
        }

        if let Some(pool) = &self.page_pool {
            if let Some(mut page) = pool.pop() {
                if let Some(inner) = Arc::get_mut(&mut page) {
                    inner.reset_for_reuse();
                    return Ok(page);
                }
            }
        }

        let preferred_idx = self.shard_index(lba);
        if let Some(page) = self.try_reclaim_cache_page(preferred_idx) {
            return Ok(page);
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
                return Ok(page);
            }

            attempts -= 1;
        }

        Err(CacheError::NoFreePages)
    }

    async fn insert_page_or_get_existing(
        &self,
        lba: u64,
        page: Arc<Page<BLOCK_SIZE>>,
    ) -> Arc<Page<BLOCK_SIZE>> {
        let idx = self.shard_index(lba);
        let mut shard = self.shards[idx].lock();

        if let Some(existing) = shard.index.get(&lba) {
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

    async fn read_block_into_unique_page(
        &self,
        lba: u64,
        page: &mut Arc<Page<BLOCK_SIZE>>,
    ) -> Result<(), CacheError<B::Error>> {
        let page = Arc::get_mut(page).ok_or(CacheError::NoFreePages)?;
        let data = page.data.get_mut();
        self.backend
            .read_block(lba, &mut data.bytes[..])
            .await
            .map_err(CacheError::Backend)?;

        self.stats.backend_reads.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn load_detached_page_from_backend(
        &self,
        lba: u64,
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        let mut page = Arc::new(Page::new_zeroed());
        self.read_block_into_unique_page(lba, &mut page).await?;
        Ok(page)
    }

    async fn load_cache_page_from_backend(
        &self,
        lba: u64,
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        let mut page = self.acquire_cache_page(lba).await?;
        match self.read_block_into_unique_page(lba, &mut page).await {
            Ok(()) => Ok(page),
            Err(e) => {
                self.recycle_or_drop_page(page);
                Err(e)
            }
        }
    }

    fn fill_unique_page_from_full_block_write(
        page: &mut Arc<Page<BLOCK_SIZE>>,
        src: &[u8],
    ) -> Result<(), CacheError<B::Error>> {
        let page = Arc::get_mut(page).ok_or(CacheError::NoFreePages)?;
        let data = page.data.get_mut();
        data.bytes[..].copy_from_slice(src);
        Ok(())
    }

    async fn new_cache_page_from_full_block_write(
        &self,
        lba: u64,
        src: &[u8],
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        let mut page = self.acquire_cache_page(lba).await?;
        if let Err(e) = Self::fill_unique_page_from_full_block_write(&mut page, src) {
            self.recycle_or_drop_page(page);
            return Err(e);
        }
        Ok(page)
    }

    fn new_detached_page_from_full_block_write(
        &self,
        src: &[u8],
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        let mut page = Arc::new(Page::new_zeroed());
        Self::fill_unique_page_from_full_block_write(&mut page, src)?;
        Ok(page)
    }

    async fn get_or_create_read_page(
        &self,
        lba: u64,
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        if let Some(page) = self.try_get_page(lba).await {
            self.stats.read_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(page);
        }

        self.stats.read_misses.fetch_add(1, Ordering::Relaxed);

        if !self.cfg.read_allocate {
            return self.load_detached_page_from_backend(lba).await;
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
    ) -> Result<WriteAcquire<BLOCK_SIZE>, CacheError<B::Error>> {
        if let Some(page) = self.try_get_page(lba).await {
            self.stats.write_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(WriteAcquire::Cached(page));
        }

        self.stats.write_misses.fetch_add(1, Ordering::Relaxed);

        let is_full_block = block_off == 0 && write_len == BLOCK_SIZE;

        if self.cfg.write_allocate {
            if is_full_block {
                let page = self
                    .new_cache_page_from_full_block_write(lba, src_for_full)
                    .await?;
                let page = self.insert_page_or_get_existing(lba, page).await;
                return Ok(WriteAcquire::Cached(page));
            }

            let page = self.load_cache_page_from_backend(lba).await?;
            let page = self.insert_page_or_get_existing(lba, page).await;
            return Ok(WriteAcquire::Cached(page));
        }

        if is_full_block {
            let page = self.new_detached_page_from_full_block_write(src_for_full)?;
            return Ok(WriteAcquire::Direct(page));
        }

        let page = self.load_detached_page_from_backend(lba).await?;
        Ok(WriteAcquire::Direct(page))
    }

    async fn direct_write_page(
        &self,
        lba: u64,
        page: &Arc<Page<BLOCK_SIZE>>,
    ) -> Result<(), CacheError<B::Error>> {
        let mut req = RequestHandle::new(
            RequestType::Write {
                offset: lba * BLOCK_SIZE as u64,
                len: BLOCK_SIZE,
                flush_write_through: false,
                owner: 0,
            },
            RequestData::empty(),
        );
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        {
            let data_guard = page.data.read();
            let io_buf = IoBuffer::<Described, ToDevice>::new(&data_guard.bytes[..]);
            let mut borrow = BorrowedHandle::read_only(&mut req, &io_buf);
            self.backend
                .write_request(borrow.handle())
                .await
                .map_err(CacheError::Backend)?;
        }

        self.stats.backend_writes.fetch_add(1, Ordering::Relaxed);
        self.stats.direct_writebacks.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    async fn flush_page_task(
        backend: Arc<B>,
        stats: Arc<StatsInner>,
        dirty_pages: Arc<AtomicUsize>,
        lba: u64,
        page: Arc<Page<BLOCK_SIZE>>,
    ) -> Result<bool, CacheError<B::Error>> {
        stats.flush_attempts.fetch_add(1, Ordering::Relaxed);

        if !page.dirty.load(Ordering::Acquire) {
            stats.flush_skipped_clean.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        if page.writeback.swap(true, Ordering::AcqRel) {
            stats.flush_skipped_busy.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        if !page.dirty.load(Ordering::Acquire) {
            page.writeback.store(false, Ordering::Release);
            stats.flush_skipped_clean.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        let wb_gen = page.generation.load(Ordering::Acquire);
        page.wb_generation.store(wb_gen, Ordering::Release);

        let mut req = RequestHandle::new(
            RequestType::Write {
                offset: lba * BLOCK_SIZE as u64,
                len: BLOCK_SIZE,
                flush_write_through: false,
                owner: 0,
            },
            RequestData::empty(),
        );
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        let write_res = {
            let data_guard = page.data.read();
            let io_buf = IoBuffer::<Described, ToDevice>::new(&data_guard.bytes[..]);
            let mut borrow = BorrowedHandle::read_only(&mut req, &io_buf);
            backend
                .write_request(borrow.handle())
                .await
                .map_err(CacheError::Backend)
        };

        match write_res {
            Ok(()) => {
                stats.backend_writes.fetch_add(1, Ordering::Relaxed);
                let cur_gen = page.generation.load(Ordering::Acquire);
                if cur_gen == wb_gen {
                    if page.dirty.swap(false, Ordering::AcqRel) {
                        dirty_pages.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                page.writeback.store(false, Ordering::Release);
                stats.flush_success.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(e) => {
                page.writeback.store(false, Ordering::Release);
                if !page.dirty.swap(true, Ordering::AcqRel) {
                    dirty_pages.fetch_add(1, Ordering::AcqRel);
                }
                Err(e)
            }
        }
    }

    /// Joins is a vector used to track in-flight flush task handles.
    async fn flush_pages_parallel(
        backend: Arc<B>,
        stats: Arc<StatsInner>,
        dirty_pages: Arc<AtomicUsize>,
        pages: &[(u64, Arc<Page<BLOCK_SIZE>>)],
        joins: &mut Vec<FfiFuture<()>>,
        parallelism: usize,
    ) -> Result<usize, CacheError<B::Error>> {
        if pages.is_empty() {
            return Ok(0);
        }

        joins.clear();
        let first_error = Mutex::new(None);
        let first_error_ptr = &first_error as *const _ as usize;
        let writebacks = AtomicUsize::new(0);
        let writebacks_ptr = &writebacks as *const _ as usize;
        let parallelism = parallelism.max(1);

        for (lba, page) in pages {
            let backend = Arc::clone(&backend);
            let stats = Arc::clone(&stats);
            let dirty_pages = Arc::clone(&dirty_pages);
            let page = Arc::clone(page);
            let lba = *lba;
            let first_error_ptr_copy = first_error_ptr;
            let writebacks_ptr_copy = writebacks_ptr;

            let handle = spawn(async move {
                match Self::flush_page_task(backend, stats, dirty_pages, lba, page).await {
                    Ok(true) => {
                        // SAFETY: We await all handles before returning from this function,
                        // guaranteeing that `writebacks` safely outlives this spawned task.
                        let writebacks_ref =
                            unsafe { &*(writebacks_ptr_copy as *const AtomicUsize) };
                        writebacks_ref.fetch_add(1, Ordering::AcqRel);
                    }
                    Ok(false) => {}
                    Err(err) => {
                        println!(
                            "volmgr: VolumeCache::flush_pages_parallel failed at lba {}: {:?}",
                            lba, err
                        );

                        // SAFETY: We await all handles before returning from this function,
                        // guaranteeing that `first_error` safely outlives this spawned task.
                        let first_error_ref = unsafe {
                            &*(first_error_ptr_copy as *const Mutex<Option<CacheError<B::Error>>>)
                        };
                        let mut slot = first_error_ref.lock();
                        if slot.is_none() {
                            *slot = Some(err);
                        }
                    }
                }
            });

            joins.push(handle);

            if joins.len() >= parallelism {
                for handle in joins.drain(..) {
                    handle.await;
                }
                if first_error.lock().is_some() {
                    break;
                }
            }
        }

        for handle in joins.drain(..) {
            handle.await;
        }

        if let Some(err) = first_error.into_inner() {
            return Err(err);
        }

        Ok(writebacks.into_inner())
    }
    async fn flush_shard_streaming(
        &self,
        shard_idx: usize,
        filter: &FlushFilter<'_>,
        parallelism: usize,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        let parallelism = parallelism.max(1);
        let mut start = 0usize;
        let mut matched = 0usize;
        let mut writebacks = 0usize;

        loop {
            let (walked, batch, mut joins) = {
                let mut scratch = self.flush_scratch.lock();
                scratch.reset();
                scratch.ensure_join_capacity(parallelism);
                let batch_capacity = scratch.batch.capacity();
                if batch_capacity < parallelism {
                    scratch.batch.reserve(parallelism - batch_capacity);
                }

                let walked = {
                    let shard = self.shards[shard_idx].lock();
                    shard.index.for_each_chunk(start, parallelism, |k, v| {
                        if v.dirty.load(Ordering::Acquire) && filter.matches(k, v) {
                            scratch.batch.push((k, Arc::clone(v)));
                        }
                    })
                };

                if walked == 0 {
                    return Ok((matched, writebacks));
                }

                let batch = core::mem::take(&mut scratch.batch);
                let joins = core::mem::take(&mut scratch.joins);
                (walked, batch, joins)
            };

            matched += batch.len();

            if !batch.is_empty() {
                writebacks += Self::flush_pages_parallel(
                    Arc::clone(&self.backend),
                    Arc::clone(&self.stats),
                    Arc::clone(&self.dirty_pages),
                    &batch,
                    &mut joins,
                    parallelism,
                )
                .await?;
            }

            {
                let mut scratch = self.flush_scratch.lock();
                scratch.batch = batch;
                scratch.joins = joins;
                scratch.reset();
            }

            start += walked;
        }
    }
    async fn flush_shards_streaming_all(
        self: &Arc<Self>,
        parallelism: usize,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        let mut shard_idx = 0usize;
        let mut matched = 0usize;
        let mut writebacks = 0usize;
        while shard_idx < self.shards.len() {
            let (shard_matched, shard_writebacks) = self
                .flush_shard_streaming(shard_idx, &FlushFilter::All, parallelism)
                .await?;
            matched += shard_matched;
            writebacks += shard_writebacks;
            shard_idx += 1;
        }
        Ok((matched, writebacks))
    }

    async fn has_dirty_pages_filtered(&self, filter: &FlushFilter<'_>) -> bool {
        let mut shard_idx = 0usize;
        while shard_idx < self.shards.len() {
            let shard = self.shards[shard_idx].lock();
            let mut found = false;
            shard.index.for_each(|lba, page| {
                if !found && page.dirty.load(Ordering::Acquire) && filter.matches(lba, page) {
                    found = true;
                }
            });
            if found {
                return true;
            }
            shard_idx += 1;
        }
        false
    }

    async fn flush_until_clean(&self) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::All, true)
            .await
    }

    async fn finish_flush_job(&self, id: u64) {
        let mut job = self.flush_job.lock();
        if job.as_ref().map(|h| h.id == id).unwrap_or(false) {
            job.take();
        }
    }

    pub(crate) async fn ensure_flush_job(self: &Arc<Self>) -> Arc<FlushJobHandle<B::Error>> {
        let mut job_guard = self.flush_job.lock();
        if let Some(handle) = job_guard.as_ref() {
            return Arc::clone(handle);
        }

        let id = self
            .flush_job_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);

        let result_slot = Arc::new(Mutex::new(None));
        let result_slot_clone = Arc::clone(&result_slot);
        let cache = Arc::clone(self);

        let job_future = spawn(async move {
            let outcome = cache.flush_until_clean().await;
            if let Err(err) = &outcome {
                println!(
                    "volmgr: VolumeCache::ensure_flush_job job {} failed: {:?}",
                    id, err
                );
            }
            {
                let mut slot = result_slot_clone.lock();
                *slot = Some(outcome);
            }
            cache.finish_flush_job(id).await;
        })
        .shared();

        let handle = Arc::new(FlushJobHandle {
            id,
            future: job_future.clone(),
            result: result_slot,
        });

        *job_guard = Some(Arc::clone(&handle));
        handle
    }

    pub(crate) async fn wait_for_flush_job(self: &Arc<Self>) -> Result<(), CacheError<B::Error>>
    where
        B::Error: Clone,
    {
        let handle = self.ensure_flush_job().await;
        handle.future.clone().await;
        handle.result.lock().as_ref().cloned().unwrap_or(Ok(()))
    }

    async fn flush_internal_filtered(
        &self,
        filter: &FlushFilter<'_>,
        force_device_flush: bool,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        self.check_open()?;
        let mut shard_idx = 0usize;
        let mut matched = 0usize;
        let mut writebacks = 0usize;
        while shard_idx < self.shards.len() {
            let (shard_matched, shard_writebacks) = self
                .flush_shard_streaming(shard_idx, filter, self.cfg.flush_parallelism)
                .await?;
            matched += shard_matched;
            writebacks += shard_writebacks;
            shard_idx += 1;
        }

        if force_device_flush || writebacks != 0 {
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
            self.flush_internal_filtered(filter, force_device_flush)
                .await?;
            if !self.has_dirty_pages_filtered(filter).await {
                break;
            }

            let dirty_after = self.dirty_pages.load(Ordering::Acquire);
            if dirty_after >= dirty_before {
                self.flush_internal_filtered(filter, force_device_flush)
                    .await?;
            }
        }

        Ok(())
    }

    async fn flush_internal_range(
        &self,
        block_range: Range<u64>,
    ) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::BlockRange(&block_range), true)
            .await
    }

    async fn flush_internal_all(&self) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::All, true)
            .await
    }

    async fn flush_internal_owner(&self, owner: u64) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::Owner(owner), true)
            .await
    }

    fn should_start_background_writeback(&self) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        let dirty = self.dirty_pages.load(Ordering::Acquire);
        if dirty == 0 {
            return false;
        }

        dirty >= self.cfg.dirty_high_watermark_blocks
    }

    async fn background_writeback_loop(&self) {
        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }

            let dirty_before = self.dirty_pages.load(Ordering::Acquire);
            if dirty_before == 0 {
                break;
            }

            let high = self.cfg.dirty_high_watermark_blocks;
            let low = self.cfg.dirty_low_watermark_blocks;

            let filter = if dirty_before >= high {
                FlushFilter::All
            } else {
                break;
            };

            let (matched, writebacks) = match self.flush_internal_filtered(&filter, false).await {
                Ok(pass) => pass,
                Err(err) => {
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

            if dirty_after <= low && !self.should_start_background_writeback() {
                break;
            }
        }
    }

    fn maybe_start_background_writeback(cache: &Arc<Self>) {
        if !cache.should_start_background_writeback() {
            return;
        }

        if cache
            .background_writeback_active
            .swap(true, Ordering::AcqRel)
        {
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
        if cache.closed.load(Ordering::Acquire) {
            return;
        }

        let cache = Arc::clone(cache);
        spawn_detached(async move {
            if let Err(err) = cache.flush_internal_owner(owner).await {
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
        self.flush_internal_range(block_range.clone()).await?;

        let mut removed = 0usize;
        let mut i = 0usize;

        while i < self.shards.len() {
            let mut shard = self.shards[i].lock();
            let mut keys = Vec::new();

            shard.index.for_each(|k, _| {
                if k >= block_range.start && k < block_range.end {
                    keys.push(k);
                }
            });

            let mut j = 0usize;
            while j < keys.len() {
                if let Some(page) = shard.index.peek(&keys[j]) {
                    if Self::page_can_be_reclaimed(page) {
                        if let Some(page) = shard.index.remove(&keys[j]) {
                            self.recycle_or_drop_page(page);
                        }
                        removed += 1;
                    }
                }
                j += 1;
            }

            i += 1;
        }

        Ok(removed)
    }

    pub async fn close_and_flush(&self) -> Result<(), CacheError<B::Error>> {
        self.flush_until_clean().await?;
        self.closed.store(true, Ordering::Release);
        Ok(())
    }

    pub fn prefetch_range(self: &Arc<Self>, offset: u64, len: usize) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }

        let range = match Self::block_range_from_bytes(offset, len) {
            Ok(r) => r,
            Err(_) => return,
        };

        if !self.cfg.read_allocate {
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

    /// Shared write implementation that optionally tags pages with an owner.
    async fn write_at_inner(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        self.check_open()?;
        let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, data.len())?;

        if data.is_empty() {
            return Ok(());
        }

        let mut src_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = VolumeCache::<B, BLOCK_SIZE, F>::block_size_u64();

        while src_pos < data.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, data.len() - src_pos);

            let acquired = self
                .get_or_create_write_page(lba, block_off, take, &data[src_pos..src_pos + take])
                .await?;

            match acquired {
                WriteAcquire::Cached(page) => {
                    let _use_guard = PageUseGuard::new(&page);

                    {
                        let mut page_data = page.data.write();
                        page_data.bytes[block_off..block_off + take]
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    }

                    self.mark_cached_page_dirty(&page, owner);
                }
                WriteAcquire::Direct(page) => {
                    {
                        let mut page_data = page.data.write();
                        page_data.bytes[block_off..block_off + take]
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    }

                    if owner == 0 {
                        page.mark_dirty();
                    } else {
                        page.mark_dirty_with_owner(owner);
                    }
                    self.direct_write_page(lba, &page).await?;
                }
            }

            src_pos += take;
            cur_off += take as u64;
        }

        Ok(())
    }
}

impl<B, const BLOCK_SIZE: usize, F> VolumeCacheOps for Arc<VolumeCache<B, BLOCK_SIZE, F>>
where
    B: VolumeCacheBackend,
    B::Error: Clone,
    F: CacheIndexFactory<Arc<Page<BLOCK_SIZE>>>,
{
    type Error = CacheError<B::Error>;

    async fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<(), Self::Error> {
        self.check_open()?;
        let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, out.len())?;

        if out.is_empty() {
            return Ok(());
        }

        let mut dst_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = VolumeCache::<B, BLOCK_SIZE, F>::block_size_u64();

        while dst_pos < out.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, out.len() - dst_pos);

            let page = self.get_or_create_read_page(lba).await?;
            let _use_guard = PageUseGuard::new(&page);

            {
                let data = page.data.read();
                out[dst_pos..dst_pos + take]
                    .copy_from_slice(&data.bytes[block_off..block_off + take]);
            }

            dst_pos += take;
            cur_off += take as u64;
        }

        Ok(())
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
        self.write_at_inner(offset, data, 0).await?;
        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self);
        Ok(())
    }

    async fn write_at_owned(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), Self::Error> {
        self.write_at_inner(offset, data, owner).await?;
        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self);
        Ok(())
    }

    async fn write_through_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
        self.write_at_inner(offset, data, 0).await?;
        self.flush_range(offset, data.len()).await
    }

    async fn write_through_at_owned(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), Self::Error> {
        self.write_at_inner(offset, data, owner).await?;
        self.flush_range(offset, data.len()).await
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        self.flush_internal_all().await
    }

    async fn flush_owner(&self, owner: u64) -> Result<(), Self::Error> {
        self.flush_internal_owner(owner).await
    }

    async fn flush_range(&self, offset: u64, len: usize) -> Result<(), Self::Error> {
        let block_range = VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
        self.flush_internal_range(block_range).await
    }

    async fn invalidate_range(&self, offset: u64, len: usize) -> Result<usize, Self::Error> {
        let block_range = VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
        self.invalidate_blocks_after_flush(block_range).await
    }

    async fn drop_clean(&self) -> Result<usize, Self::Error> {
        self.check_open()?;

        let mut removed = 0usize;
        let mut i = 0usize;

        while i < self.shards.len() {
            let mut shard = self.shards[i].lock();
            let mut keys = Vec::new();

            shard.index.for_each(|k, v| {
                if VolumeCache::<B, BLOCK_SIZE, F>::page_can_be_reclaimed(v) {
                    keys.push(k);
                }
            });

            let mut j = 0usize;
            while j < keys.len() {
                if let Some(page) = shard.index.remove(&keys[j]) {
                    self.recycle_or_drop_page(page);
                    removed += 1;
                    self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                }
                j += 1;
            }

            i += 1;
        }

        Ok(removed)
    }

    fn flush_background_pass(&self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }

        let cache = Arc::clone(self);
        spawn_detached(async move {
            let _ = cache.ensure_flush_job().await;
        });
    }
    async fn flush_async(&self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }

        let _ = self.ensure_flush_job().await;
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
