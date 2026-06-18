use crate::alloc::vec::Vec;
use crate::cache::{CacheIndex, CacheIndexFactory, DefaultIndexFactory};
use crate::cache_traits::{
    CacheConfig, CacheError, CacheStats, VolumeCacheBackend, VolumeCacheOps,
};
use alloc::sync::Arc;
use core::cmp::min;
use core::future::Future;
use core::hint::{cold_path, likely, unlikely};
use core::marker::PhantomData;
use core::ops::Range;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use futures::future::FutureExt as FuturesFutureExt;
use kernel_api::dma::dma_base_page_size;
use kernel_api::kernel_types::dma::{
    Described, FromDevice, IOBUFFER_INLINE_SEGMENT_CAPACITY, IoBuffer, ToDevice,
};
use kernel_api::println;
use kernel_api::request::{RequestHandle, TraversalPolicy, Write};
use kernel_api::runtime::spawn;
use kernel_api::runtime::spawn_detached;
use spin::Mutex;

use super::flush::{
    FlushFilter, FlushJobHandle, FlushRunScratchLease, FlushScratch, PreparedFlushPage,
};
use super::notify::WritebackNotifier;
use super::page::{Page, PagePool, PageUseGuard};

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

enum WriteAcquire<const BLOCK_SIZE: usize> {
    Cached(Arc<Page<BLOCK_SIZE>>),
    Direct(Arc<Page<BLOCK_SIZE>>),
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

struct WritebackProgressWait<'cache, 'filter, 'range, B, const BLOCK_SIZE: usize, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<Page<BLOCK_SIZE>>>,
{
    cache: &'cache VolumeCache<B, BLOCK_SIZE, F>,
    filter: &'filter FlushFilter<'range>,
}

impl<'cache, 'filter, 'range, B, const BLOCK_SIZE: usize, F> Future
    for WritebackProgressWait<'cache, 'filter, 'range, B, BLOCK_SIZE, F>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<Page<BLOCK_SIZE>>>,
{
    type Output = WritebackWaitResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let observed_epoch = this.cache.writeback_notifier.epoch();

        match this.cache.filtered_writeback_state(this.filter) {
            FilteredWritebackState::Clean => Poll::Ready(WritebackWaitResult::Clean),
            FilteredWritebackState::NeedsFlush => Poll::Ready(WritebackWaitResult::NeedsFlush),
            FilteredWritebackState::ActiveWriteback => {
                if this
                    .cache
                    .writeback_notifier
                    .register_if_unchanged(observed_epoch, cx.waker())
                {
                    Poll::Pending
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
}

pub(crate) struct VolumeCache<B, const BLOCK_SIZE: usize, F = DefaultIndexFactory>
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
    writeback_notifier: WritebackNotifier,
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
            Some(PagePool::new(cfg.capacity_blocks).ok_or(CacheError::InvalidIoBuffer)?)
        };

        Ok(Self {
            backend,
            shards,
            page_pool,
            cfg,
            stats: Arc::new(StatsInner::new()),
            dirty_pages: Arc::new(AtomicUsize::new(0)),
            writeback_notifier: WritebackNotifier::new(),
            background_writeback_active: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            flush_job: Mutex::new(None),
            flush_job_id: AtomicU64::new(0),
            flush_scratch: Mutex::new(FlushScratch::new(
                cfg.flush_parallelism,
                cfg.capacity_blocks,
            )),
            _index_factory: PhantomData,
        })
    }

    fn block_size_u64() -> u64 {
        BLOCK_SIZE as u64
    }

    fn check_open(&self) -> Result<(), CacheError<B::Error>> {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return Err(CacheError::Closed);
        }
        Ok(())
    }

    fn mark_cached_page_dirty(&self, _lba: u64, page: &Page<BLOCK_SIZE>, owner: u64) {
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

    fn start_flush_job_background(cache: &Arc<Self>) {
        if unlikely(cache.closed.load(Ordering::Acquire)) {
            cold_path();
            return;
        }

        let cache = Arc::clone(cache);
        spawn_detached(async move {
            let _ = cache.ensure_flush_job().await;
        });
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
            && Arc::strong_count(page) == 1
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

        let Some(prepared) = Self::prepare_flush_page(&self.stats, lba, page) else {
            return Ok(true);
        };

        let run = [prepared];
        Self::flush_prepared_run(
            &self.backend,
            &self.stats,
            &self.dirty_pages,
            &self.writeback_notifier,
            &run,
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
        if unlikely(self.cfg.lazy_page_allocation) {
            cold_path();
            return Ok(Arc::new(
                Page::new_zeroed().ok_or(CacheError::InvalidIoBuffer)?,
            ));
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

    async fn read_block_into_unique_page(
        &self,
        lba: u64,
        page: &mut Arc<Page<BLOCK_SIZE>>,
    ) -> Result<(), CacheError<B::Error>> {
        let page = Arc::get_mut(page).ok_or(CacheError::NoFreePages)?;
        let bytes_read = {
            let data = page.data.get_mut();
            let io_buf = IoBuffer::<Described, FromDevice>::from_slice_mut(&mut data.bytes[..]);
            self.backend
                .read_phys_framed(lba, 1, io_buf)
                .await
                .map_err(CacheError::Backend)?
        };
        if unlikely(bytes_read > BLOCK_SIZE) {
            cold_path();
            return Err(CacheError::InvalidIoBuffer);
        }
        if unlikely(bytes_read < BLOCK_SIZE) {
            cold_path();
            let data = page.data.get_mut();
            data.bytes[bytes_read..].fill(0);
        }

        self.stats.backend_reads.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn load_detached_page_from_backend(
        &self,
        lba: u64,
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        let mut page = Arc::new(Page::new_zeroed().ok_or(CacheError::InvalidIoBuffer)?);
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
        let mut page = Arc::new(Page::new_zeroed().ok_or(CacheError::InvalidIoBuffer)?);
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

        cold_path();
        self.stats.read_misses.fetch_add(1, Ordering::Relaxed);

        if unlikely(!self.cfg.read_allocate) {
            cold_path();
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

        cold_path();
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

    async fn direct_read_at(
        &self,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(out.is_empty()) {
            cold_path();
            return Ok(());
        }

        let mut dst_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = Self::block_size_u64();

        while dst_pos < out.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, out.len() - dst_pos);
            let page = self.load_detached_page_from_backend(lba).await?;

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

    async fn direct_write_at(
        &self,
        offset: u64,
        data: &[u8],
        _owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(data.is_empty()) {
            cold_path();
            return Ok(());
        }

        let mut src_pos = 0usize;
        let mut cur_off = offset;
        let bs_u64 = Self::block_size_u64();

        while src_pos < data.len() {
            let lba = cur_off / bs_u64;
            let block_off = (cur_off % bs_u64) as usize;
            let take = min(BLOCK_SIZE - block_off, data.len() - src_pos);
            let src = &data[src_pos..src_pos + take];

            if block_off == 0 && take == BLOCK_SIZE {
                let page = self.new_detached_page_from_full_block_write(src)?;
                self.direct_write_page(lba, &page).await?;
            } else {
                let page = self.load_detached_page_from_backend(lba).await?;
                {
                    let mut page_data = page.data.write();
                    page_data.bytes[block_off..block_off + take].copy_from_slice(src);
                }
                self.direct_write_page(lba, &page).await?;
            }

            src_pos += take;
            cur_off += take as u64;
        }

        Ok(())
    }

    async fn direct_write_page(
        &self,
        lba: u64,
        page: &Arc<Page<BLOCK_SIZE>>,
    ) -> Result<(), CacheError<B::Error>> {
        {
            let data_guard = page.data.read();
            let io_buf = IoBuffer::<Described, ToDevice>::from_slice(&data_guard.bytes[..]);
            let mut req = RequestHandle::new(Write {
                offset: lba * BLOCK_SIZE as u64,
                len: BLOCK_SIZE,
                no_buffer: false,
                owner: 0,
                buffer: io_buf,
            });
            req.set_traversal_policy(TraversalPolicy::ForwardLower);

            self.backend
                .write_request(&mut req)
                .await
                .map_err(CacheError::Backend)?;
        }

        self.stats.backend_writes.fetch_add(1, Ordering::Relaxed);
        self.stats.direct_writebacks.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn prepare_flush_page(
        stats: &StatsInner,
        lba: u64,
        page: Arc<Page<BLOCK_SIZE>>,
    ) -> Option<PreparedFlushPage<BLOCK_SIZE>> {
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
            page,
            wb_generation,
        })
    }

    fn finish_prepared_flush_pages(
        stats: &StatsInner,
        dirty_pages: &AtomicUsize,
        writeback_notifier: &WritebackNotifier,
        pages: &[PreparedFlushPage<BLOCK_SIZE>],
        success: bool,
    ) {
        let mut completed_writebacks = 0usize;

        for prepared in pages {
            if likely(success) {
                let cur_gen = prepared.page.generation.load(Ordering::Acquire);
                if cur_gen == prepared.wb_generation
                    && prepared.page.dirty.swap(false, Ordering::AcqRel)
                {
                    dirty_pages.fetch_sub(1, Ordering::AcqRel);
                }
                stats.flush_success.fetch_add(1, Ordering::Relaxed);
            } else if !prepared.page.dirty.swap(true, Ordering::AcqRel) {
                cold_path();
                dirty_pages.fetch_add(1, Ordering::AcqRel);
            }
            prepared.page.writeback.store(false, Ordering::Release);
            completed_writebacks += 1;
        }

        if completed_writebacks != 0 {
            writeback_notifier.notify_all();
        }
    }

    async fn flush_prepared_run(
        backend: &Arc<B>,
        stats: &Arc<StatsInner>,
        dirty_pages: &Arc<AtomicUsize>,
        writeback_notifier: &WritebackNotifier,
        run: &[PreparedFlushPage<BLOCK_SIZE>],
    ) -> Result<usize, CacheError<B::Error>> {
        // TODO: allow this to be configured
        const INLINE_RUNS: usize = 8;
        const INLINE_SEGMENTS: usize = INLINE_RUNS;

        let run_len = run.len();

        if run_len == 0 {
            return Ok(0);
        }

        if run_len.checked_mul(BLOCK_SIZE).is_none() {
            cold_path();
            Self::finish_prepared_flush_pages(stats, dirty_pages, writeback_notifier, run, false);
            return Err(CacheError::OffsetOverflow);
        }

        if run_len <= INLINE_RUNS && run_len <= INLINE_SEGMENTS {
            let mut read_guards = [const { None }; INLINE_RUNS];
            let mut segments: [&[u8]; INLINE_SEGMENTS] = [&[]; INLINE_SEGMENTS];

            for idx in 0..run_len {
                read_guards[idx] = Some(run[idx].page.data.read());
            }

            for idx in 0..run_len {
                let guard = unsafe { read_guards.get_unchecked(idx).as_ref().unwrap_unchecked() };

                segments[idx] = &guard.bytes[..];
            }

            let io_buf = match IoBuffer::<Described, ToDevice>::from_segments(&segments[..run_len])
            {
                Ok(io_buf) => io_buf,
                Err(_) => {
                    cold_path();
                    Self::finish_prepared_flush_pages(
                        stats,
                        dirty_pages,
                        writeback_notifier,
                        run,
                        false,
                    );
                    return Err(CacheError::InvalidIoBuffer);
                }
            };

            let write_res = backend
                .write_phys_framed(run[0].lba, run_len, io_buf)
                .await
                .map_err(CacheError::Backend);

            match write_res {
                Ok(()) => {
                    stats
                        .backend_writes
                        .fetch_add(run_len as u64, Ordering::Relaxed);
                    Self::finish_prepared_flush_pages(
                        stats,
                        dirty_pages,
                        writeback_notifier,
                        run,
                        true,
                    );
                    Ok(run_len)
                }
                Err(err) => {
                    cold_path();
                    Self::finish_prepared_flush_pages(
                        stats,
                        dirty_pages,
                        writeback_notifier,
                        run,
                        false,
                    );
                    Err(err)
                }
            }
        } else {
            let mut read_guards = Vec::with_capacity(run_len);

            for prepared in run {
                read_guards.push(prepared.page.data.read());
            }

            let mut segments = Vec::with_capacity(run_len);

            for guard in &read_guards {
                segments.push(&guard.bytes[..]);
            }

            let io_buf = match IoBuffer::<Described, ToDevice>::from_segments(&segments[..]) {
                Ok(io_buf) => io_buf,
                Err(_) => {
                    cold_path();
                    Self::finish_prepared_flush_pages(
                        stats,
                        dirty_pages,
                        writeback_notifier,
                        run,
                        false,
                    );
                    return Err(CacheError::InvalidIoBuffer);
                }
            };

            let write_res = backend
                .write_phys_framed(run[0].lba, run_len, io_buf)
                .await
                .map_err(CacheError::Backend);

            match write_res {
                Ok(()) => {
                    stats
                        .backend_writes
                        .fetch_add(run_len as u64, Ordering::Relaxed);
                    Self::finish_prepared_flush_pages(
                        stats,
                        dirty_pages,
                        writeback_notifier,
                        run,
                        true,
                    );
                    Ok(run_len)
                }
                Err(err) => {
                    cold_path();
                    Self::finish_prepared_flush_pages(
                        stats,
                        dirty_pages,
                        writeback_notifier,
                        run,
                        false,
                    );
                    Err(err)
                }
            }
        }
    }

    fn page_for_flush_key(
        &self,
        lba: u64,
        filter: &FlushFilter<'_>,
    ) -> Option<Arc<Page<BLOCK_SIZE>>> {
        let shard_idx = self.shard_index(lba);
        let shard = self.shards[shard_idx].lock();
        let page: &Arc<Page<BLOCK_SIZE>> = shard.index.peek(&lba)?;
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
        max_blocks_per_run: usize,
    ) -> Result<usize, CacheError<B::Error>> {
        if unlikely(keys.is_empty()) {
            cold_path();
            return Ok(0);
        }

        let max_blocks_per_buffer = self.max_blocks_per_flush_run(max_blocks_per_run);
        let run_capacity = max_blocks_per_buffer.min(keys.len());

        let mut run_scratch = FlushRunScratchLease::new(&self.flush_scratch);
        let run = run_scratch.run_mut();

        run.clear();
        if run.capacity() < run_capacity {
            run.reserve(run_capacity - run.capacity());
        }

        let mut writebacks = 0usize;
        let mut result = Ok(());

        for lba in keys {
            let contiguous = run
                .last()
                .map(|last| last.lba.checked_add(1) == Some(*lba))
                .unwrap_or(true);

            if !contiguous || run.len() >= max_blocks_per_buffer {
                match Self::flush_prepared_run(
                    &self.backend,
                    &self.stats,
                    &self.dirty_pages,
                    &self.writeback_notifier,
                    run.as_slice(),
                )
                .await
                {
                    Ok(flushed) => writebacks += flushed,
                    Err(err) => {
                        cold_path();
                        result = Err(err);
                        break;
                    }
                }

                run.clear();
            }

            if result.is_err() {
                cold_path();
                break;
            }

            let Some(page) = self.page_for_flush_key(*lba, filter) else {
                cold_path();

                if !run.is_empty() {
                    match Self::flush_prepared_run(
                        &self.backend,
                        &self.stats,
                        &self.dirty_pages,
                        &self.writeback_notifier,
                        run.as_slice(),
                    )
                    .await
                    {
                        Ok(flushed) => writebacks += flushed,
                        Err(err) => {
                            cold_path();
                            result = Err(err);
                            break;
                        }
                    }

                    run.clear();
                }

                continue;
            };

            if let Some(prepared) = Self::prepare_flush_page(&self.stats, *lba, page) {
                run.push(prepared);
            } else if !run.is_empty() {
                cold_path();

                match Self::flush_prepared_run(
                    &self.backend,
                    &self.stats,
                    &self.dirty_pages,
                    &self.writeback_notifier,
                    run.as_slice(),
                )
                .await
                {
                    Ok(flushed) => writebacks += flushed,
                    Err(err) => {
                        cold_path();
                        result = Err(err);
                        break;
                    }
                }

                run.clear();
            }
        }

        if result.is_ok() && !run.is_empty() {
            match Self::flush_prepared_run(
                &self.backend,
                &self.stats,
                &self.dirty_pages,
                &self.writeback_notifier,
                run.as_slice(),
            )
            .await
            {
                Ok(flushed) => writebacks += flushed,
                Err(err) => {
                    cold_path();
                    result = Err(err);
                }
            }
        }

        run.clear();

        result.map(|()| writebacks)
    }

    fn max_blocks_per_flush_run(&self, max_blocks_per_run: usize) -> usize {
        max_blocks_per_run
            .max(1)
            .min(self.cfg.capacity_blocks.saturating_sub(1).max(1))
            .min(Self::max_blocks_per_dma_request())
    }

    fn max_blocks_per_dma_request() -> usize {
        let dma_page_size = dma_base_page_size().max(1);
        let segments_per_block = BLOCK_SIZE.div_ceil(dma_page_size).max(1);
        IOBUFFER_INLINE_SEGMENT_CAPACITY
            .checked_div(segments_per_block)
            .unwrap_or(0)
            .max(1)
    }

    async fn flush_owner_streaming_batched(
        &self,
        owner: u64,
        max_blocks_per_run: usize,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        if unlikely(owner == 0) {
            cold_path();
            return Ok((0, 0));
        }

        let filter = FlushFilter::Owner(owner);
        let chunk_limit = self
            .max_blocks_per_flush_run(max_blocks_per_run)
            .max(self.cfg.flush_parallelism.max(1));

        let mut matched = 0usize;
        let mut writebacks = 0usize;
        let mut shard_idx = 0usize;

        while shard_idx < self.shards.len() {
            let mut start = 0usize;

            loop {
                let (walked, mut keys) = {
                    let mut scratch = self.flush_scratch.lock();
                    let mut keys = core::mem::take(&mut scratch.keys);

                    keys.clear();
                    if keys.capacity() < chunk_limit {
                        keys.reserve(chunk_limit - keys.capacity());
                    }

                    let walked = {
                        let shard = self.shards[shard_idx].lock();
                        shard.index.for_each_chunk(start, chunk_limit, |lba, page| {
                            if page.dirty.load(Ordering::Acquire) && filter.matches(lba, page) {
                                keys.push(lba);
                            }
                        })
                    };

                    (walked, keys)
                };

                if walked == 0 {
                    let mut scratch = self.flush_scratch.lock();
                    if scratch.keys.capacity() < keys.capacity() {
                        scratch.keys = keys;
                    }
                    break;
                }

                if !keys.is_empty() {
                    keys.sort_unstable();
                    matched += keys.len();
                    writebacks += self
                        .flush_sorted_candidate_keys_batched(&filter, &keys, max_blocks_per_run)
                        .await?;
                }

                {
                    let mut scratch = self.flush_scratch.lock();
                    keys.clear();
                    if scratch.keys.capacity() < keys.capacity() {
                        scratch.keys = keys;
                    }
                }

                start += walked;
            }

            shard_idx += 1;
        }

        Ok((matched, writebacks))
    }

    async fn flush_filtered_batched(
        &self,
        filter: &FlushFilter<'_>,
        max_blocks_per_run: usize,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        if let FlushFilter::Owner(owner) = filter {
            return self
                .flush_owner_streaming_batched(*owner, max_blocks_per_run)
                .await;
        }

        let mut keys = {
            let mut scratch = self.flush_scratch.lock();
            scratch.reset();
            core::mem::take(&mut scratch.keys)
        };

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
            .flush_sorted_candidate_keys_batched(filter, &keys, max_blocks_per_run)
            .await?;

        {
            let mut scratch = self.flush_scratch.lock();
            scratch.keys = keys;
            scratch.reset();
        }

        Ok((matched, writebacks))
    }

    fn filtered_writeback_state(&self, filter: &FlushFilter<'_>) -> FilteredWritebackState {
        let mut has_dirty = false;
        let mut shard_idx = 0usize;

        while shard_idx < self.shards.len() {
            let shard = self.shards[shard_idx].lock();
            shard.index.for_each(|lba, page| {
                if page.dirty.load(Ordering::Acquire) && filter.matches(lba, page) {
                    has_dirty = true;
                }
            });

            if has_dirty {
                let mut has_active_writeback = false;
                shard.index.for_each(|lba, page| {
                    if !has_active_writeback
                        && page.dirty.load(Ordering::Acquire)
                        && page.writeback.load(Ordering::Acquire)
                        && filter.matches(lba, page)
                    {
                        has_active_writeback = true;
                    }
                });

                if has_active_writeback {
                    return FilteredWritebackState::ActiveWriteback;
                }
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
        let max_blocks_per_run = if force_device_flush {
            usize::MAX
        } else {
            self.cfg.flush_parallelism.max(1)
        };
        let (matched, writebacks) = self
            .flush_filtered_batched(filter, max_blocks_per_run)
            .await?;

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
                if retry_writebacks == 0 {
                    if matches!(
                        self.wait_for_writeback_progress(filter).await,
                        WritebackWaitResult::Clean
                    ) {
                        break;
                    }
                }
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
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return false;
        }

        let dirty = self.dirty_pages.load(Ordering::Acquire);
        if likely(dirty == 0) {
            return false;
        }

        dirty >= self.cfg.dirty_high_watermark_blocks
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

            if dirty_after <= low && !self.should_start_background_writeback() {
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
            if let Err(err) = cache.flush_internal_owner(owner).await {
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

    /// Shared write implementation that optionally tags pages with an owner.
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
                        Self::start_flush_job_background(cache);
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
                    let _use_guard = PageUseGuard::new(&page);

                    {
                        let mut page_data = page.data.write();
                        page_data.bytes[block_off..block_off + take]
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    }

                    cache.mark_cached_page_dirty(lba, &page, owner);
                }
                WriteAcquire::Direct(page) => {
                    cold_path();
                    {
                        let mut page_data = page.data.write();
                        page_data.bytes[block_off..block_off + take]
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    }

                    if likely(owner == 0) {
                        page.mark_dirty();
                    } else {
                        page.mark_dirty_with_owner(owner);
                    }
                    cache.direct_write_page(lba, &page).await?;
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
                        VolumeCache::<B, BLOCK_SIZE, F>::start_flush_job_background(self);
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
        self.flush_range(offset, data.len()).await
    }

    async fn write_through_at_owned(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), Self::Error> {
        VolumeCache::<B, BLOCK_SIZE, F>::write_at_inner(self, offset, data, owner).await?;
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
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return;
        }

        let cache = Arc::clone(self);
        spawn_detached(async move {
            let _ = cache.ensure_flush_job().await;
        });
    }
    async fn flush_async(&self) {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
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
