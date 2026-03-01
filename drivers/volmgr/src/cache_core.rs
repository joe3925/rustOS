use super::cache::{
    CacheConfig, CacheError, CacheIndex, CacheIndexFactory, CacheStats, DefaultIndexFactory,
    VolumeCacheBackend, VolumeCacheOps,
};
use crate::alloc::vec::Vec;
use crate::vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cmp::min;
use core::marker::PhantomData;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use futures::future::{FutureExt as FuturesFutureExt, Shared};
use futures::stream::StreamExt;
use kernel_api::async_ffi::FfiFuture;
use kernel_api::kernel_types::async_types::{AsyncMutex, AsyncRwLock};
use kernel_api::kernel_types::request::RequestData;
use kernel_api::request::{RequestHandle, RequestType, TraversalPolicy};
use kernel_api::runtime::spawn;
use kernel_api::runtime::spawn_detached;
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
    data: AsyncRwLock<PageBuf<BLOCK_SIZE>>,
    dirty: AtomicBool,
    writeback: AtomicBool,
    generation: AtomicU64,
    wb_generation: AtomicU64,
    active_ops: AtomicUsize,
}

impl<const BLOCK_SIZE: usize> Page<BLOCK_SIZE> {
    fn new_zeroed() -> Self {
        Self {
            data: AsyncRwLock::new(PageBuf::zeroed()),
            dirty: AtomicBool::new(false),
            writeback: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            wb_generation: AtomicU64::new(0),
            active_ops: AtomicUsize::new(0),
        }
    }

    fn mark_dirty(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.dirty.store(true, Ordering::Release);
    }

    fn enter_use(&self) {
        self.active_ops.fetch_add(1, Ordering::AcqRel);
    }

    fn leave_use(&self) {
        self.active_ops.fetch_sub(1, Ordering::AcqRel);
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

enum WriteAcquire<const BLOCK_SIZE: usize> {
    Cached(Arc<Page<BLOCK_SIZE>>),
    Direct(Arc<Page<BLOCK_SIZE>>),
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
    result: Arc<AsyncMutex<Option<Result<(), CacheError<E>>>>>,
}

// pooled page vectors removed; streaming batching used instead.

pub struct VolumeCache<B, const BLOCK_SIZE: usize, F = DefaultIndexFactory>
where
    B: VolumeCacheBackend,
    F: CacheIndexFactory<Arc<Page<BLOCK_SIZE>>>,
{
    backend: Arc<B>,
    shards: Vec<AsyncMutex<Shard<F::Index>>>,
    cfg: CacheConfig,
    stats: Arc<StatsInner>,
    closed: AtomicBool,
    flush_job: AsyncMutex<Option<Arc<FlushJobHandle<B::Error>>>>,
    flush_job_id: AtomicU64,
    flush_scratch: AsyncMutex<FlushScratch<BLOCK_SIZE>>,
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

        let shard_count = cfg.shards;
        let per_shard = (cfg.capacity_blocks + shard_count - 1) / shard_count;
        let mut shards = Vec::with_capacity(shard_count);

        let mut i = 0usize;
        while i < shard_count {
            let index = factory.build(per_shard);
            shards.push(AsyncMutex::new(Shard::new(index, per_shard)));
            i += 1;
        }

        Ok(Self {
            backend,
            shards,
            cfg,
            stats: Arc::new(StatsInner::new()),
            closed: AtomicBool::new(false),
            flush_job: AsyncMutex::new(None),
            flush_job_id: AtomicU64::new(0),
            flush_scratch: AsyncMutex::new(FlushScratch::new(cfg.flush_parallelism)),
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
        let mut shard = self.shards[idx].lock().await;
        shard.index.get(&lba).map(|page| Arc::clone(&*page))
    }

    fn trim_shard_locked(&self, shard: &mut Shard<F::Index>) {
        while shard.index.len() > shard.target_capacity {
            let popped = shard.index.pop_oldest();
            let Some((lba, page)) = popped else {
                break;
            };

            if page.is_evictable() {
                let _ = lba;
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let _ = shard.index.insert(lba, page);
            self.stats.failed_evictions.fetch_add(1, Ordering::Relaxed);
            break;
        }
    }

    async fn insert_page_or_get_existing(
        &self,
        lba: u64,
        page: Arc<Page<BLOCK_SIZE>>,
    ) -> Arc<Page<BLOCK_SIZE>> {
        let idx = self.shard_index(lba);
        let mut shard = self.shards[idx].lock().await;

        if let Some(existing) = shard.index.get(&lba) {
            return Arc::clone(&*existing);
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

    async fn load_page_from_backend(
        &self,
        lba: u64,
    ) -> Result<Arc<Page<BLOCK_SIZE>>, CacheError<B::Error>> {
        let page = Arc::new(Page::new_zeroed());
        {
            let mut data = page.data.write().await;
            self.backend
                .read_block(lba, &mut data.bytes[..])
                .await
                .map_err(CacheError::Backend)?;
        }
        self.stats.backend_reads.fetch_add(1, Ordering::Relaxed);
        Ok(page)
    }

    async fn new_page_from_full_block_write(&self, src: &[u8]) -> Arc<Page<BLOCK_SIZE>> {
        let page = Arc::new(Page::new_zeroed());
        {
            let mut data = page.data.write().await;
            data.bytes[..].copy_from_slice(src);
        }
        page.mark_dirty();
        page
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
            return self.load_page_from_backend(lba).await;
        }

        let loaded = self.load_page_from_backend(lba).await?;
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
                let page = self.new_page_from_full_block_write(src_for_full).await;
                let page = self.insert_page_or_get_existing(lba, page).await;
                return Ok(WriteAcquire::Cached(page));
            }

            let page = self.load_page_from_backend(lba).await?;
            let page = self.insert_page_or_get_existing(lba, page).await;
            return Ok(WriteAcquire::Cached(page));
        }

        if is_full_block {
            let page = self.new_page_from_full_block_write(src_for_full).await;
            return Ok(WriteAcquire::Direct(page));
        }

        let page = self.load_page_from_backend(lba).await?;
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
            },
            RequestData::from_boxed_bytes(vec![0u8; BLOCK_SIZE].into_boxed_slice()),
        );
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        {
            let mut w = req.write();
            let dst = w.data_slice_mut();
            let data = page.data.read().await;
            dst.copy_from_slice(&data.bytes[..]);
        }

        self.backend
            .write_request(&mut req)
            .await
            .map_err(CacheError::Backend)?;

        self.stats.backend_writes.fetch_add(1, Ordering::Relaxed);
        self.stats.direct_writebacks.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    async fn flush_page_task(
        backend: Arc<B>,
        stats: Arc<StatsInner>,
        lba: u64,
        page: Arc<Page<BLOCK_SIZE>>,
    ) -> Result<(), CacheError<B::Error>> {
        stats.flush_attempts.fetch_add(1, Ordering::Relaxed);

        if !page.dirty.load(Ordering::Acquire) {
            stats.flush_skipped_clean.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        if page.writeback.swap(true, Ordering::AcqRel) {
            stats.flush_skipped_busy.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        if !page.dirty.load(Ordering::Acquire) {
            page.writeback.store(false, Ordering::Release);
            stats.flush_skipped_clean.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let wb_gen = page.generation.load(Ordering::Acquire);
        page.wb_generation.store(wb_gen, Ordering::Release);

        let mut req = RequestHandle::new(
            RequestType::Write {
                offset: lba * BLOCK_SIZE as u64,
                len: BLOCK_SIZE,
                flush_write_through: false,
            },
            RequestData::from_boxed_bytes(vec![0u8; BLOCK_SIZE].into_boxed_slice()),
        );
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        {
            let mut req_w = req.write();
            let dst = req_w.data_slice_mut();
            let data = page.data.read().await;
            dst.copy_from_slice(&data.bytes[..]);
        }

        let write_res = backend
            .write_request(&mut req)
            .await
            .map_err(CacheError::Backend);

        match write_res {
            Ok(()) => {
                stats.backend_writes.fetch_add(1, Ordering::Relaxed);
                let cur_gen = page.generation.load(Ordering::Acquire);
                if cur_gen == wb_gen {
                    page.dirty.store(false, Ordering::Release);
                }
                page.writeback.store(false, Ordering::Release);
                stats.flush_success.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                page.writeback.store(false, Ordering::Release);
                page.dirty.store(true, Ordering::Release);
                Err(e)
            }
        }
    }
    /// Joins is a vector with len equal to the desired parallelism, used to track in-flight flush tasks.
    async fn flush_pages_parallel(
        backend: Arc<B>,
        stats: Arc<StatsInner>,
        pages: &[(u64, Arc<Page<BLOCK_SIZE>>)],
        joins: &mut Vec<FfiFuture<()>>,
    ) -> Result<(), CacheError<B::Error>> {
        if pages.is_empty() {
            return Ok(());
        }

        let mut width = joins.capacity();
        if width == 0 {
            width = 1;
        }
        if width > pages.len() {
            width = pages.len();
        }

        joins.clear();

        futures::stream::iter(pages.iter().cloned())
            .for_each_concurrent(width, |(lba, page)| {
                let backend = Arc::clone(&backend);
                let stats = Arc::clone(&stats);
                async move {
                    let _ = Self::flush_page_task(backend, stats, lba, page).await;
                }
            })
            .await;

        Ok(())
    }
    async fn flush_shard_streaming(
        &self,
        shard_idx: usize,
        block_range: Option<&Range<u64>>,
        parallelism: usize,
    ) -> Result<(), CacheError<B::Error>> {
        let mut scratch = self.flush_scratch.lock().await;
        scratch.reset();
        scratch.ensure_join_capacity(parallelism);

        {
            let shard = self.shards[shard_idx].lock().await;
            let needed = shard.index.len();
            let current = scratch.batch.capacity();
            if current < needed {
                scratch.batch.reserve(needed - current);
            }

            shard.index.for_each_chunk(0, usize::MAX, |k, v| {
                if block_range.map_or(true, |r| k >= r.start && k < r.end) {
                    scratch.batch.push((k, Arc::clone(v)));
                }
            });
        }

        if scratch.batch.is_empty() {
            return Ok(());
        }

        let mut joins = core::mem::take(&mut scratch.joins);
        Self::flush_pages_parallel(
            Arc::clone(&self.backend),
            Arc::clone(&self.stats),
            &scratch.batch,
            &mut joins,
        )
        .await?;
        scratch.joins = joins;

        scratch.reset();

        Ok(())
    }
    async fn flush_shards_streaming_all(
        self: &Arc<Self>,
        parallelism: usize,
    ) -> Result<(), CacheError<B::Error>> {
        let mut shard_idx = 0usize;
        while shard_idx < self.shards.len() {
            self.flush_shard_streaming(shard_idx, None, parallelism)
                .await?;
            shard_idx += 1;
        }
        Ok(())
    }

    async fn has_dirty_pages(&self) -> bool {
        let mut shard_idx = 0usize;
        while shard_idx < self.shards.len() {
            let shard = self.shards[shard_idx].lock().await;
            let mut found = false;
            shard.index.for_each(|_, page| {
                if !found && page.dirty.load(Ordering::Acquire) {
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
        loop {
            self.flush_internal_all().await?;
            if !self.has_dirty_pages().await {
                break;
            }
        }
        Ok(())
    }

    async fn finish_flush_job(&self, id: u64) {
        let mut job = self.flush_job.lock().await;
        if job.as_ref().map(|h| h.id == id).unwrap_or(false) {
            job.take();
        }
    }

    pub(crate) async fn ensure_flush_job(self: &Arc<Self>) -> Arc<FlushJobHandle<B::Error>> {
        let mut job_guard = self.flush_job.lock().await;
        if let Some(handle) = job_guard.as_ref() {
            return Arc::clone(handle);
        }

        let id = self
            .flush_job_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);

        let result_slot = Arc::new(AsyncMutex::new(None));
        let result_slot_clone = Arc::clone(&result_slot);
        let cache = Arc::clone(self);

        let job_future = spawn(async move {
            let outcome = cache.flush_until_clean().await;
            let mut slot = result_slot_clone.lock().await;
            *slot = Some(outcome);
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
        handle
            .result
            .lock()
            .await
            .as_ref()
            .cloned()
            .unwrap_or(Ok(()))
    }

    async fn flush_internal_range(
        &self,
        block_range: Range<u64>,
    ) -> Result<(), CacheError<B::Error>> {
        self.check_open()?;
        let mut shard_idx = 0usize;
        while shard_idx < self.shards.len() {
            self.flush_shard_streaming(shard_idx, Some(&block_range), self.cfg.flush_parallelism)
                .await?;
            shard_idx += 1;
        }

        self.backend
            .flush_device()
            .await
            .map_err(CacheError::Backend)
    }

    async fn flush_internal_all(&self) -> Result<(), CacheError<B::Error>> {
        self.check_open()?;
        let mut shard_idx = 0usize;
        while shard_idx < self.shards.len() {
            self.flush_shard_streaming(shard_idx, None, self.cfg.flush_parallelism)
                .await?;
            shard_idx += 1;
        }

        self.backend
            .flush_device()
            .await
            .map_err(CacheError::Backend)
    }

    async fn invalidate_blocks_after_flush(
        &self,
        block_range: Range<u64>,
    ) -> Result<usize, CacheError<B::Error>> {
        self.flush_internal_range(block_range.clone()).await?;

        let mut removed = 0usize;
        let mut i = 0usize;

        while i < self.shards.len() {
            let mut shard = self.shards[i].lock().await;
            let mut keys = Vec::new();

            shard.index.for_each(|k, _| {
                if k >= block_range.start && k < block_range.end {
                    keys.push(k);
                }
            });

            let mut j = 0usize;
            while j < keys.len() {
                if let Some(page) = shard.index.peek(&keys[j]) {
                    if page.active_ops.load(Ordering::Acquire) == 0
                        && !page.writeback.load(Ordering::Acquire)
                        && !page.dirty.load(Ordering::Acquire)
                    {
                        let _ = shard.index.remove(&keys[j]);
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
                    if let Ok(page) = cache.load_page_from_backend(lba).await {
                        let _ = cache.insert_page_or_get_existing(lba, page).await;
                    }
                }
                lba += 1;
            }
        });
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
                let data = page.data.read().await;
                out[dst_pos..dst_pos + take]
                    .copy_from_slice(&data.bytes[block_off..block_off + take]);
            }

            dst_pos += take;
            cur_off += take as u64;
        }

        Ok(())
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
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
                        let mut page_data = page.data.write().await;
                        page_data.bytes[block_off..block_off + take]
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    }

                    page.mark_dirty();
                }
                WriteAcquire::Direct(page) => {
                    {
                        let mut page_data = page.data.write().await;
                        page_data.bytes[block_off..block_off + take]
                            .copy_from_slice(&data[src_pos..src_pos + take]);
                    }

                    page.mark_dirty();
                    self.direct_write_page(lba, &page).await?;
                }
            }

            src_pos += take;
            cur_off += take as u64;
        }

        Ok(())
    }

    async fn write_through_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
        self.write_at(offset, data).await?;
        self.flush_range(offset, data.len()).await
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        self.flush_internal_all().await
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
            let mut shard = self.shards[i].lock().await;
            let mut keys = Vec::new();

            shard.index.for_each(|k, v| {
                if v.is_evictable() {
                    keys.push(k);
                }
            });

            let mut j = 0usize;
            while j < keys.len() {
                if shard.index.remove(&keys[j]).is_some() {
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
            let shard = self.shards[i].lock().await;
            total += shard.index.len();
            i += 1;
        }

        total
    }
}
