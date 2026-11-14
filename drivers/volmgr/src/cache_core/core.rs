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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use kernel_api::kernel_types::dma::{
    FromDevice, IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc, ToDevice,
};
use kernel_api::memory::{
    KernelMapping, PageTableFlags, VirtAddr, allocate_auto_contiguous_kernel_mapping,
};
use kernel_api::println;
use kernel_api::request::Read;
use kernel_api::request::Write;
use kernel_api::runtime::spawn_detached;
use spin::Mutex;

use super::notify::WritebackNotifier;

const FLUSH_WRITE_CHAIN: usize = MAX_WRITE_CHAIN;
const CACHE_GRANULE: usize = 1024;
const READ_AHEAD_BATCH_BYTES: usize = 4 * 1024 * 1024;
const READ_AHEAD_REQUESTS: usize = 2;

struct ReadAhead {
    start: u64,
    next: u64,
    last_lba: u64,
    pending: [Option<Range<u64>>; READ_AHEAD_REQUESTS],
}

struct CacheWriteGuard<'a> {
    active: &'a AtomicUsize,
}

impl Drop for CacheWriteGuard<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
    }
}

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
    yielded: bool,
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
                    if !this.yielded {
                        this.yielded = true;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
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
    slot_lbas: Vec<AtomicU64>,
    dirty_slots: Vec<AtomicU64>,
    free_pages: Mutex<Vec<Arc<CachePage>>>,
    direct_page: Mutex<Option<Arc<CachePage>>>,
    flush_scratch: Mutex<FlushScratch>,
    flush_workers: Mutex<Vec<FlushScratch>>,
    writeback_batch_blocks: usize,
    write_stream_blocks: usize,
    read_ahead_blocks: usize,
    read_stream_blocks: usize,
    read_ahead: Mutex<ReadAhead>,
    read_ahead_active: AtomicUsize,
    read_miss_next: AtomicU64,
    write_stream: Mutex<(u64, u64)>,
    active_writes: AtomicUsize,
    write_epoch: AtomicU64,
    cache_base: VirtAddr,
    cache_bytes: usize,
    cache_backing: Option<IoBufferBacking<'static>>,
    cache_mapping: Option<KernelMapping>,
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

        if cfg.writeback_batch_bytes == 0 || cfg.writeback_batch_bytes % BLOCK_SIZE != 0 {
            return Err(CacheError::InvalidConfig);
        }
        let writeback_batch_blocks = (cfg.writeback_batch_bytes / BLOCK_SIZE)
            .min(cfg.capacity_blocks);
        let read_ahead_blocks = (READ_AHEAD_BATCH_BYTES / BLOCK_SIZE).max(1)
            .min((cfg.capacity_blocks / 8).max(1));
        let (write_stream_blocks, read_stream_blocks) = if let Some(bytes) = cfg.stream_reuse_bytes {
            let blocks = bytes / BLOCK_SIZE;
            if bytes % BLOCK_SIZE != 0
                || blocks < writeback_batch_blocks.max(read_ahead_blocks)
                || blocks > cfg.capacity_blocks
            {
                return Err(CacheError::InvalidConfig);
            }
            (blocks, blocks)
        } else {
            let write_batches = cfg.flush_parallelism.saturating_add(1)
                .min(cfg.capacity_blocks / writeback_batch_blocks);
            let read_batches = READ_AHEAD_REQUESTS.saturating_add(1)
                .min(cfg.capacity_blocks / read_ahead_blocks);
            (write_batches * writeback_batch_blocks, read_batches * read_ahead_blocks)
        };

        let backing_blocks = cfg
            .capacity_blocks
            .checked_add(1)
            .ok_or(CacheError::InvalidConfig)?;

        let cache_bytes = backing_blocks
            .checked_mul(BLOCK_SIZE)
            .ok_or(CacheError::InvalidConfig)?;

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let cache_mapping = allocate_auto_contiguous_kernel_mapping(cache_bytes as u64, flags)
            .map_err(|_| CacheError::InsufficientResources)?;
        let cache_base = cache_mapping.address();

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
                    return Err(CacheError::InvalidIoBuffer(e));
                }
            };

        if cfg.dma_map_entire_cache {
            if let Err(e) = backend.dma_map_cache(&mut cache_backing).await {
                drop(cache_backing);

                return Err(CacheError::Backend(e));
            }
        }

        let shard_count = cfg.shards;
        let index_reserve = cfg.capacity_blocks;

        let mut shards = Vec::new();
        if shards.try_reserve_exact(shard_count).is_err() {
            drop(cache_backing);

            return Err(CacheError::InsufficientResources);
        }

        let mut i = 0usize;
        while i < shard_count {
            let mut index = factory.build(index_reserve);
            index.reserve_or_panic(index_reserve);
            shards.push(Mutex::new(Shard { index }));
            i += 1;
        }

        let mut free_pages = Vec::new();
        if free_pages.try_reserve_exact(cfg.capacity_blocks).is_err() {
            drop(shards);
            drop(cache_backing);

            return Err(CacheError::InsufficientResources);
        }

        let mut slot = cfg.capacity_blocks;
        while slot != 0 {
            slot -= 1;
            free_pages.push(Arc::new(CachePage::new(slot)));
        }

        let direct_page = Arc::new(CachePage::new(cfg.capacity_blocks));

        let mut slot_lbas = Vec::new();
        slot_lbas
            .try_reserve_exact(cfg.capacity_blocks)
            .map_err(|_| CacheError::InsufficientResources)?;
        slot_lbas.resize_with(cfg.capacity_blocks, || AtomicU64::new(0));

        let dirty_words = cfg.capacity_blocks.div_ceil(64);
        let mut dirty_slots = Vec::new();
        dirty_slots
            .try_reserve_exact(dirty_words)
            .map_err(|_| CacheError::InsufficientResources)?;
        dirty_slots.resize_with(dirty_words, || AtomicU64::new(0));

        let flush_scratch = match FlushScratch::new(cfg.capacity_blocks, FLUSH_WRITE_CHAIN) {
            Ok(scratch) => scratch,
            Err(_) => {
                drop(direct_page);
                drop(free_pages);
                drop(shards);
                drop(cache_backing);

                return Err(CacheError::InsufficientResources);
            }
        };

        let mut flush_workers = Vec::new();
        flush_workers
            .try_reserve_exact(cfg.flush_parallelism)
            .map_err(|_| CacheError::InsufficientResources)?;
        for _ in 0..cfg.flush_parallelism {
            flush_workers.push(
                FlushScratch::new(0, writeback_batch_blocks)
                    .map_err(|_| CacheError::InsufficientResources)?,
            );
        }

        Ok(Self {
            backend,
            shards,
            slot_lbas,
            dirty_slots,
            free_pages: Mutex::new(free_pages),
            direct_page: Mutex::new(Some(direct_page)),
            flush_scratch: Mutex::new(flush_scratch),
            flush_workers: Mutex::new(flush_workers),
            writeback_batch_blocks,
            write_stream_blocks,
            read_ahead_blocks,
            read_stream_blocks,
            read_ahead: Mutex::new(ReadAhead {
                start: 0,
                next: 0,
                last_lba: 0,
                pending: [const { None }; READ_AHEAD_REQUESTS],
            }),
            read_ahead_active: AtomicUsize::new(0),
            read_miss_next: AtomicU64::new(u64::MAX),
            write_stream: Mutex::new((0, 0)),
            active_writes: AtomicUsize::new(0),
            write_epoch: AtomicU64::new(0),
            cache_base,
            cache_bytes,
            cache_backing: Some(cache_backing),
            cache_mapping: Some(cache_mapping),
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
    fn full_granule_mask() -> u64 {
        let granules = BLOCK_SIZE / CACHE_GRANULE;
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
    fn page_ptr(&self, page: &CachePage) -> *mut u8 {
        (self.cache_base.as_u64() as usize + Self::page_offset(page.slot)) as *mut u8
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

    fn check_open(&self) -> Result<(), CacheError<B::Error>> {
        if unlikely(self.closed.load(Ordering::Acquire)) {
            cold_path();
            return Err(CacheError::Closed);
        }
        Ok(())
    }

    fn mark_cached_page_dirty_range(&self, page: &CachePage, owner: u64, bits: u64) {
        if unlikely(bits == 0) {
            cold_path();
            return;
        }

        let _guard = page.dirty_lock.lock();
        page.owner.store(owner, Ordering::Release);
        let valid = page.valid_mask.load(Ordering::Relaxed);
        if valid & bits != bits {
            page.valid_mask.store(valid | bits, Ordering::Release);
        }
        let generation = page.generation.load(Ordering::Relaxed);
        page.generation.store(generation.wrapping_add(1), Ordering::Release);

        let dirty = page.dirty_mask.load(Ordering::Relaxed);
        if dirty & bits != bits {
            page.dirty_mask.store(dirty | bits, Ordering::Release);
        }
        if dirty == 0 {
            self.dirty_pages.fetch_add(1, Ordering::AcqRel);
            self.dirty_slots[page.slot / 64]
                .fetch_or(1u64 << (page.slot % 64), Ordering::AcqRel);
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

    fn try_get_page(&self, lba: u64) -> Option<Arc<CachePage>> {
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
            .oldest_matching(shard.index.len().div_ceil(2), |_, page| {
                Self::page_can_be_reclaimed(page)
            });

        if let Some(lba) = reclaim_key {
            let Some(page) = shard.index.remove(&lba) else {
                return None;
            };
            page.reset_for_lba(0);
            return Some(page);
        }

        None
    }

    fn try_reclaim_cache_page(&self, lba: u64, preferred_slot: Option<usize>, stream_start: Option<u64>) -> Option<Arc<CachePage>> {
        let writing = self.active_writes.load(Ordering::Acquire) != 0;
        let stream_blocks = if writing {
            self.write_stream_blocks
        } else {
            self.read_stream_blocks
        };
        let next_slot = stream_start.map(|start| {
            let position = if writing { lba } else { lba - start };
            (position % stream_blocks as u64) as usize
        })
            .or(preferred_slot).or_else(|| {
            let previous_lba = lba.checked_sub(1)?;
            let shard = self.shards[self.shard_index(previous_lba)].lock();
            shard.index.peek(&previous_lba)
                .map(|page| (page.slot + 1) % self.cfg.capacity_blocks)
        });
        if let Some(slot) = next_slot {
            let old_lba = self.slot_lbas[slot].load(Ordering::Acquire);
            let mut shard = self.shards[self.shard_index(old_lba)].lock();
            let stream_page = stream_start.is_some_and(|start| {
                old_lba >= start && old_lba < lba && lba - old_lba >= stream_blocks as u64
            }) && shard.index.peek(&old_lba).is_some_and(|page| page.slot == slot);
            if stream_page || shard.index.oldest_matching(shard.index.len().div_ceil(2), |key, page| {
                key == old_lba && page.slot == slot
            }) == Some(old_lba) {
                let page = shard.index.peek(&old_lba).expect("reclaim page disappeared");
                if Self::page_can_be_reclaimed(page) {
                    let page = shard.index.remove(&old_lba).expect("reclaim page disappeared");
                    page.reset_for_lba(lba);
                    return Some(page);
                }
                if page.dirty_mask.load(Ordering::Acquire) != 0
                    || self.flush_active.load(Ordering::Acquire)
                {
                    return None;
                }
            }
        }
        let preferred_idx = self.shard_index(lba);
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
            .oldest_matching(usize::MAX, |_, page| Self::page_can_be_flushed_for_reclaim(page))?;
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

        let mut lease = FlushRunScratchLease::new(&self.flush_scratch);
        let result = self
            .flush_prepared_pages_chained_with_runs(
                &prepared,
                &mut runs,
                &mut extents,
                lease.writes.as_mut().expect("flush write scratch lease used after drop"),
            )
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

        drop(prepared);
        self.writeback_notifier.notify_all();
        result?;
        Ok(true)
    }

    async fn acquire_cache_page(self: &Arc<Self>, lba: u64, stream_start: Option<u64>) -> Result<Arc<CachePage>, CacheError<B::Error>> {
        if let Some(page) = self.free_pages.lock().pop() {
            page.reset_for_lba(lba);
            return Ok(page);
        }

        let preferred_idx = self.shard_index(lba);
        if let Some(page) = self.try_reclaim_cache_page(lba, None, stream_start) {
            page.reset_for_lba(lba);
            return Ok(page);
        }

        if self.dirty_pages.load(Ordering::Acquire) != 0
            || self.flush_active.load(Ordering::Acquire)
        {
            let reclaimed = core::future::poll_fn(|cx| loop {
                let epoch = self.writeback_notifier.epoch();
                if let Some(page) = self.try_reclaim_cache_page(lba, None, stream_start) {
                    return Poll::Ready(Some(page));
                }
                if !self.flush_active.load(Ordering::Acquire) {
                    return Poll::Ready(None);
                }
                if self.writeback_notifier.register_if_unchanged(epoch, cx.waker()) {
                    return Poll::Pending;
                }
            })
            .await;
            if let Some(page) = reclaimed {
                page.reset_for_lba(lba);
                return Ok(page);
            }
            self.flush_internal_filtered(&FlushFilter::All, false).await?;
            let free_page = self.free_pages.lock().pop();
            if let Some(page) = free_page.or_else(|| self.try_reclaim_cache_page(lba, None, stream_start)) {
                page.reset_for_lba(lba);
                return Ok(page);
            }
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

            if let Some(page) = self.try_reclaim_cache_page(lba, None, stream_start) {
                page.reset_for_lba(lba);
                return Ok(page);
            }

            attempts -= 1;
        }

        Err(CacheError::NoFreePages)
    }

    fn insert_page_or_get_existing(&self, lba: u64, page: Arc<CachePage>) -> Arc<CachePage> {
        let idx = self.shard_index(lba);
        let mut shard = self.shards[idx].lock();

        if let Some(existing) = shard.index.get(&lba) {
            cold_path();
            let existing = Arc::clone(&*existing);
            drop(shard);
            self.recycle_or_drop_page(page);
            return existing;
        }

        self.slot_lbas[page.slot].store(lba, Ordering::Release);
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

        let bits = Self::granule_mask_for_range(block_off, len)?;
        let base = lba
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(CacheError::OffsetOverflow)?;

        {
            let _data_guard = match page.data_lock.try_write() {
                Some(guard) => guard,
                None => page.data_lock.write().await,
            };

            let mut missing = bits & !page.valid_mask.load(Ordering::Acquire);
            while let Some((granule_start, granule_count, run_bits)) = Self::first_mask_run(missing) {
                let read_off = granule_start
                    .checked_mul(CACHE_GRANULE)
                    .ok_or(CacheError::OffsetOverflow)?;
                let read_len = granule_count
                    .checked_mul(CACHE_GRANULE)
                    .ok_or(CacheError::OffsetOverflow)?;
                let offset = base
                    .checked_add(read_off as u64)
                    .ok_or(CacheError::OffsetOverflow)?;
                let io_buf = self.create_cache_from_device_buffer_at(page, read_off, read_len)?;
                let mut req = Read::new(offset, read_len, false, Some(io_buf));
                self.backend
                    .read_request(&mut req)
                    .await
                    .map_err(CacheError::Backend)?;

                page.valid_mask.fetch_or(run_bits, Ordering::AcqRel);
                missing &= !run_bits;
            }
        }

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

    async fn wait_for_read_ahead(&self, range: Range<u64>) {
        if self.read_ahead_active.load(Ordering::Acquire) == 0 {
            return;
        }
        core::future::poll_fn(|cx| loop {
            let epoch = self.writeback_notifier.epoch();
            let pending = self.read_ahead.lock().pending.iter().flatten().any(|pending| {
                pending.start < range.end && range.start < pending.end
            });
            if !pending {
                return Poll::Ready(());
            }
            if self.writeback_notifier.register_if_unchanged(epoch, cx.waker()) {
                return Poll::Pending;
            }
        }).await;
    }

    fn start_read_ahead(self: &Arc<Self>, lba: u64) {
        if !self.cfg.read_allocate || self.cfg.capacity_blocks < 16
            || self.closed.load(Ordering::Acquire)
            || self.active_writes.load(Ordering::Acquire) != 0
        {
            return;
        }
        let blocks = self.read_ahead_blocks;
        let horizon = lba.saturating_add((blocks * READ_AHEAD_REQUESTS) as u64);
        let mut launches: [Option<Range<u64>>; READ_AHEAD_REQUESTS] =
            [const { None }; READ_AHEAD_REQUESTS];
        {
            let mut state = self.read_ahead.lock();
            if lba < state.last_lba || lba >= state.next {
                if state.pending.iter().any(Option::is_some) {
                    return;
                }
                state.start = lba;
                state.next = lba;
            }
            state.last_lba = lba;
            for (slot, launch) in launches.iter_mut().enumerate() {
                if state.pending[slot].is_none() && state.next < horizon {
                    let end = state.next.saturating_add(blocks as u64);
                    if end == state.next {
                        break;
                    }
                    let range = state.next..end;
                    state.next = end;
                    state.pending[slot] = Some(range.clone());
                    *launch = Some(range);
                    self.read_ahead_active.fetch_add(1, Ordering::Release);
                }
            }
        }
        for (slot, range) in launches.into_iter().enumerate() {
            let Some(range) = range else { continue; };
            let cache = Arc::clone(self);
            spawn_detached(async move {
                let stream_start = cache.read_ahead.lock().start;
                let stream_start = (range.start.saturating_sub(stream_start) >= cache.cfg.capacity_blocks as u64)
                    .then_some(stream_start);
                let mut cursor = range.start;
                let mut pages: Vec<(u64, Arc<CachePage>)> = Vec::with_capacity(blocks);
                let mut reads = Vec::with_capacity(blocks);
                while cursor < range.end && !cache.closed.load(Ordering::Acquire) {
                    let write_epoch = cache.write_epoch.load(Ordering::Acquire);
                    if cache.active_writes.load(Ordering::Acquire) != 0 {
                        break;
                    }
                    if cache.try_get_page(cursor).is_some() {
                        cursor += 1;
                        continue;
                    }
                    while cursor < range.end {
                        if cache.try_get_page(cursor).is_some() {
                            break;
                        }
                        let free = cache.free_pages.lock().pop();
                        let Some(page) = free.or_else(|| cache.try_reclaim_cache_page(
                            cursor,
                            pages.last().map(|(_, page)| (page.slot + 1) % cache.cfg.capacity_blocks),
                            stream_start,
                        )) else {
                            break;
                        };
                        page.reset_for_lba(cursor);
                        pages.push((cursor, page));
                        cursor += 1;
                    }
                    if pages.is_empty() {
                        break;
                    }
                    let mut status = Ok(());
                    let mut start = 0usize;
                    while start < pages.len() {
                        let mut end = start + 1;
                        while end < pages.len() && pages[end].1.slot == pages[end - 1].1.slot + 1 {
                            end += 1;
                        }
                        let len = (end - start) * BLOCK_SIZE;
                        let buffer = match cache.create_cache_from_device_buffer(&pages[start].1, len) {
                            Ok(buffer) => buffer,
                            Err(error) => {
                                status = Err(error);
                                break;
                            }
                        };
                        let Some(offset) = pages[start].0.checked_mul(BLOCK_SIZE as u64) else {
                            status = Err(CacheError::OffsetOverflow);
                            break;
                        };
                        reads.push(Read::new(offset, len, false, Some(buffer)));
                        start = end;
                    }
                    if status.is_ok() {
                        for index in 0..reads.len().saturating_sub(1) {
                            unsafe {
                                let next = reads.as_mut_ptr().add(index + 1);
                                reads[index].append_next(next);
                            }
                        }
                        status = cache.backend.read_request(&mut reads[0]).await.map_err(CacheError::Backend);
                    }
                    reads.clear();
                    let publish = status.is_ok()
                        && cache.active_writes.load(Ordering::Acquire) == 0
                        && cache.write_epoch.load(Ordering::Acquire) == write_epoch;
                    for (lba, page) in pages.drain(..) {
                        if publish {
                            page.valid_mask.store(Self::full_granule_mask(), Ordering::Release);
                            page.prefetched.store(true, Ordering::Relaxed);
                            cache.insert_page_or_get_existing(lba, page);
                        } else {
                            cache.recycle_or_drop_page(page);
                        }
                    }
                    if !publish {
                        break;
                    }
                }
                cache.read_ahead.lock().pending[slot] = None;
                cache.read_ahead_active.fetch_sub(1, Ordering::Release);
                cache.writeback_notifier.notify_all();
            });
        }
    }

    async fn load_cache_page_from_backend(
        self: &Arc<Self>,
        lba: u64,
    ) -> Result<Arc<CachePage>, CacheError<B::Error>> {
        let page = self.acquire_cache_page(lba, None).await?;
        match self.read_block_into_page(lba, &page).await {
            Ok(_) => Ok(page),
            Err(e) => {
                self.recycle_or_drop_page(page);
                Err(e)
            }
        }
    }

    async fn get_or_create_read_page(
        self: &Arc<Self>,
        lba: u64,
    ) -> Result<Arc<CachePage>, CacheError<B::Error>> {
        if let Some(page) = self.try_get_page(lba) {
            return Ok(page);
        }

        cold_path();

        if unlikely(!self.cfg.read_allocate) {
            cold_path();
            return Err(CacheError::NoFreePages);
        }

        let next = lba.saturating_add(1);
        if self.read_miss_next.swap(next, Ordering::Relaxed) == lba {
            self.start_read_ahead(lba);
        }
        self.wait_for_read_ahead(lba..next).await;
        if let Some(page) = self.try_get_page(lba) {
            return Ok(page);
        }
        let loaded = self.load_cache_page_from_backend(lba).await?;
        Ok(self.insert_page_or_get_existing(lba, loaded))
    }

    async fn get_or_create_write_page(
        self: &Arc<Self>,
        lba: u64,
        advance_stream: bool,
    ) -> Result<WriteAcquire, CacheError<B::Error>> {
        if let Some(page) = self.try_get_page(lba) {
            if advance_stream {
                let mut stream = self.write_stream.lock();
                if stream.1 == lba {
                    stream.1 = lba.saturating_add(1);
                }
            }
            return Ok(WriteAcquire::Cached(page));
        }

        cold_path();

        if !self.cfg.write_allocate {
            return Ok(WriteAcquire::Direct);
        }

        let stream_start = {
            let mut stream = self.write_stream.lock();
            if stream.1 != lba {
                stream.0 = lba;
            }
            stream.1 = lba.saturating_add(1);
            (lba.saturating_sub(stream.0) >= self.writeback_batch_blocks as u64)
                .then_some(stream.0)
        };
        let page = self.acquire_cache_page(lba, stream_start).await?;
        let page = self.insert_page_or_get_existing(lba, page);
        let high_watermark = self.cfg.dirty_high_watermark_blocks
            .min(self.writeback_batch_blocks.saturating_mul(self.cfg.flush_parallelism))
            .min(self.write_stream_blocks.saturating_sub(self.writeback_batch_blocks)
                .max(self.writeback_batch_blocks));
        if stream_start.is_some() && self.dirty_pages.load(Ordering::Acquire) >= high_watermark
            && self.free_pages.lock().is_empty()
        {
            Self::maybe_start_background_writeback(
                self,
                Some(high_watermark.saturating_sub(self.writeback_batch_blocks)),
            );
        }
        Ok(WriteAcquire::Cached(page))
    }

    async fn read_block_into_page(
        &self,
        lba: u64,
        page: &Arc<CachePage>,
    ) -> Result<usize, CacheError<B::Error>> {
        let bytes_read = {
            let _data_guard = match page.data_lock.try_write() {
                Some(guard) => guard,
                None => page.data_lock.write().await,
            };
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
            let _data_guard = match page.data_lock.try_write() {
                Some(guard) => guard,
                None => page.data_lock.write().await,
            };
            unsafe {
                core::slice::from_raw_parts_mut(self.page_ptr(page), BLOCK_SIZE)[bytes_read..]
                    .fill(0);
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
        let buffer = self.create_cache_to_device_buffer_at(page, 0, BLOCK_SIZE)?;
        self.write_buffer_to_backend(lba * BLOCK_SIZE as u64, buffer, owner)
            .await
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

            if let Err(err) = self.read_block_into_page(lba, &page).await {
                result = Err(err);
                break;
            }

            self.ensure_page_range_valid(lba, &page, block_off, take)
                .await?;

            {
                let _guard = match page.data_lock.try_read() {
                    Some(guard) => guard,
                    None => page.data_lock.read().await,
                };
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
        remaining: &mut Option<IoBuffer<'buffer, 'buffer, ToDevice>>,
        buffer_offset: &mut usize,
        len: usize,
        owner: u64,
    ) -> Result<(), CacheError<B::Error>> {
        if unlikely(len == 0) {
            cold_path();
            return Ok(());
        }
        let end = buffer_offset
            .checked_add(len)
            .ok_or(CacheError::OffsetOverflow)?;
        if unlikely(remaining.as_ref().is_none_or(|buffer| buffer.len() < end)) {
            cold_path();
            return Err(CacheError::InvalidConfig);
        }

        let page = self.take_direct_page()?;
        let mut result = Ok(());
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
                    let source = if *buffer_offset == 0 {
                        Some(source)
                    } else {
                        match source.split_at(*buffer_offset) {
                            Ok((prefix, source)) => {
                                drop(prefix);
                                *buffer_offset = 0;
                                Some(source)
                            }
                            Err((source, _)) => {
                                *remaining = Some(source);
                                None
                            }
                        }
                    };
                    let direct_buffer = match source {
                        Some(source) if source.len() == direct_len => Some(source),
                        Some(source) => match source.split_at(direct_len) {
                            Ok((direct_buffer, tail)) => {
                                *remaining = Some(tail);
                                Some(direct_buffer)
                            }
                            Err((source, _)) => {
                                *remaining = Some(source);
                                None
                            }
                        },
                        None => None,
                    };
                    if let Some(direct_buffer) = direct_buffer {
                        if let Err(err) = self
                            .write_buffer_to_backend(cur_off, direct_buffer, owner)
                            .await
                        {
                            result = Err(err);
                            break;
                        }
                        *buffer_offset = 0;
                        written += direct_len;
                        cur_off += direct_len as u64;
                        continue;
                    }
                }
            }

            let lba = cur_off / bs_u64;
            let take = min(BLOCK_SIZE - block_off, len - written);

            if block_off != 0 || take != BLOCK_SIZE {
                if let Err(err) = self.read_block_into_page(lba, &page).await {
                    result = Err(err);
                    break;
                }
            }

            {
                let _guard = match page.data_lock.try_write() {
                    Some(guard) => guard,
                    None => page.data_lock.write().await,
                };
                let destination =
                    unsafe {
                        &mut core::slice::from_raw_parts_mut(self.page_ptr(&page), BLOCK_SIZE)
                            [block_off..block_off + take]
                    };
                if let Err(err) = remaining
                    .as_ref()
                    .expect("direct write buffer disappeared")
                    .copy_to_slice(*buffer_offset, destination)
                {
                    result = Err(CacheError::InvalidIoBuffer(err));
                    break;
                }
            }

            if let Err(err) = self.write_block_from_direct_page(lba, &page, owner).await {
                result = Err(err);
                break;
            }

            *buffer_offset += take;
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
        let data_guard = page.data_lock.try_read()?;
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

        drop(data_guard);
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
        let mut clean_pages = 0usize;
        let mut cleared_word: Option<usize> = None;
        let mut cleared_slots = 0u64;
        for prepared in extents {
            let _guard = prepared.page.dirty_lock.lock();
            let old = prepared.page.dirty_mask.load(Ordering::Relaxed);
            if likely(success) {
                let cur_gen = prepared.page.generation.load(Ordering::Acquire);
                if cur_gen == prepared.wb_generation {
                    let new = old & !prepared.bits;
                    prepared.page.dirty_mask.store(new, Ordering::Release);
                    if old != 0 && new == 0 {
                        clean_pages += 1;
                        let word = prepared.page.slot / 64;
                        let bit = 1u64 << (prepared.page.slot % 64);
                        if prepared.bits == Self::full_granule_mask() {
                            if cleared_word != Some(word) {
                                if let Some(previous) = cleared_word {
                                    self.dirty_slots[previous]
                                        .fetch_and(!cleared_slots, Ordering::AcqRel);
                                }
                                cleared_word = Some(word);
                                cleared_slots = 0;
                            }
                            cleared_slots |= bit;
                        } else {
                            self.dirty_slots[word].fetch_and(!bit, Ordering::AcqRel);
                        }
                    }
                }
            } else {
                prepared.page.dirty_mask.store(old | prepared.bits, Ordering::Release);
                if old == 0 {
                    self.dirty_pages.fetch_add(1, Ordering::AcqRel);
                    self.dirty_slots[prepared.page.slot / 64]
                        .fetch_or(1u64 << (prepared.page.slot % 64), Ordering::AcqRel);
                }
            }
        }
        if let Some(word) = cleared_word {
            self.dirty_slots[word].fetch_and(!cleared_slots, Ordering::AcqRel);
        }
        if clean_pages != 0 {
            self.dirty_pages.fetch_sub(clean_pages, Ordering::AcqRel);
        }
        for prepared in extents {
            prepared
                .page
                .writeback_mask
                .fetch_and(!prepared.bits, Ordering::AcqRel);
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

    fn for_each_dirty_page(&self, mut visit: impl FnMut(u64, &Arc<CachePage>)) {
        if self.dirty_pages.load(Ordering::Acquire) == 0 {
            return;
        }

        for (word_index, word) in self.dirty_slots.iter().enumerate() {
            let mut slots = word.load(Ordering::Acquire);
            while slots != 0 {
                let slot = word_index * 64 + slots.trailing_zeros() as usize;
                slots &= slots - 1;
                let lba = self.slot_lbas[slot].load(Ordering::Acquire);
                let shard = self.shards[self.shard_index(lba)].lock();
                if let Some(page) = shard.index.peek(&lba) {
                    if page.slot == slot && page.dirty_mask.load(Ordering::Acquire) != 0 {
                        visit(lba, page);
                    }
                }
            }
        }
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
        let batch_limit = self.writeback_batch_blocks.min(prepared.capacity());

        while *key_cursor < keys.len() {
            let lba = keys[*key_cursor];

            let Some(page) = self.page_for_flush_key(lba, filter) else {
                *key_cursor += 1;
                continue;
            };

            if keys.len() > batch_limit && !prepared.is_empty()
                && page.slot % batch_limit.max(1) == 0
            {
                return Ok(true);
            }

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

                if prepared.len() == batch_limit {
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
        writes: &mut [Option<Write<'static>>; MAX_WRITE_CHAIN],
    ) -> Result<usize, CacheError<B::Error>> {
        if pages.is_empty() {
            return Ok(0);
        }

        if let Err(error) = Self::collect_prepared_runs_into(pages, logical_runs)
            .and_then(|()| Self::collect_cache_slot_extents_into(pages, logical_runs, extents))
        {
            self.finish_prepared_flush_extents(pages, false);
            return Err(error);
        }

        if unlikely(extents.len() > FLUSH_WRITE_CHAIN) {
            cold_path();
            self.finish_prepared_flush_extents(pages, false);
            return Err(CacheError::InsufficientResources);
        }
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
        self: &Arc<Self>,
        filter: &FlushFilter,
        keys: &[u64],
    ) -> Result<usize, CacheError<B::Error>> {
        if unlikely(keys.is_empty()) {
            cold_path();
            return Ok(0);
        }

        let workers: Vec<FlushScratch> = core::future::poll_fn(|cx| loop {
            let epoch = self.writeback_notifier.epoch();
            let mut workers = self.flush_workers.lock();
            if !workers.is_empty() {
                let count = keys.len()
                    .div_ceil(self.writeback_batch_blocks)
                    .min(workers.len());
                return Poll::Ready(workers.drain(..count).collect());
            }
            drop(workers);
            if self.writeback_notifier.register_if_unchanged(epoch, cx.waker()) {
                return Poll::Pending;
            }
        }).await;
        let mut candidates = Vec::with_capacity(if workers.len() == 1 {
            keys.len()
        } else {
            self.cfg.capacity_blocks
        });
        candidates.extend_from_slice(keys);
        let key_cursor = Arc::new(Mutex::new((candidates, 0usize, workers.len().saturating_mul(16))));
        let completed = Arc::new(Mutex::new(Vec::with_capacity(workers.len())));
        let mut joins = Vec::with_capacity(workers.len());
        for mut worker in workers {
            let cache = Arc::clone(self);
            let key_cursor = Arc::clone(&key_cursor);
            let completed = Arc::clone(&completed);
            let filter = *filter;
            let task = async move {
                let mut total_flushed = 0usize;
                let mut result = Ok(());
                worker.prepared.clear();
                worker.runs.clear();
                worker.extents.clear();
                let mut batch = 0usize;
                loop {
                    let observed_epoch = cache.writeback_notifier.epoch();
                    let has_chain = {
                        let mut state = key_cursor.lock();
                        let (keys, cursor, batches_left) = &mut *state;
                        if *batches_left == 0 {
                            break;
                        }
                        if keys.len() - *cursor < cache.writeback_batch_blocks {
                            keys.clear();
                            *cursor = 0;
                            cache.for_each_dirty_page(|lba, page| {
                                if filter.matches(lba, page)
                                    && page.writeback_mask.load(Ordering::Acquire) == 0
                                {
                                    keys.push(lba);
                                }
                            });
                            keys.sort_unstable();
                        }
                        if keys.is_empty() || (batch != 0 && keys.len() < cache.writeback_batch_blocks) {
                            if matches!(cache.filtered_writeback_state(&filter), FilteredWritebackState::ActiveWriteback) {
                                None
                            } else {
                                break;
                            }
                        } else {
                            let prepared = cache.prepare_flush_chain_from_keys(
                                &filter,
                                keys,
                                cursor,
                                &mut worker.prepared,
                            );
                            if matches!(prepared, Ok(true)) {
                                *batches_left -= 1;
                            }
                            Some(prepared)
                        }
                    };
                    let Some(has_chain) = has_chain else {
                        core::future::poll_fn(|cx| {
                            if cache.writeback_notifier.register_if_unchanged(observed_epoch, cx.waker()) {
                                Poll::Pending
                            } else {
                                Poll::Ready(())
                            }
                        }).await;
                        continue;
                    };
                    let has_chain = match has_chain {
                        Ok(has_chain) => has_chain,
                        Err(error) => {
                            cache.finish_prepared_flush_extents(&worker.prepared, false);
                            result = Err(error);
                            break;
                        }
                    };
                    if !has_chain {
                        break;
                    }
                    batch += 1;
                    let flushed = cache.flush_prepared_pages_chained_with_runs(
                        &worker.prepared,
                        &mut worker.runs,
                        &mut worker.extents,
                        worker.writes.as_mut().expect("flush worker has no request storage"),
                    ).await;
                    worker.prepared.clear();
                    worker.runs.clear();
                    worker.extents.clear();
                    cache.writeback_notifier.notify_all();
                    match flushed {
                        Ok(count) => total_flushed += count,
                        Err(error) => {
                            result = Err(error);
                            break;
                        }
                    }
                }
                worker.prepared.clear();
                worker.runs.clear();
                worker.extents.clear();
                cache.flush_workers.lock().push(worker);
                completed.lock().push(result.map(|()| total_flushed));
                cache.writeback_notifier.notify_all();
            };
            let mut task = alloc::boxed::Box::pin(task);
            let ready = core::future::poll_fn(|cx| {
                Poll::Ready(task.as_mut().poll(cx).is_ready())
            }).await;
            if !ready {
                joins.push(kernel_api::runtime::spawn(task));
            }
        }
        for join in joins { join.await; }
        let mut total_flushed = 0usize;
        let mut first_error = None;
        for result in completed.lock().drain(..) {
            match result {
                Ok(count) => total_flushed += count,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(total_flushed),
        }
    }
    async fn flush_filtered_batched(
        self: &Arc<Self>,
        filter: &FlushFilter,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        let mut keys = {
            let mut scratch = self.flush_scratch.lock();
            core::mem::take(&mut scratch.keys)
        };

        keys.clear();

        self.for_each_dirty_page(|lba, page| {
            if filter.matches(lba, page) {
                keys.push(lba);
            }
        });

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
        self.for_each_dirty_page(|lba, page| {
            if filter.matches(lba, page) {
                has_dirty = true;
                has_active_writeback |= page.writeback_mask.load(Ordering::Acquire) != 0;
            }
        });

        if has_active_writeback {
            FilteredWritebackState::ActiveWriteback
        } else if has_dirty {
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
            yielded: false,
        }
    }

    async fn flush_internal_filtered(
        self: &Arc<Self>,
        filter: &FlushFilter,
        force_device_flush: bool,
    ) -> Result<(usize, usize), CacheError<B::Error>> {
        self.check_open()?;
        FlushSlotWait { cache: self }.await;

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
        self: &Arc<Self>,
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

    async fn flush_internal_all(self: &Arc<Self>) -> Result<(), CacheError<B::Error>> {
        self.flush_until_filtered_clean(&FlushFilter::All, true)
            .await
    }

    async fn flush_internal_owner_to_backend(
        self: &Arc<Self>,
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

    fn report_background_writeback_error(error: &CacheError<B::Error>) {
        cold_path();
        // TODO: Find a better policy for asynchronous write-back failures.
        println!(
            "[volmgr] background cache write-back failed; affected pages remain dirty: {:?}",
            error
        );
    }

    async fn background_writeback_loop(self: &Arc<Self>, low_watermark: usize) -> Result<(), CacheError<B::Error>> {
        loop {
            if unlikely(self.closed.load(Ordering::Acquire)) {
                cold_path();
                break;
            }

            let dirty_before = self.dirty_pages.load(Ordering::Acquire);
            if dirty_before <= low_watermark {
                break;
            }

            let (matched, writebacks) =
                match self.flush_internal_filtered(&FlushFilter::All, false).await {
                    Ok(pass) => pass,
                    Err(err) => {
                        cold_path();
                        return Err(err);
                    }
                };

            let dirty_after = self.dirty_pages.load(Ordering::Acquire);

            if matched == 0 || writebacks == 0 || dirty_after >= dirty_before {
                break;
            }
        }

        Ok(())
    }

    fn maybe_start_background_writeback(cache: &Arc<Self>, pressure_low_watermark: Option<usize>) {
        if likely(pressure_low_watermark.is_none() && !cache.should_start_background_writeback()) {
            return;
        }

        if cache
            .background_writeback_active
            .swap(true, Ordering::AcqRel)
        {
            cold_path();
            return;
        }
        let low_watermark = pressure_low_watermark.unwrap_or(cache.cfg.dirty_low_watermark_blocks);
        let cache_for_task = Arc::clone(cache);

        spawn_detached(async move {
            let writeback_succeeded = match cache_for_task.background_writeback_loop(low_watermark).await {
                Ok(()) => true,
                Err(err) => {
                    Self::report_background_writeback_error(&err);
                    false
                }
            };
            cache_for_task
                .background_writeback_active
                .store(false, Ordering::Release);

            if writeback_succeeded
                && cache_for_task.should_start_background_writeback()
                && !cache_for_task
                    .background_writeback_active
                    .swap(true, Ordering::AcqRel)
            {
                let cache_for_followup = Arc::clone(&cache_for_task);

                spawn_detached(async move {
                    if let Err(err) = cache_for_followup.background_writeback_loop(low_watermark).await {
                        Self::report_background_writeback_error(&err);
                    }
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
                Self::report_background_writeback_error(&err);
            }
        });
    }

    pub async fn close_and_flush(self: &Arc<Self>) -> Result<(), CacheError<B::Error>> {
        self.flush_internal_all().await?;
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

            if len != 0 && cache.try_get_page(lba).is_some() {
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

            let acquired = match cache.get_or_create_write_page(lba, block_off == 0).await {
                Ok(acquired) => acquired,
                Err(CacheError::NoFreePages) if cache.cfg.direct_io_on_no_free_pages => {
                    cold_path();

                    if !no_free_flush_started {
                        Self::maybe_start_background_writeback(cache, None);
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

                    if block_off % CACHE_GRANULE != 0 || take % CACHE_GRANULE != 0 {
                        cache
                            .ensure_page_range_valid(lba, &page, block_off, take)
                            .await?;
                    }

                    loop {
                        let guard = match page.data_lock.try_write() {
                            Some(guard) => guard,
                            None => page.data_lock.write().await,
                        };
                        if page.writeback_mask.load(Ordering::Acquire) & bits != 0 {
                            drop(guard);
                            core::future::poll_fn(|cx| loop {
                                let epoch = cache.writeback_notifier.epoch();
                                if page.writeback_mask.load(Ordering::Acquire) & bits == 0 {
                                    return Poll::Ready(());
                                }
                                if cache.writeback_notifier.register_if_unchanged(epoch, cx.waker()) {
                                    return Poll::Pending;
                                }
                            }).await;
                            continue;
                        }
                        let destination = unsafe {
                            &mut core::slice::from_raw_parts_mut(
                                cache.page_ptr(&page),
                                BLOCK_SIZE,
                            )[block_off..block_off + take]
                        };
                        remaining
                            .as_ref()
                            .expect("write buffer disappeared")
                            .copy_to_slice(buffer_offset, destination)
                            .map_err(CacheError::InvalidIoBuffer)?;
                        page.prefetched.store(false, Ordering::Relaxed);
                        cache.mark_cached_page_dirty_range(&page, owner, bits);
                        break;
                    }
                    if block_off + take == BLOCK_SIZE
                        && (page.slot + 1) % cache.writeback_batch_blocks == 0
                        && cache.flush_active.load(Ordering::Acquire)
                    {
                        cache.writeback_notifier.notify_all();
                    }
                }
                WriteAcquire::Direct => {
                    cold_path();

                    let direct_len =
                        Self::direct_write_miss_len(cache, cur_off, len - written).await?;

                    cache
                        .direct_write_at(
                            cur_off,
                            &mut remaining,
                            &mut buffer_offset,
                            direct_len,
                            owner,
                        )
                        .await?;

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
                        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self, None);
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

            if block_off == 0 && page.prefetched.load(Ordering::Relaxed) {
                self.start_read_ahead(lba);
            }

            self.ensure_page_range_valid(lba, &page, block_off, take)
                .await?;

            {
                let _guard = match page.data_lock.try_read() {
                    Some(guard) => guard,
                    None => page.data_lock.read().await,
                };
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

        drop(self.cache_mapping.take());
        self.cache_bytes = 0;
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

        for entry in req.iter_mut() {
            let mut single = Read::new(
                entry.offset,
                entry.len,
                entry.no_buffer,
                entry.buffer.take(),
            );
            let result = async {
                let req = &mut single;
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

                req.len = len;
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

                if !self.cfg.read_allocate
                    && (offset as usize) % BLOCK_SIZE == 0
                    && len % BLOCK_SIZE == 0
                {
                    let block_range =
                        VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
                    let mut has_cached_page = false;
                    let mut lba = block_range.start;

                    while lba < block_range.end {
                        if self.try_get_page(lba).is_some() {
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
            .await;
            entry.len = single.len;
            entry.buffer = single.buffer.take();
            result?;
        }
        Ok(())
    }

    async fn write_request<'req, 'data>(&self, req: &mut Write<'data>) -> Result<(), Self::Error> {
        self.check_open()?;

        for entry in req.iter_mut() {
            let mut single = Write::new(
                entry.offset,
                entry.len,
                entry.no_buffer,
                entry.owner,
                entry.buffer.take(),
            );
            let result = async {
                let req = &mut single;
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

                req.len = len;
                let _ = VolumeCache::<B, BLOCK_SIZE, F>::end_offset(offset, len)?;

                if unlikely(len == 0) {
                    cold_path();
                    return Ok(());
                }

                self.active_writes.fetch_add(1, Ordering::AcqRel);
                self.write_epoch.fetch_add(1, Ordering::AcqRel);
                let _write_guard = CacheWriteGuard {
                    active: &self.active_writes,
                };
                let range = VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
                self.wait_for_read_ahead(range).await;

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

                if !self.cfg.write_allocate
                    && (offset as usize) % BLOCK_SIZE == 0
                    && len % BLOCK_SIZE == 0
                {
                    let block_range =
                        VolumeCache::<B, BLOCK_SIZE, F>::block_range_from_bytes(offset, len)?;
                    let mut has_cached_page = false;
                    let mut lba = block_range.start;

                    while lba < block_range.end {
                        if self.try_get_page(lba).is_some() {
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

                        VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(
                            self, None,
                        );
                        return Ok(());
                    }
                }

                let buffer = req.buffer.take().ok_or(CacheError::InvalidConfig)?;

                VolumeCache::<B, BLOCK_SIZE, F>::write_at_inner(self, offset, buffer, len, owner)
                    .await?;
                VolumeCache::<B, BLOCK_SIZE, F>::maybe_start_background_writeback(self, None);
                Ok(())
            }
            .await;
            entry.len = single.len;
            entry.buffer = single.buffer.take();
            result?;
        }
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
            if let Err(err) = cache.flush_internal_all().await {
                VolumeCache::<B, BLOCK_SIZE, F>::report_background_writeback_error(&err);
            }
        });
    }
}
