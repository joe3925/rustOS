use kernel_api::async_ffi::FfiFuture;
use kernel_api::kernel_types::dma::{FromDevice, IoBuffer, PhysFramed, ToDevice};
use kernel_api::request::RequestHandle;

#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    pub capacity_blocks: usize,
    pub shards: usize,
    pub flush_parallelism: usize,
    pub write_allocate: bool,
    pub read_allocate: bool,
    pub lazy_page_allocation: bool,
    pub lazy_index_allocation: bool,
    /// When page allocation/reclaim cannot supply a cache page, bypass the cache
    /// and issue the current request directly to the lower device.
    pub direct_io_on_no_free_pages: bool,
    /// Start background writeback when dirty pages reach this count.
    pub dirty_high_watermark_blocks: usize,
    /// Background writeback keeps flushing until dirty pages drop to this count.
    pub dirty_low_watermark_blocks: usize,
}

impl CacheConfig {
    pub const fn new(capacity_blocks: usize) -> Self {
        let high = if capacity_blocks > 4 {
            (capacity_blocks * 3) / 4
        } else {
            capacity_blocks
        };
        let low = if capacity_blocks > 4 {
            capacity_blocks / 2
        } else {
            0
        };
        Self {
            capacity_blocks,
            shards: 16,
            flush_parallelism: 4,
            write_allocate: true,
            read_allocate: true,
            lazy_page_allocation: false,
            lazy_index_allocation: false,
            direct_io_on_no_free_pages: true,
            dirty_high_watermark_blocks: high,
            dirty_low_watermark_blocks: low,
        }
    }

    pub const fn with_lazy_page_allocation(mut self, enabled: bool) -> Self {
        self.lazy_page_allocation = enabled;
        self
    }
    pub const fn with_lazy_index_allocation(mut self, enabled: bool) -> Self {
        self.lazy_index_allocation = enabled;
        self
    }
    pub const fn with_direct_io_on_no_free_pages(mut self, enabled: bool) -> Self {
        self.direct_io_on_no_free_pages = enabled;
        self
    }

    pub const fn with_dirty_watermarks(mut self, high_blocks: usize, low_blocks: usize) -> Self {
        self.dirty_high_watermark_blocks = high_blocks;
        self.dirty_low_watermark_blocks = low_blocks;
        self
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    pub read_hits: u64,
    pub read_misses: u64,
    pub write_hits: u64,
    pub write_misses: u64,
    pub backend_reads: u64,
    pub backend_writes: u64,
    pub flush_attempts: u64,
    pub flush_success: u64,
    pub flush_skipped_clean: u64,
    pub flush_skipped_busy: u64,
    pub evictions: u64,
    pub failed_evictions: u64,
    pub oversubscribe_inserts: u64,
    pub direct_writebacks: u64,
}

#[derive(Debug)]
pub enum CacheError<E> {
    Backend(E),
    InvalidConfig,
    OffsetOverflow,
    Closed,
    NoFreePages,
    InvalidIoBuffer,
}

impl<E: Clone> Clone for CacheError<E> {
    fn clone(&self) -> Self {
        match self {
            CacheError::Backend(e) => CacheError::Backend(e.clone()),
            CacheError::InvalidConfig => CacheError::InvalidConfig,
            CacheError::OffsetOverflow => CacheError::OffsetOverflow,
            CacheError::Closed => CacheError::Closed,
            CacheError::NoFreePages => CacheError::NoFreePages,
            CacheError::InvalidIoBuffer => CacheError::InvalidIoBuffer,
        }
    }
}

/// Backend I/O interface used by the cache.
///
/// Implement this on your volume device wrapper (or a small adapter around it).
///
/// Requirements:
/// - `read_phys_framed` and `write_phys_framed` operate on one or more contiguous logical blocks.
/// - `lba` is a logical block index, not a byte offset.
/// - `flush_device` should commit device-side writeback state (if any).

// Ffi future is used instead of BoxFuture here because we already have slab alloc for Ffi future.
pub trait VolumeCacheBackend: Send + Sync + 'static {
    type Error: Send + Sync + core::fmt::Debug + 'static;

    fn read_phys_framed<'a, 'buffer>(
        &'a self,
        lba: u64,
        blocks: usize,
        buffer: IoBuffer<'buffer, PhysFramed, FromDevice>,
    ) -> FfiFuture<Result<usize, Self::Error>>;
    fn write_request<'a>(
        &'a self,
        req: &'a mut RequestHandle<'_, '_>,
    ) -> FfiFuture<Result<(), Self::Error>>;
    fn write_phys_framed<'a, 'buffer>(
        &'a self,
        lba: u64,
        blocks: usize,
        buffer: IoBuffer<'buffer, PhysFramed, ToDevice>,
    ) -> FfiFuture<Result<(), Self::Error>>;
    fn flush_device(&self) -> FfiFuture<Result<(), Self::Error>>;
}

/// Async cache operations exposed to the rest of the volume driver.
///
/// Implementers should support unaligned byte offsets and lengths by internally
/// doing block-sized reads/writes as needed.
///
/// `write_at` is write-back (cached) when configured to allocate; it may defer device writes.
/// `write_through_at` should not return until the written range is pushed to the backend.
/// `flush_background_pass` should start background work and return quickly.
pub trait VolumeCacheOps {
    type Error;

    async fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<(), Self::Error>;
    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error>;
    async fn write_at_owned(&self, offset: u64, data: &[u8], owner: u64)
    -> Result<(), Self::Error>;
    async fn write_through_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error>;
    async fn write_through_at_owned(
        &self,
        offset: u64,
        data: &[u8],
        owner: u64,
    ) -> Result<(), Self::Error>;

    async fn flush(&self) -> Result<(), Self::Error>;
    async fn flush_owner(&self, owner: u64) -> Result<(), Self::Error>;
    async fn flush_range(&self, offset: u64, len: usize) -> Result<(), Self::Error>;

    async fn invalidate_range(&self, offset: u64, len: usize) -> Result<usize, Self::Error>;
    async fn drop_clean(&self) -> Result<usize, Self::Error>;

    fn flush_background_pass(&self);
    async fn flush_async(&self);
    async fn stats(&self) -> CacheStats;
    async fn cached_blocks(&self) -> usize;
}
