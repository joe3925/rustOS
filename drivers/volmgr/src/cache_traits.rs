use kernel_api::async_ffi::FfiFuture;
use kernel_api::request::RequestHandle;

#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    pub capacity_blocks: usize,
    pub shards: usize,
    pub flush_parallelism: usize,
    pub write_allocate: bool,
    pub read_allocate: bool,
}

impl CacheConfig {
    pub const fn new(capacity_blocks: usize) -> Self {
        Self {
            capacity_blocks,
            shards: 16,
            flush_parallelism: 4,
            write_allocate: true,
            read_allocate: true,
        }
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
}

/// Backend I/O interface used by the cache.
///
/// Implement this on your volume device wrapper (or a small adapter around it).
///
/// Requirements:
/// - `read_block` and `write_block` must operate on exactly one logical block.
/// - `out.len()` / `data.len()` will always equal the cache block size (`BLOCK_SIZE`).
/// - `lba` is a logical block index, not a byte offset.
/// - `flush_device` should commit device-side writeback state (if any).

// Ffi future is used instead of BoxFuture here because we already have slab alloc for Ffi future.
pub trait VolumeCacheBackend: Send + Sync + 'static {
    type Error: Send + Sync + 'static;

    fn read_block<'a>(&'a self, lba: u64, out: &'a mut [u8]) -> FfiFuture<Result<(), Self::Error>>;
    fn write_block<'a>(&'a self, lba: u64, data: &'a [u8]) -> FfiFuture<Result<(), Self::Error>>;
    fn write_request<'a>(
        &'a self,
        req: &'a mut RequestHandle<'_>,
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
    async fn write_through_at(&self, offset: u64, data: &[u8]) -> Result<(), Self::Error>;

    async fn flush(&self) -> Result<(), Self::Error>;
    async fn flush_range(&self, offset: u64, len: usize) -> Result<(), Self::Error>;

    async fn invalidate_range(&self, offset: u64, len: usize) -> Result<usize, Self::Error>;
    async fn drop_clean(&self) -> Result<usize, Self::Error>;

    fn flush_background_pass(&self);
    async fn flush_async(&self);
    async fn stats(&self) -> CacheStats;
    async fn cached_blocks(&self) -> usize;
}
