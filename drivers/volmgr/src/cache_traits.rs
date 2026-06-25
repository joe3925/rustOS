use kernel_api::async_ffi::FfiFuture;
use kernel_api::dma::dma::{IoBufferBacking, IoBufferError};
use kernel_api::kernel_types::dma::{Described, FromDevice, IoBuffer};
use kernel_api::request::{Read, RequestHandle, Write};

#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    pub capacity_blocks: usize,
    pub shards: usize,
    pub flush_parallelism: usize,
    pub write_allocate: bool,
    pub read_allocate: bool,
    pub direct_io_on_no_free_pages: bool,
    pub dirty_high_watermark_blocks: usize,
    pub dirty_low_watermark_blocks: usize,
    pub dma_map_entire_cache: bool,
}

impl CacheConfig {
    pub const fn new(
        capacity_blocks: usize,
        dirty_high_watermark_percent: u8,
        dirty_low_watermark_percent: u8,
    ) -> Self {
        let high_percent = if dirty_high_watermark_percent > 100 {
            100usize
        } else {
            dirty_high_watermark_percent as usize
        };

        let low_percent = if dirty_low_watermark_percent > 100 {
            100usize
        } else {
            dirty_low_watermark_percent as usize
        };

        let high = if capacity_blocks == 0 || high_percent == 0 {
            0
        } else {
            capacity_blocks
                .saturating_mul(high_percent)
                .saturating_add(99)
                / 100
        };

        let mut low = capacity_blocks.saturating_mul(low_percent) / 100;

        if low > high {
            low = high;
        }

        Self {
            capacity_blocks,
            shards: 16,
            flush_parallelism: 4,
            write_allocate: true,
            read_allocate: true,
            direct_io_on_no_free_pages: true,
            dirty_high_watermark_blocks: high,
            dirty_low_watermark_blocks: low,
            dma_map_entire_cache: true,
        }
    }
}

#[derive(Debug)]
pub enum CacheError<E> {
    Backend(E),
    InvalidConfig,
    OffsetOverflow,
    Closed,
    NoFreePages,
    InsufficientResources,
    InvalidIoBuffer(IoBufferError),
}

impl<E: Clone> Clone for CacheError<E> {
    fn clone(&self) -> Self {
        match self {
            CacheError::Backend(e) => CacheError::Backend(e.clone()),
            CacheError::InvalidConfig => CacheError::InvalidConfig,
            CacheError::OffsetOverflow => CacheError::OffsetOverflow,
            CacheError::Closed => CacheError::Closed,
            CacheError::NoFreePages => CacheError::NoFreePages,
            CacheError::InsufficientResources => CacheError::InsufficientResources,
            CacheError::InvalidIoBuffer(e) => CacheError::InvalidIoBuffer(*e),
        }
    }
}

pub trait VolumeCacheBackend: Send + Sync + 'static {
    type Error: Send + Sync + core::fmt::Debug + 'static;

    fn read_request<'a, 'req, 'data>(
        &'a self,
        req: &'a mut RequestHandle<'req, Read<'data>>,
    ) -> FfiFuture<Result<(), Self::Error>>;

    fn read_phys_framed<'a, 'buffer>(
        &'a self,
        lba: u64,
        blocks: usize,
        buffer: IoBuffer<'buffer, 'buffer, Described, FromDevice>,
    ) -> FfiFuture<Result<usize, Self::Error>>;

    fn write_request<'a, 'req, 'data>(
        &'a self,
        req: &'a mut RequestHandle<'req, Write<'data>>,
    ) -> FfiFuture<Result<(), Self::Error>>;

    fn flush_device(&self) -> FfiFuture<Result<(), Self::Error>>;

    fn dma_map_cache(&self, backing: &mut IoBufferBacking) -> FfiFuture<Result<(), Self::Error>>;
}

pub trait VolumeCacheOps {
    type Error;

    async fn read_request<'req, 'data>(
        &self,
        req: &mut RequestHandle<'req, Read<'data>>,
    ) -> Result<(), Self::Error>;

    async fn write_request<'req, 'data>(
        &self,
        req: &mut RequestHandle<'req, Write<'data>>,
    ) -> Result<(), Self::Error>;

    async fn flush(&self) -> Result<(), Self::Error>;
    async fn flush_owner(&self, owner: u64) -> Result<(), Self::Error>;

    fn flush_background_pass(&self);
}
