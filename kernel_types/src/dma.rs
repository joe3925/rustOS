use alloc::sync::Arc;
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr;
use kernel_macros::RequestPayload;

use crate::device::DeviceObject;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DmaDeviceHandle(pub u64);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DmaPciDeviceIdentity {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub requester_id: u16,
    pub flags: u32,
    pub command: u16,
    pub reserved: u16,
    pub config_space_phys: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DmaDeviceState {
    pub registered: u8,
    pub activated: u8,
    pub iommu_vendor: u8,
    pub reserved0: u8,
    pub remapper_index: u32,
    pub active_mappings: u32,
    pub reserved1: u32,
    pub domain_id: u64,
}

pub const DMA_IOMMU_VENDOR_NONE: u8 = 0;
pub const DMA_IOMMU_VENDOR_INTEL_DMAR: u8 = 1;
pub const DMA_IOMMU_VENDOR_AMD_IVRS: u8 = 2;

pub const DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE: u32 = 1 << 0;
pub const DMA_PCI_IDENTITY_FLAG_BUS_MASTER_ENABLED: u32 = 1 << 1;

pub const IOBUFFER_PAGE_SIZE: usize = 4096;
pub const IOBUFFER_INLINE_PAGE_CAPACITY: usize = 32;
pub const IOBUFFER_INLINE_SEGMENT_CAPACITY: usize = 32;

pub enum Described {}
pub enum Pinned {}
pub enum DmaMapped {}

pub enum ToDevice {}
pub enum FromDevice {}
pub enum Bidirectional {}

mod sealed {
    pub trait IoBufferState {}
    pub trait IoBufferDirection {}
    pub trait WritableDirection {}
    pub trait MappableState {}
}

pub trait IoBufferState: sealed::IoBufferState {}
impl<T: sealed::IoBufferState> IoBufferState for T {}

pub trait IoBufferDirection: sealed::IoBufferDirection {}
impl<T: sealed::IoBufferDirection> IoBufferDirection for T {}

pub trait WritableIoBufferDirection: IoBufferDirection + sealed::WritableDirection {}
impl<T: IoBufferDirection + sealed::WritableDirection> WritableIoBufferDirection for T {}

impl sealed::IoBufferState for Described {}
impl sealed::IoBufferState for Pinned {}
impl sealed::IoBufferState for DmaMapped {}

pub trait MappableIoBufferState: IoBufferState + sealed::MappableState {}
impl<T: IoBufferState + sealed::MappableState> MappableIoBufferState for T {}

impl sealed::MappableState for Described {}
impl sealed::MappableState for Pinned {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaMappingStrategy {
    /// Entire buffer mapped as a single contiguous IOVA region -> 1 segment.
    SingleContiguous,
    /// Buffer divided into N equal chunks; each chunk is one contiguous IOVA
    /// segment. Requires `buffer.len() % chunk_size == 0` and
    /// `chunk_size % PAGE_SIZE == 0`.
    ContiguousChunks { chunk_size: usize },
    /// Every page's IOVA == its physical address. Adjacent physical pages are
    /// merged into a single segment.
    FullIdentity,
    /// One IOVA segment per page (scatter-gather, no merging).
    ScatterGather,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaMapError {
    /// IOMMU not available or device not registered.
    NoIommu,
    /// Mapping would require allocating synthetic IOVA space, which is not
    /// implemented yet for this path.
    RemappingUnavailable,
    /// `chunk_size` does not evenly divide `buffer.len()`.
    UnalignedChunkSize {
        buffer_len: usize,
        chunk_size: usize,
    },
    /// `chunk_size` is not a multiple of `IOBUFFER_PAGE_SIZE`.
    ChunkSizeNotPageAligned { chunk_size: usize },
    /// Buffer spans more pages than inline page-frame storage can describe
    /// (capacity = 32).
    PageCapacityExceeded { required: usize },
    /// Too many resulting segments to fit in inline storage (capacity = 32).
    SegmentCapacityExceeded { required: usize },
    /// `chunk_size` is zero or buffer is empty.
    InvalidSize,
}

impl sealed::IoBufferDirection for ToDevice {}
impl sealed::IoBufferDirection for FromDevice {}
impl sealed::IoBufferDirection for Bidirectional {}

impl sealed::WritableDirection for FromDevice {}
impl sealed::WritableDirection for Bidirectional {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoBufferPageFrame {
    pub phys_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoBufferDmaSegment {
    pub dma_addr: u64,
    pub byte_len: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoBufferError {
    PageCapacityExceeded { required: usize, capacity: usize },
    SegmentCapacityExceeded { required: usize, capacity: usize },
}

const EMPTY_PAGE_FRAME: IoBufferPageFrame = IoBufferPageFrame { phys_addr: 0 };
const EMPTY_DMA_SEGMENT: IoBufferDmaSegment = IoBufferDmaSegment {
    dma_addr: 0,
    byte_len: 0,
    reserved: 0,
};

pub type DmaUnmapFn = fn(&Arc<DeviceObject>, usize);

#[repr(C)]
struct DmaDropContext {
    mapped_by: Arc<DeviceObject>,
    unmap: DmaUnmapFn,
    cookie: usize,
}

#[repr(C)]
enum IoBufferBorrow<'a> {
    ReadOnly(&'a [u8]),
    Writable(&'a mut [u8]),
}

impl<'a> IoBufferBorrow<'a> {
    fn len(&self) -> usize {
        match self {
            Self::ReadOnly(buf) => buf.len(),
            Self::Writable(buf) => buf.len(),
        }
    }

    fn as_ptr(&self) -> *const u8 {
        match self {
            Self::ReadOnly(buf) => buf.as_ptr(),
            Self::Writable(buf) => buf.as_ptr(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::ReadOnly(buf) => buf,
            Self::Writable(buf) => buf,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            Self::Writable(buf) => buf.as_mut_ptr(),
            Self::ReadOnly(_) => unreachable!("mutable IoBuffer access on read-only borrow"),
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Writable(buf) => buf,
            Self::ReadOnly(_) => unreachable!("mutable IoBuffer access on read-only borrow"),
        }
    }
}

/// ABI-erased `IoBuffer` storage passed across the kernel DMA map/unmap calls.
#[repr(C)]
pub struct IoBufferInner<'a> {
    borrow: IoBufferBorrow<'a>,
    virt_addr: usize,
    page_base: usize,
    page_offset: usize,
    page_count: usize,
    page_frames: [IoBufferPageFrame; IOBUFFER_INLINE_PAGE_CAPACITY],
    page_frames_len: usize,
    dma_segments: [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
    dma_segments_len: usize,
    mapped_by: Option<Arc<DeviceObject>>,
    dma_drop: Option<DmaDropContext>,
}

impl<'a> IoBufferInner<'a> {
    fn new_read_only(buf: &'a [u8]) -> Self {
        Self::new(IoBufferBorrow::ReadOnly(buf))
    }

    fn new_writable(buf: &'a mut [u8]) -> Self {
        Self::new(IoBufferBorrow::Writable(buf))
    }

    fn new(borrow: IoBufferBorrow<'a>) -> Self {
        let virt_addr = borrow.as_ptr() as usize;
        let len = borrow.len();
        let page_offset = virt_addr & (IOBUFFER_PAGE_SIZE - 1);
        let page_base = virt_addr - page_offset;
        let span = page_offset.saturating_add(len);
        let page_count = if span == 0 {
            0
        } else {
            span.div_ceil(IOBUFFER_PAGE_SIZE)
        };

        Self {
            borrow,
            virt_addr,
            page_base,
            page_offset,
            page_count,
            page_frames: [EMPTY_PAGE_FRAME; IOBUFFER_INLINE_PAGE_CAPACITY],
            page_frames_len: 0,
            dma_segments: [EMPTY_DMA_SEGMENT; IOBUFFER_INLINE_SEGMENT_CAPACITY],
            dma_segments_len: 0,
            mapped_by: None,
            dma_drop: None,
        }
    }

    pub fn len(&self) -> usize {
        self.borrow.len()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.borrow.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.borrow.as_slice()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.borrow.as_mut_ptr()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.borrow.as_mut_slice()
    }

    pub fn page_frames(&self) -> &[IoBufferPageFrame] {
        &self.page_frames[..self.page_frames_len]
    }

    pub fn dma_segments(&self) -> &[IoBufferDmaSegment] {
        &self.dma_segments[..self.dma_segments_len]
    }

    pub fn replace_page_frames(&mut self, frames: &[IoBufferPageFrame]) -> Result<(), IoBufferError> {
        if frames.len() > IOBUFFER_INLINE_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: frames.len(),
                capacity: IOBUFFER_INLINE_PAGE_CAPACITY,
            });
        }

        self.page_frames.fill(EMPTY_PAGE_FRAME);
        self.page_frames[..frames.len()].copy_from_slice(frames);
        self.page_frames_len = frames.len();
        Ok(())
    }

    pub fn replace_dma_segments(
        &mut self,
        segments: &[IoBufferDmaSegment],
    ) -> Result<(), IoBufferError> {
        if segments.len() > IOBUFFER_INLINE_SEGMENT_CAPACITY {
            return Err(IoBufferError::SegmentCapacityExceeded {
                required: segments.len(),
                capacity: IOBUFFER_INLINE_SEGMENT_CAPACITY,
            });
        }

        self.dma_segments.fill(EMPTY_DMA_SEGMENT);
        self.dma_segments[..segments.len()].copy_from_slice(segments);
        self.dma_segments_len = segments.len();
        Ok(())
    }

    pub fn set_dma_drop(&mut self, mapped_by: Arc<DeviceObject>, unmap: DmaUnmapFn, cookie: usize) {
        self.mapped_by = Some(mapped_by.clone());
        self.dma_drop = Some(DmaDropContext {
            mapped_by,
            unmap,
            cookie,
        });
    }

    pub fn page_base_address(&self) -> usize {
        self.page_base
    }

    pub fn page_offset(&self) -> usize {
        self.page_offset
    }

    pub fn page_count(&self) -> usize {
        self.page_count
    }

    pub fn page_frames_storage_mut(
        &mut self,
    ) -> &mut [IoBufferPageFrame; IOBUFFER_INLINE_PAGE_CAPACITY] {
        &mut self.page_frames
    }

    pub fn set_page_frames_len(&mut self, len: usize) -> Result<(), IoBufferError> {
        if len > IOBUFFER_INLINE_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: len,
                capacity: IOBUFFER_INLINE_PAGE_CAPACITY,
            });
        }
        self.page_frames_len = len;
        Ok(())
    }

    pub fn dma_segments_storage_mut(
        &mut self,
    ) -> &mut [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY] {
        &mut self.dma_segments
    }

    pub fn set_dma_segments_len(&mut self, len: usize) -> Result<(), IoBufferError> {
        if len > IOBUFFER_INLINE_SEGMENT_CAPACITY {
            return Err(IoBufferError::SegmentCapacityExceeded {
                required: len,
                capacity: IOBUFFER_INLINE_SEGMENT_CAPACITY,
            });
        }
        self.dma_segments_len = len;
        Ok(())
    }

    pub fn remove_dma_mapping_in_place(&mut self) {
        if let Some(ctx) = self.dma_drop.take() {
            (ctx.unmap)(&ctx.mapped_by, ctx.cookie);
        }
        self.mapped_by = None;
        self.dma_segments.fill(EMPTY_DMA_SEGMENT);
        self.dma_segments_len = 0;
    }
}

#[repr(C)]
#[derive(RequestPayload)]
pub struct IoBuffer<'a, State: IoBufferState, Direction: IoBufferDirection> {
    inner: IoBufferInner<'a>,
    _state: PhantomData<fn() -> State>,
    _direction: PhantomData<fn() -> Direction>,
}

impl<'a, State: IoBufferState, Direction: IoBufferDirection> IoBuffer<'a, State, Direction> {
    /// Rebuild an `IoBuffer` from its ABI-erased inner storage.
    pub fn from_inner(inner: IoBufferInner<'a>) -> Self {
        Self {
            inner,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }

    /// Erase the state and direction markers while preserving the underlying
    /// buffer storage.
    pub fn into_inner(self) -> IoBufferInner<'a> {
        let this = ManuallyDrop::new(self);
        unsafe { ptr::read(&this.inner) }
    }

    #[allow(dead_code)]
    fn cast_state<NextState: IoBufferState>(self) -> IoBuffer<'a, NextState, Direction> {
        IoBuffer::<'a, NextState, Direction>::from_inner(self.into_inner())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    pub fn virtual_address(&self) -> usize {
        self.inner.virt_addr
    }

    pub fn page_base_address(&self) -> usize {
        self.inner.page_base
    }

    pub fn page_offset(&self) -> usize {
        self.inner.page_offset
    }

    pub fn page_count(&self) -> usize {
        self.inner.page_count
    }

    pub fn page_frames(&self) -> &[IoBufferPageFrame] {
        self.inner.page_frames()
    }

    pub fn dma_segments(&self) -> &[IoBufferDmaSegment] {
        self.inner.dma_segments()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl<'a, Direction: IoBufferDirection> IoBuffer<'a, DmaMapped, Direction> {
    pub fn mapped_by(&self) -> Option<&Arc<DeviceObject>> {
        self.inner.mapped_by.as_ref()
    }
}

impl<'a, State: IoBufferState, Direction: WritableIoBufferDirection>
    IoBuffer<'a, State, Direction>
{
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }
}

impl<'a> IoBuffer<'a, Described, ToDevice> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self::from_inner(IoBufferInner::new_read_only(buf))
    }
}

impl<'a> IoBuffer<'a, Described, FromDevice> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self::from_inner(IoBufferInner::new_writable(buf))
    }
}

impl<'a> IoBuffer<'a, Described, Bidirectional> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self::from_inner(IoBufferInner::new_writable(buf))
    }
}

impl<'a, State: IoBufferState, Direction: IoBufferDirection> Drop
    for IoBuffer<'a, State, Direction>
{
    fn drop(&mut self) {
        if let Some(drop_ctx) = self.inner.dma_drop.take() {
            (drop_ctx.unmap)(&drop_ctx.mapped_by, drop_ctx.cookie);
        }
    }
}

impl<'a, S: MappableIoBufferState, D: IoBufferDirection> IoBuffer<'a, S, D> {
    /// Consume this buffer, fill DMA segments, register the unmap callback,
    /// and return an `IoBuffer<DmaMapped, D>`.
    ///
    /// On error the original buffer is returned so the caller can recover it.
    pub fn apply_dma_mapping(
        self,
        segments: &[IoBufferDmaSegment],
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<IoBuffer<'a, DmaMapped, D>, (Self, IoBufferError)> {
        let mut inner = self.into_inner();
        if let Err(e) = inner.replace_dma_segments(segments) {
            return Err((IoBuffer::<'a, S, D>::from_inner(inner), e));
        }
        inner.set_dma_drop(mapped_by, unmap, cookie);
        Ok(IoBuffer::<'a, DmaMapped, D>::from_inner(inner))
    }
}

impl<'a, D: IoBufferDirection> IoBuffer<'a, DmaMapped, D> {
    /// Consume this `DmaMapped` buffer, invoke the stored unmap callback,
    /// clear all DMA segments, and return a `Described` buffer wrapping the
    /// same underlying slice.
    pub fn remove_dma_mapping(self) -> IoBuffer<'a, Described, D> {
        let mut inner = self.into_inner();
        if let Some(ctx) = inner.dma_drop.take() {
            (ctx.unmap)(&ctx.mapped_by, ctx.cookie);
        }
        inner.mapped_by = None;
        inner.dma_segments.fill(EMPTY_DMA_SEGMENT);
        inner.dma_segments_len = 0;
        IoBuffer::<'a, Described, D>::from_inner(inner)
    }
}

impl<'a, State: IoBufferState, Direction: IoBufferDirection> fmt::Debug
    for IoBuffer<'a, State, Direction>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoBuffer")
            .field("state", &core::any::type_name::<State>())
            .field("direction", &core::any::type_name::<Direction>())
            .field("virt_addr", &self.inner.virt_addr)
            .field("len", &self.inner.len())
            .field("page_base", &self.inner.page_base)
            .field("page_offset", &self.inner.page_offset)
            .field("page_count", &self.inner.page_count)
            .field("page_frames_len", &self.inner.page_frames_len)
            .field("dma_segments_len", &self.inner.dma_segments_len)
            .field("mapped", &self.inner.mapped_by.is_some())
            .finish()
    }
}
