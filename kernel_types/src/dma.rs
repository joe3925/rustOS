use alloc::sync::Arc;
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::{self, NonNull};

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

type DmaUnmapFn = fn(&Arc<DeviceObject>, usize);

struct DmaDropContext {
    mapped_by: Arc<DeviceObject>,
    unmap: DmaUnmapFn,
    cookie: usize,
}

struct IoBufferInner {
    ptr: NonNull<u8>,
    len: usize,
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

impl IoBufferInner {
    fn new(ptr: *mut u8, len: usize) -> Self {
        let ptr = NonNull::new(ptr).unwrap_or_else(NonNull::dangling);
        let virt_addr = ptr.as_ptr() as usize;
        let page_offset = virt_addr & (IOBUFFER_PAGE_SIZE - 1);
        let page_base = virt_addr - page_offset;
        let span = page_offset.saturating_add(len);
        let page_count = if span == 0 {
            0
        } else {
            span.div_ceil(IOBUFFER_PAGE_SIZE)
        };

        Self {
            ptr,
            len,
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

    fn page_frames(&self) -> &[IoBufferPageFrame] {
        &self.page_frames[..self.page_frames_len]
    }

    fn dma_segments(&self) -> &[IoBufferDmaSegment] {
        &self.dma_segments[..self.dma_segments_len]
    }

    #[allow(dead_code)]
    fn replace_page_frames(&mut self, frames: &[IoBufferPageFrame]) -> Result<(), IoBufferError> {
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

    #[allow(dead_code)]
    fn replace_dma_segments(
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

    #[allow(dead_code)]
    fn set_dma_drop(&mut self, mapped_by: Arc<DeviceObject>, unmap: DmaUnmapFn, cookie: usize) {
        self.mapped_by = Some(mapped_by.clone());
        self.dma_drop = Some(DmaDropContext {
            mapped_by,
            unmap,
            cookie,
        });
    }
}

#[repr(C)]
pub struct IoBuffer<'a, State: IoBufferState, Direction: IoBufferDirection> {
    inner: IoBufferInner,
    _borrow: PhantomData<&'a [u8]>,
    _state: PhantomData<State>,
    _direction: PhantomData<Direction>,
}

impl<'a, State: IoBufferState, Direction: IoBufferDirection> IoBuffer<'a, State, Direction> {
    fn from_inner(inner: IoBufferInner) -> Self {
        Self {
            inner,
            _borrow: PhantomData,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }

    #[allow(dead_code)]
    fn into_inner(self) -> IoBufferInner {
        let this = ManuallyDrop::new(self);
        unsafe { ptr::read(&this.inner) }
    }

    #[allow(dead_code)]
    fn cast_state<NextState: IoBufferState>(self) -> IoBuffer<'a, NextState, Direction> {
        IoBuffer::<'a, NextState, Direction>::from_inner(self.into_inner())
    }

    pub fn len(&self) -> usize {
        self.inner.len
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len == 0
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
        self.inner.ptr.as_ptr() as *const u8
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len()) }
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
        self.inner.ptr.as_ptr()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
}

impl<'a> IoBuffer<'a, Described, ToDevice> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self::from_inner(IoBufferInner::new(buf.as_ptr() as *mut u8, buf.len()))
    }
}

impl<'a> IoBuffer<'a, Described, FromDevice> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self::from_inner(IoBufferInner::new(buf.as_mut_ptr(), buf.len()))
    }
}

impl<'a> IoBuffer<'a, Described, Bidirectional> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self::from_inner(IoBufferInner::new(buf.as_mut_ptr(), buf.len()))
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

impl<'a, State: IoBufferState, Direction: IoBufferDirection> fmt::Debug
    for IoBuffer<'a, State, Direction>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoBuffer")
            .field("state", &core::any::type_name::<State>())
            .field("direction", &core::any::type_name::<Direction>())
            .field("virt_addr", &self.inner.virt_addr)
            .field("len", &self.inner.len)
            .field("page_base", &self.inner.page_base)
            .field("page_offset", &self.inner.page_offset)
            .field("page_count", &self.inner.page_count)
            .field("page_frames_len", &self.inner.page_frames_len)
            .field("dma_segments_len", &self.inner.dma_segments_len)
            .field("mapped", &self.inner.mapped_by.is_some())
            .finish()
    }
}
