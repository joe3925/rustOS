use alloc::sync::Arc;
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr;
use kernel_macros::RequestPayload;
use x86_64::registers::control::Cr3;

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
pub const IOBUFFER_FRAME_SIZE_4KIB: u64 = 4 * 1024;
pub const IOBUFFER_FRAME_SIZE_2MIB: u64 = 2 * 1024 * 1024;
pub const IOBUFFER_FRAME_SIZE_1GIB: u64 = 1024 * 1024 * 1024;
pub const IOBUFFER_INLINE_PAGE_CAPACITY: usize = 512;
pub const IOBUFFER_INLINE_FRAME_CAPACITY: usize = IOBUFFER_INLINE_PAGE_CAPACITY;
pub const IOBUFFER_INLINE_SEGMENT_CAPACITY: usize = 32;

pub enum Described {}
pub enum Pinned {}
pub enum PhysFramed {}
pub struct DmaMapped<Source = Described>(PhantomData<fn() -> Source>);

pub enum ToDevice {}
pub enum FromDevice {}
pub enum Bidirectional {}

mod sealed {
    pub trait IoBufferState {}
    pub trait IoBufferDirection {}
    pub trait WritableDirection {}
    pub trait MappableState {}
    pub trait VirtualBackedState {}
}

pub trait IoBufferState: sealed::IoBufferState {}
impl<T: sealed::IoBufferState> IoBufferState for T {}

pub trait IoBufferDirection: sealed::IoBufferDirection {}
impl<T: sealed::IoBufferDirection> IoBufferDirection for T {}

pub trait WritableIoBufferDirection: IoBufferDirection + sealed::WritableDirection {}
impl<T: IoBufferDirection + sealed::WritableDirection> WritableIoBufferDirection for T {}

impl sealed::IoBufferState for Described {}
impl sealed::IoBufferState for Pinned {}
impl sealed::IoBufferState for PhysFramed {}
impl<S: sealed::IoBufferState> sealed::IoBufferState for DmaMapped<S> {}

pub trait MappableIoBufferState: IoBufferState + sealed::MappableState {}
impl<T: IoBufferState + sealed::MappableState> MappableIoBufferState for T {}

pub trait VirtualBackedIoBufferState: IoBufferState + sealed::VirtualBackedState {}
impl<T: IoBufferState + sealed::VirtualBackedState> VirtualBackedIoBufferState for T {}

impl sealed::MappableState for Described {}
impl sealed::MappableState for Pinned {}
impl sealed::MappableState for PhysFramed {}

impl sealed::VirtualBackedState for Described {}
impl sealed::VirtualBackedState for Pinned {}
impl<S: sealed::VirtualBackedState> sealed::VirtualBackedState for DmaMapped<S> {}

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
    /// Buffer spans more frames than inline frame storage can describe
    /// (capacity = 512).
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
    pub byte_len: u64,
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
    PageCapacityExceeded {
        required: usize,
        capacity: usize,
    },
    SegmentCapacityExceeded {
        required: usize,
        capacity: usize,
    },
    InvalidFrameSize {
        byte_len: u64,
    },
    InvalidFrameAlignment {
        phys_addr: u64,
        byte_len: u64,
    },
    InvalidFrameLayout {
        frame_offset: usize,
        byte_len: usize,
    },
    TranslationFailed {
        virt_addr: usize,
    },
}

const EMPTY_PAGE_FRAME: IoBufferPageFrame = IoBufferPageFrame {
    phys_addr: 0,
    byte_len: 0,
};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VirtualFrameTranslation {
    phys_addr: u64,
    byte_len: u64,
    offset: u64,
}

const PRESENT: u64 = 1 << 0;
const HUGE_PAGE: u64 = 1 << 7;

const ADDR_MASK_4K: u64 = 0x000f_ffff_ffff_f000;
const ADDR_MASK_2M: u64 = 0x000f_ffff_ffe0_0000;
const ADDR_MASK_1G: u64 = 0x000f_ffff_c000_0000;

#[inline(always)]
fn p4_index(addr: u64) -> usize {
    ((addr >> 39) & 0x1ff) as usize
}

#[inline(always)]
fn p3_index(addr: u64) -> usize {
    ((addr >> 30) & 0x1ff) as usize
}

#[inline(always)]
fn p2_index(addr: u64) -> usize {
    ((addr >> 21) & 0x1ff) as usize
}

#[inline(always)]
fn p1_index(addr: u64) -> usize {
    ((addr >> 12) & 0x1ff) as usize
}

#[inline(always)]
unsafe fn read_pte(table_phys: u64, index: usize) -> u64 {
    let table = (crate::PHYSICAL_MEMORY_OFFSET.as_u64() + table_phys) as *const u64;
    unsafe { core::ptr::read(table.add(index)) }
}

#[inline]
fn is_valid_frame_size(byte_len: u64) -> bool {
    matches!(
        byte_len,
        IOBUFFER_FRAME_SIZE_4KIB | IOBUFFER_FRAME_SIZE_2MIB | IOBUFFER_FRAME_SIZE_1GIB
    )
}

fn translate_virtual_frame(virt_addr: usize) -> Option<VirtualFrameTranslation> {
    let virt = virt_addr as u64;
    let cr3_phys = Cr3::read().0.start_address().as_u64();

    unsafe {
        let pml4e = read_pte(cr3_phys, p4_index(virt));
        if pml4e & PRESENT == 0 {
            return None;
        }

        let pdpt_phys = pml4e & ADDR_MASK_4K;
        let pdpte = read_pte(pdpt_phys, p3_index(virt));
        if pdpte & PRESENT == 0 {
            return None;
        }

        if pdpte & HUGE_PAGE != 0 {
            let offset = virt & (IOBUFFER_FRAME_SIZE_1GIB - 1);
            return Some(VirtualFrameTranslation {
                phys_addr: pdpte & ADDR_MASK_1G,
                byte_len: IOBUFFER_FRAME_SIZE_1GIB,
                offset,
            });
        }

        let pd_phys = pdpte & ADDR_MASK_4K;
        let pde = read_pte(pd_phys, p2_index(virt));
        if pde & PRESENT == 0 {
            return None;
        }

        if pde & HUGE_PAGE != 0 {
            let offset = virt & (IOBUFFER_FRAME_SIZE_2MIB - 1);
            return Some(VirtualFrameTranslation {
                phys_addr: pde & ADDR_MASK_2M,
                byte_len: IOBUFFER_FRAME_SIZE_2MIB,
                offset,
            });
        }

        let pt_phys = pde & ADDR_MASK_4K;
        let pte = read_pte(pt_phys, p1_index(virt));
        if pte & PRESENT == 0 {
            return None;
        }

        let offset = virt & (IOBUFFER_FRAME_SIZE_4KIB - 1);
        Some(VirtualFrameTranslation {
            phys_addr: pte & ADDR_MASK_4K,
            byte_len: IOBUFFER_FRAME_SIZE_4KIB,
            offset,
        })
    }
}

fn describe_virtual_buffer(
    virt_addr: usize,
    byte_len: usize,
    frames: &mut [IoBufferPageFrame; IOBUFFER_INLINE_PAGE_CAPACITY],
) -> Result<(usize, usize), IoBufferError> {
    frames.fill(EMPTY_PAGE_FRAME);
    if byte_len == 0 {
        return Ok((0, 0));
    }

    let mut consumed = 0usize;
    let mut frame_count = 0usize;
    let mut first_frame_offset = 0usize;

    while consumed < byte_len {
        let current = virt_addr
            .checked_add(consumed)
            .ok_or(IoBufferError::TranslationFailed { virt_addr })?;
        let translated = translate_virtual_frame(current)
            .ok_or(IoBufferError::TranslationFailed { virt_addr: current })?;

        if frame_count >= IOBUFFER_INLINE_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: frame_count + 1,
                capacity: IOBUFFER_INLINE_PAGE_CAPACITY,
            });
        }

        if frame_count == 0 {
            first_frame_offset = translated.offset as usize;
        }

        frames[frame_count] = IoBufferPageFrame {
            phys_addr: translated.phys_addr,
            byte_len: translated.byte_len,
        };
        frame_count += 1;

        let bytes_in_frame = (translated.byte_len - translated.offset) as usize;
        consumed += (byte_len - consumed).min(bytes_in_frame);
    }

    Ok((frame_count, first_frame_offset))
}

fn validate_physical_frames(
    frame_offset: usize,
    byte_len: usize,
    frames: &[IoBufferPageFrame],
) -> Result<(), IoBufferError> {
    if frames.len() > IOBUFFER_INLINE_PAGE_CAPACITY {
        return Err(IoBufferError::PageCapacityExceeded {
            required: frames.len(),
            capacity: IOBUFFER_INLINE_PAGE_CAPACITY,
        });
    }

    if byte_len == 0 {
        return Ok(());
    }

    let Some(first) = frames.first() else {
        return Err(IoBufferError::InvalidFrameLayout {
            frame_offset,
            byte_len,
        });
    };

    for frame in frames {
        if !is_valid_frame_size(frame.byte_len) {
            return Err(IoBufferError::InvalidFrameSize {
                byte_len: frame.byte_len,
            });
        }
        if frame.phys_addr & (frame.byte_len - 1) != 0 {
            return Err(IoBufferError::InvalidFrameAlignment {
                phys_addr: frame.phys_addr,
                byte_len: frame.byte_len,
            });
        }
    }

    if frame_offset >= first.byte_len as usize {
        return Err(IoBufferError::InvalidFrameLayout {
            frame_offset,
            byte_len,
        });
    }

    let mut available = (first.byte_len as usize).saturating_sub(frame_offset);
    for frame in &frames[1..] {
        if available >= byte_len {
            return Ok(());
        }
        available = available.saturating_add(frame.byte_len as usize);
    }

    if available < byte_len {
        return Err(IoBufferError::InvalidFrameLayout {
            frame_offset,
            byte_len,
        });
    }

    Ok(())
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
    borrow: Option<IoBufferBorrow<'a>>,
    virt_addr: usize,
    byte_len: usize,
    frame_offset: usize,
    page_frames: [IoBufferPageFrame; IOBUFFER_INLINE_PAGE_CAPACITY],
    page_frames_len: usize,
    dma_segments: [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
    dma_segments_len: usize,
    mapped_by: Option<Arc<DeviceObject>>,
    dma_drop: Option<DmaDropContext>,
}

impl<'a> IoBufferInner<'a> {
    fn new_read_only(buf: &'a [u8]) -> Self {
        Self::new_virtual(IoBufferBorrow::ReadOnly(buf))
    }

    fn new_writable(buf: &'a mut [u8]) -> Self {
        Self::new_virtual(IoBufferBorrow::Writable(buf))
    }

    fn new_virtual(borrow: IoBufferBorrow<'a>) -> Self {
        let virt_addr = borrow.as_ptr() as usize;
        let len = borrow.len();
        let mut page_frames = [EMPTY_PAGE_FRAME; IOBUFFER_INLINE_PAGE_CAPACITY];
        let (page_frames_len, frame_offset) =
            describe_virtual_buffer(virt_addr, len, &mut page_frames)
                .expect("IoBuffer<Described> could not describe virtual backing");

        Self {
            borrow: Some(borrow),
            virt_addr,
            byte_len: len,
            frame_offset,
            page_frames,
            page_frames_len,
            dma_segments: [EMPTY_DMA_SEGMENT; IOBUFFER_INLINE_SEGMENT_CAPACITY],
            dma_segments_len: 0,
            mapped_by: None,
            dma_drop: None,
        }
    }

    fn new_physical(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
    ) -> Result<Self, IoBufferError> {
        validate_physical_frames(frame_offset, byte_len, frames)?;

        let mut page_frames = [EMPTY_PAGE_FRAME; IOBUFFER_INLINE_PAGE_CAPACITY];
        page_frames[..frames.len()].copy_from_slice(frames);

        Ok(Self {
            borrow: None,
            virt_addr: 0,
            byte_len,
            frame_offset,
            page_frames,
            page_frames_len: frames.len(),
            dma_segments: [EMPTY_DMA_SEGMENT; IOBUFFER_INLINE_SEGMENT_CAPACITY],
            dma_segments_len: 0,
            mapped_by: None,
            dma_drop: None,
        })
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.borrow
            .as_ref()
            .expect("IoBuffer has no virtual backing")
            .as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.borrow
            .as_ref()
            .expect("IoBuffer has no virtual backing")
            .as_slice()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.borrow
            .as_mut()
            .expect("IoBuffer has no virtual backing")
            .as_mut_ptr()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.borrow
            .as_mut()
            .expect("IoBuffer has no virtual backing")
            .as_mut_slice()
    }

    pub fn page_frames(&self) -> &[IoBufferPageFrame] {
        &self.page_frames[..self.page_frames_len]
    }

    pub fn dma_segments(&self) -> &[IoBufferDmaSegment] {
        &self.dma_segments[..self.dma_segments_len]
    }

    pub fn replace_page_frames(
        &mut self,
        frames: &[IoBufferPageFrame],
    ) -> Result<(), IoBufferError> {
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
        let page_offset = self.virt_addr & (IOBUFFER_PAGE_SIZE - 1);
        self.virt_addr - page_offset
    }

    pub fn page_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn page_count(&self) -> usize {
        self.page_frames_len
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

    pub fn remove_virtual_backing_in_place(&mut self) {
        self.borrow = None;
        self.virt_addr = 0;
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

    pub fn page_offset(&self) -> usize {
        self.inner.page_offset()
    }

    pub fn page_count(&self) -> usize {
        self.inner.page_count()
    }

    pub fn frame_offset(&self) -> usize {
        self.inner.page_offset()
    }

    pub fn frame_count(&self) -> usize {
        self.inner.page_count()
    }

    pub fn page_frames(&self) -> &[IoBufferPageFrame] {
        self.inner.page_frames()
    }

    pub fn physical_frames(&self) -> &[IoBufferPageFrame] {
        self.inner.page_frames()
    }

    pub fn dma_segments(&self) -> &[IoBufferDmaSegment] {
        self.inner.dma_segments()
    }
}

impl<'a, State: VirtualBackedIoBufferState, Direction: IoBufferDirection>
    IoBuffer<'a, State, Direction>
{
    pub fn virtual_address(&self) -> usize {
        self.inner.virt_addr
    }

    pub fn page_base_address(&self) -> usize {
        self.inner.page_base_address()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl<'a, Source: MappableIoBufferState, Direction: IoBufferDirection>
    IoBuffer<'a, DmaMapped<Source>, Direction>
{
    pub fn mapped_by(&self) -> Option<&Arc<DeviceObject>> {
        self.inner.mapped_by.as_ref()
    }
}

impl<'a, State: VirtualBackedIoBufferState, Direction: WritableIoBufferDirection>
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

impl<'a, Direction: IoBufferDirection> IoBuffer<'a, PhysFramed, Direction> {
    pub fn new(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
    ) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferInner::new_physical(
            frame_offset,
            byte_len,
            frames,
        )?))
    }
}

impl<'a, Direction: IoBufferDirection> IoBuffer<'a, Described, Direction> {
    pub fn into_phys_framed(self) -> IoBuffer<'a, PhysFramed, Direction> {
        let mut inner = self.into_inner();
        inner.remove_virtual_backing_in_place();
        IoBuffer::<'a, PhysFramed, Direction>::from_inner(inner)
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
    /// and return an `IoBuffer<DmaMapped<S>, D>`.
    ///
    /// On error the original buffer is returned so the caller can recover it.
    pub fn apply_dma_mapping(
        self,
        segments: &[IoBufferDmaSegment],
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<IoBuffer<'a, DmaMapped<S>, D>, (Self, IoBufferError)> {
        let mut inner = self.into_inner();
        if let Err(e) = inner.replace_dma_segments(segments) {
            return Err((IoBuffer::<'a, S, D>::from_inner(inner), e));
        }
        inner.set_dma_drop(mapped_by, unmap, cookie);
        Ok(IoBuffer::<'a, DmaMapped<S>, D>::from_inner(inner))
    }
}

impl<'a, S: MappableIoBufferState, D: IoBufferDirection> IoBuffer<'a, DmaMapped<S>, D> {
    /// Consume this `DmaMapped` buffer, invoke the stored unmap callback,
    /// clear all DMA segments, and return a buffer with its original source
    /// state.
    pub fn remove_dma_mapping(self) -> IoBuffer<'a, S, D> {
        let mut inner = self.into_inner();
        if let Some(ctx) = inner.dma_drop.take() {
            (ctx.unmap)(&ctx.mapped_by, ctx.cookie);
        }
        inner.mapped_by = None;
        inner.dma_segments.fill(EMPTY_DMA_SEGMENT);
        inner.dma_segments_len = 0;
        IoBuffer::<'a, S, D>::from_inner(inner)
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
            .field("has_virtual_backing", &self.inner.borrow.is_some())
            .field("frame_offset", &self.inner.frame_offset)
            .field("page_frames_len", &self.inner.page_frames_len)
            .field("dma_segments_len", &self.inner.dma_segments_len)
            .field("mapped", &self.inner.mapped_by.is_some())
            .finish()
    }
}
