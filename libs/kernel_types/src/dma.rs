use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr;
use kernel_macros::RequestPayload;

use crate::arch::{PagingPlatform, PhysAddr, Platform, VirtAddr};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceMmuPlatformDeviceIdentity {
    pub firmware_node: u64,
    pub iommu_id_base: u32,
    pub iommu_id_count: u32,
    pub flags: u32,
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

pub const IOBUFFER_INLINE_PAGE_CAPACITY: usize = 8;
pub const IOBUFFER_INLINE_FRAME_CAPACITY: usize = IOBUFFER_INLINE_PAGE_CAPACITY;
pub const IOBUFFER_INLINE_EXTENT_CAPACITY: usize = 8;
pub const IOBUFFER_INLINE_SEGMENT_CAPACITY: usize = 32;

/// Region described from one or more virtual borrows.
///
/// A `Described` buffer has virtual backing for each logical extent and
/// physical frame backing for the whole logical byte stream.
pub enum Described {}

/// Region described directly from physical frames.
///
/// A `PhysFramed` buffer has physical frame backing, but no required virtual
/// backing. This can represent regions that are not mapped in this address
/// space.
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
impl sealed::IoBufferState for PhysFramed {}
impl<S: sealed::IoBufferState> sealed::IoBufferState for DmaMapped<S> {}

pub trait MappableIoBufferState: IoBufferState + sealed::MappableState {}
impl<T: IoBufferState + sealed::MappableState> MappableIoBufferState for T {}

pub trait VirtualBackedIoBufferState: IoBufferState + sealed::VirtualBackedState {}
impl<T: IoBufferState + sealed::VirtualBackedState> VirtualBackedIoBufferState for T {}

impl sealed::MappableState for Described {}
impl sealed::MappableState for PhysFramed {}

impl sealed::VirtualBackedState for Described {}
impl<S: sealed::VirtualBackedState> sealed::VirtualBackedState for DmaMapped<S> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaMappingStrategy {
    /// Entire logical buffer mapped as a single contiguous IOVA region -> 1 segment.
    SingleContiguous,
    /// Buffer divided into N equal contiguous IOVA chunks. Requires
    /// `buffer.len() % chunk_size == 0` and alignment to the device translation granularity.
    ContiguousChunks { chunk_size: usize },
    /// Every page's IOVA == its physical address. Adjacent physical pages are
    /// merged into a single segment.
    FullIdentity,
    /// One IOVA segment per backing frame, without merging adjacent frames.
    ScatterGather,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaMapError {
    NoIommu,
    RemappingUnavailable,
    UnalignedChunkSize {
        buffer_len: usize,
        chunk_size: usize,
    },
    ChunkSizeNotPageAligned {
        chunk_size: usize,
    },
    PageCapacityExceeded {
        required: usize,
    },
    SegmentCapacityExceeded {
        required: usize,
    },
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
    /// Cached CPU virtual address for this physical frame.
    pub cpu_addr: crate::arch::VirtAddr,
}

impl IoBufferPageFrame {
    pub const fn new(phys_addr: u64, byte_len: u64, cpu_addr: crate::arch::VirtAddr) -> Self {
        Self {
            phys_addr,
            byte_len,
            cpu_addr,
        }
    }

    pub fn cpu_address(&self) -> crate::arch::VirtAddr {
        self.cpu_addr
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoBufferDmaSegment {
    pub dma_addr: u64,
    pub byte_len: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoBufferExtent {
    pub virtual_addr: Option<usize>,
    pub frame_offset: usize,
    pub byte_len: usize,
    pub first_frame: usize,
    pub frame_count: usize,
}

impl IoBufferExtent {
    pub const fn new(
        virtual_addr: Option<usize>,
        frame_offset: usize,
        byte_len: usize,
        first_frame: usize,
        frame_count: usize,
    ) -> Self {
        Self {
            virtual_addr,
            frame_offset,
            byte_len,
            first_frame,
            frame_count,
        }
    }

    pub fn virtual_address(&self) -> Option<usize> {
        self.virtual_addr
    }

    pub fn frame_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn page_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn frame_range(&self) -> core::ops::Range<usize> {
        self.first_frame..self.first_frame + self.frame_count
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoBufferError {
    PageCapacityExceeded {
        required: usize,
        capacity: usize,
    },
    ExtentCapacityExceeded {
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
    InvalidExtentLayout {
        extent_index: usize,
    },
    OverlappingMutableExtents {
        first: usize,
        second: usize,
    },
    LengthOverflow,
    TranslationFailed {
        virt_addr: usize,
    },
}

const EMPTY_PAGE_FRAME: IoBufferPageFrame =
    IoBufferPageFrame::new(0, 0, crate::arch::VirtAddr::new(0));
const EMPTY_DMA_SEGMENT: IoBufferDmaSegment = IoBufferDmaSegment {
    dma_addr: 0,
    byte_len: 0,
    reserved: 0,
};
const EMPTY_EXTENT: IoBufferExtent = IoBufferExtent::new(None, 0, 0, 0, 0);

#[derive(Clone, Debug)]
enum StoredDmaSegments {
    Inline {
        segments: [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
        len: usize,
    },
    Heap(Box<[IoBufferDmaSegment]>),
}

impl StoredDmaSegments {
    fn from_slice(items: &[IoBufferDmaSegment]) -> Self {
        if items.len() <= IOBUFFER_INLINE_SEGMENT_CAPACITY {
            let mut segments = [EMPTY_DMA_SEGMENT; IOBUFFER_INLINE_SEGMENT_CAPACITY];
            segments[..items.len()].copy_from_slice(items);
            Self::Inline {
                segments,
                len: items.len(),
            }
        } else {
            let mut heap = Vec::with_capacity(items.len());
            heap.extend_from_slice(items);
            Self::Heap(heap.into_boxed_slice())
        }
    }

    fn from_box(items: Box<[IoBufferDmaSegment]>) -> Self {
        if items.len() <= IOBUFFER_INLINE_SEGMENT_CAPACITY {
            let mut segments = [EMPTY_DMA_SEGMENT; IOBUFFER_INLINE_SEGMENT_CAPACITY];
            segments[..items.len()].copy_from_slice(items.as_ref());
            Self::Inline {
                segments,
                len: items.len(),
            }
        } else {
            Self::Heap(items)
        }
    }

    fn as_slice(&self) -> &[IoBufferDmaSegment] {
        match self {
            Self::Inline { segments, len } => &segments[..*len],
            Self::Heap(segments) => segments.as_ref(),
        }
    }

    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Debug)]
enum DmaSegmentLayout {
    None,
    Stored(StoredDmaSegments),
    Contiguous {
        segment: IoBufferDmaSegment,
    },
    PageChunks {
        iova_base: u64,
        page_offset: usize,
        byte_len: usize,
        page_size: usize,
    },
    ScatterGather {
        iova_base: u64,
        page_size: usize,
    },
    FixedChunks {
        dma_addr: u64,
        chunk_len: u32,
        count: usize,
    },
    Identity {
        frame_offset: usize,
        byte_len: usize,
    },
    IdentityExtents,
}

impl DmaSegmentLayout {
    const fn empty() -> Self {
        Self::None
    }
}

pub type DmaUnmapFn = extern "C" fn(&Arc<DeviceObject>, usize);

#[repr(C)]
struct DmaDropContext {
    mapped_by: Arc<DeviceObject>,
    unmap: DmaUnmapFn,
    cookie: usize,
}

#[repr(C)]
pub struct BorrowedDmaMapping<'a> {
    layout: DmaSegmentLayout,
    extents: &'a [IoBufferExtent],
    page_frames: &'a [IoBufferPageFrame],
    dma_drop: Option<DmaDropContext>,
    _borrow: PhantomData<&'a ()>,
}

impl<'a> BorrowedDmaMapping<'a> {
    pub fn new(
        segments: &[IoBufferDmaSegment],
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<Self, IoBufferError> {
        Ok(Self {
            layout: DmaSegmentLayout::Stored(StoredDmaSegments::from_slice(segments)),
            extents: &[],
            page_frames: &[],
            dma_drop: Some(DmaDropContext {
                mapped_by,
                unmap,
                cookie,
            }),
            _borrow: PhantomData,
        })
    }

    pub fn new_layout(
        layout: IoBufferDmaMappingLayout,
        extents: &'a [IoBufferExtent],
        page_frames: &'a [IoBufferPageFrame],
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<Self, IoBufferError> {
        validate_dma_mapping_layout(&layout)?;

        Ok(Self {
            layout: DmaSegmentLayout::from(layout),
            extents,
            page_frames,
            dma_drop: Some(DmaDropContext {
                mapped_by,
                unmap,
                cookie,
            }),
            _borrow: PhantomData,
        })
    }

    pub fn stored_segments(&self) -> Option<&[IoBufferDmaSegment]> {
        match &self.layout {
            DmaSegmentLayout::Stored(segments) => Some(segments.as_slice()),
            _ => None,
        }
    }

    pub fn dma_segments(&self) -> IoBufferDmaSegments<'_> {
        IoBufferDmaSegments::new(&self.layout, self.extents, self.page_frames)
    }

    pub fn segment_count(&self) -> usize {
        self.dma_segments().len()
    }
}

impl Drop for BorrowedDmaMapping<'_> {
    fn drop(&mut self) {
        if let Some(drop_ctx) = self.dma_drop.take() {
            (drop_ctx.unmap)(&drop_ctx.mapped_by, drop_ctx.cookie);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtToPhysResult {
    pub found: u8,
    pub reserved: [u8; 7],
    pub phys_addr: PhysAddr,
    pub frame_size: u64,
}

impl VirtToPhysResult {
    pub fn none() -> Self {
        Self {
            found: 0,
            reserved: [0; 7],
            phys_addr: PhysAddr::new(0),
            frame_size: 0,
        }
    }

    pub fn some(phys_addr: PhysAddr, frame_size: u64) -> Self {
        Self {
            found: 1,
            reserved: [0; 7],
            phys_addr,
            frame_size,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedVirtualAddress {
    phys_addr: PhysAddr,
    frame_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VirtualFrameTranslation {
    phys_addr: u64,
    byte_len: u64,
    offset: u64,
}

#[inline]
fn is_valid_frame_size(byte_len: u64) -> bool {
    byte_len != 0 && byte_len.is_power_of_two()
}

fn translate_virtual_frame(virt_addr: usize) -> Option<VirtualFrameTranslation> {
    let (frame_size, phys_addr) = resolve_virtual_range_frame(VirtAddr::new(virt_addr as u64))?;

    if !is_valid_frame_size(frame_size) {
        return None;
    }

    let offset = virt_addr as u64 & (frame_size - 1);
    let phys_addr = phys_addr.as_u64();
    let phys_base = phys_addr.checked_sub(offset)?;

    if phys_base & (frame_size - 1) != 0 {
        return None;
    }

    Some(VirtualFrameTranslation {
        phys_addr: phys_base,
        byte_len: frame_size,
        offset,
    })
}

#[cfg(any(test, feature = "hosted-tests"))]
fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    Some((hosted_test_frame_size(), PhysAddr::new(addr.as_u64())))
}

#[cfg(any(test, feature = "hosted-tests"))]
fn hosted_test_frame_size() -> u64 {
    4096
}

#[cfg(not(any(test, feature = "hosted-tests")))]
fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    let block = <Platform as PagingPlatform>::translate_addr(addr)?;
    Some((block.block_size, block.phys_addr))
}
fn describe_virtual_buffer_to_frames(
    virt_addr: usize,
    byte_len: usize,
    frames: &mut Vec<IoBufferPageFrame>,
) -> Result<(usize, usize), IoBufferError> {
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

        if frame_count == 0 {
            first_frame_offset = translated.offset as usize;
        }

        let current_base_va = current - translated.offset as usize;

        frames.push(IoBufferPageFrame::new(
            translated.phys_addr,
            translated.byte_len,
            crate::arch::VirtAddr::new(current_base_va as u64),
        ));

        frame_count += 1;

        let bytes_in_frame = (translated.byte_len - translated.offset) as usize;
        let bytes = (byte_len - consumed).min(bytes_in_frame);

        consumed = consumed
            .checked_add(bytes)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok((frame_count, first_frame_offset))
}
fn describe_virtual_extents(
    regions: &[(usize, usize)],
) -> Result<(PageFrameStorage, usize, ExtentStorage, usize, usize), IoBufferError> {
    let mut frames = Vec::new();
    let mut extents = Vec::with_capacity(regions.len());
    let mut total_len = 0usize;

    for &(virt_addr, byte_len) in regions {
        let first_frame = frames.len();
        let (frame_count, frame_offset) =
            describe_virtual_buffer_to_frames(virt_addr, byte_len, &mut frames)?;

        total_len = total_len
            .checked_add(byte_len)
            .ok_or(IoBufferError::LengthOverflow)?;

        extents.push(IoBufferExtent::new(
            Some(virt_addr),
            frame_offset,
            byte_len,
            first_frame,
            frame_count,
        ));
    }

    let page_frames_len = frames.len();
    let extents_len = extents.len();

    let page_frames = page_frame_storage_from_slice(&frames)?;
    let extents = extent_storage_from_slice(&extents)?;

    Ok((
        page_frames,
        page_frames_len,
        extents,
        extents_len,
        total_len,
    ))
}
fn validate_virtual_ranges_disjoint(regions: &[(usize, usize)]) -> Result<(), IoBufferError> {
    for first in 0..regions.len() {
        let (first_addr, first_len) = regions[first];
        if first_len == 0 {
            continue;
        }
        let first_end =
            first_addr
                .checked_add(first_len)
                .ok_or(IoBufferError::TranslationFailed {
                    virt_addr: first_addr,
                })?;

        for second in first + 1..regions.len() {
            let (second_addr, second_len) = regions[second];
            if second_len == 0 {
                continue;
            }
            let second_end =
                second_addr
                    .checked_add(second_len)
                    .ok_or(IoBufferError::TranslationFailed {
                        virt_addr: second_addr,
                    })?;

            if first_addr < second_end && second_addr < first_end {
                return Err(IoBufferError::OverlappingMutableExtents { first, second });
            }
        }
    }

    Ok(())
}

fn validate_physical_frames(
    frame_offset: usize,
    byte_len: usize,
    frames: &[IoBufferPageFrame],
) -> Result<(), IoBufferError> {
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
    None,
    Source(&'a [u8]),
    SourceSegments(Box<[&'a [u8]]>),
    Destination(&'a mut [u8]),
    DestinationSegments(Box<[&'a mut [u8]]>),
}

impl<'a> IoBufferBorrow<'a> {
    fn is_virtual_backed(&self) -> bool {
        !matches!(self, Self::None)
    }

    fn single_slice(&self) -> Option<&[u8]> {
        match self {
            Self::Source(src) => Some(*src),
            Self::SourceSegments(segments) if segments.len() == 1 => Some(segments[0]),
            Self::Destination(dst) => Some(&**dst),
            Self::DestinationSegments(segments) if segments.len() == 1 => Some(&*segments[0]),
            _ => None,
        }
    }

    fn single_mut_slice(&mut self) -> Option<&mut [u8]> {
        match self {
            Self::Destination(dst) => Some(&mut **dst),
            Self::DestinationSegments(segments) if segments.len() == 1 => {
                segments.get_mut(0).map(|segment| &mut **segment)
            }
            _ => None,
        }
    }
}

/// A logical extent of an `IoBuffer`.
///
/// All `IoBuffer`s are extent-based. The old contiguous case is represented as
/// one extent; caller-provided scatter-gather buffers have multiple extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoBufferRegion<'a> {
    virtual_addr: Option<usize>,
    frame_offset: usize,
    byte_len: usize,
    page_frames: &'a [IoBufferPageFrame],
}

impl<'a> IoBufferRegion<'a> {
    pub fn virtual_address(&self) -> Option<usize> {
        self.virtual_addr
    }

    pub fn has_virtual_backing(&self) -> bool {
        self.virtual_addr.is_some()
    }

    pub fn frame_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn page_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn page_frames(&self) -> &'a [IoBufferPageFrame] {
        self.page_frames
    }

    pub fn physical_frames(&self) -> &'a [IoBufferPageFrame] {
        self.page_frames
    }
}

pub struct IoBufferRegionIter<'a> {
    extents: &'a [IoBufferExtent],
    page_frames: &'a [IoBufferPageFrame],
    next_extent: usize,
}

impl<'a> IoBufferRegionIter<'a> {
    fn new(extents: &'a [IoBufferExtent], page_frames: &'a [IoBufferPageFrame]) -> Self {
        Self {
            extents,
            page_frames,
            next_extent: 0,
        }
    }
}

impl<'a> Iterator for IoBufferRegionIter<'a> {
    type Item = IoBufferRegion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_extent < self.extents.len() {
            let extent = self.extents[self.next_extent];
            self.next_extent += 1;

            if extent.byte_len == 0 {
                continue;
            }

            let end_frame = extent.first_frame.checked_add(extent.frame_count)?;
            let page_frames = self.page_frames.get(extent.first_frame..end_frame)?;

            return Some(IoBufferRegion {
                virtual_addr: extent.virtual_addr,
                frame_offset: extent.frame_offset,
                byte_len: extent.byte_len,
                page_frames,
            });
        }

        None
    }
}

pub struct IoBufferDmaSegments<'a> {
    layout: &'a DmaSegmentLayout,
    extents: &'a [IoBufferExtent],
    page_frames: &'a [IoBufferPageFrame],
}

impl<'a> IoBufferDmaSegments<'a> {
    fn new(
        layout: &'a DmaSegmentLayout,
        extents: &'a [IoBufferExtent],
        page_frames: &'a [IoBufferPageFrame],
    ) -> Self {
        Self {
            layout,
            extents,
            page_frames,
        }
    }

    pub fn len(&self) -> usize {
        match self.layout {
            DmaSegmentLayout::None => 0,
            DmaSegmentLayout::Stored(segments) => segments.len(),
            DmaSegmentLayout::Contiguous { .. } => 1,
            DmaSegmentLayout::PageChunks {
                page_offset,
                byte_len,
                page_size,
                ..
            } => page_chunk_segment_count(*page_offset, *byte_len, *page_size),
            DmaSegmentLayout::ScatterGather { page_size, .. } => {
                scatter_gather_segment_count(self.extents, *page_size)
            }
            DmaSegmentLayout::FixedChunks { count, .. } => *count,
            DmaSegmentLayout::Identity {
                frame_offset,
                byte_len,
            } => identity_segment_count(self.page_frames, *frame_offset, *byte_len),
            DmaSegmentLayout::IdentityExtents => {
                identity_extents_segment_count(self.extents, self.page_frames)
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn first(&self) -> Option<IoBufferDmaSegment> {
        self.iter().next()
    }

    pub fn iter(&self) -> IoBufferDmaSegmentIter<'a> {
        IoBufferDmaSegmentIter {
            layout: self.layout,
            extents: self.extents,
            page_frames: self.page_frames,
            index: 0,
            extent_index: 0,
            frame_index: 0,
            frame_end: 0,
            frame_offset: 0,
            remaining: 0,
            iova_cursor: 0,
            page_index: 0,
            page_count: 0,
            page_offset: 0,
            page_size: 0,
            initialized: false,
        }
    }
}

impl<'a> IntoIterator for IoBufferDmaSegments<'a> {
    type Item = IoBufferDmaSegment;
    type IntoIter = IoBufferDmaSegmentIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'segments, 'a> IntoIterator for &'segments IoBufferDmaSegments<'a> {
    type Item = IoBufferDmaSegment;
    type IntoIter = IoBufferDmaSegmentIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct IoBufferDmaSegmentIter<'a> {
    layout: &'a DmaSegmentLayout,
    extents: &'a [IoBufferExtent],
    page_frames: &'a [IoBufferPageFrame],
    index: usize,
    extent_index: usize,
    frame_index: usize,
    frame_end: usize,
    frame_offset: usize,
    remaining: usize,
    iova_cursor: u64,
    page_index: usize,
    page_count: usize,
    page_offset: usize,
    page_size: usize,
    initialized: bool,
}

impl<'a> Iterator for IoBufferDmaSegmentIter<'a> {
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        match self.layout {
            DmaSegmentLayout::None => None,
            DmaSegmentLayout::Stored(segments) => {
                let segments = segments.as_slice();
                if self.index >= segments.len() {
                    return None;
                }

                let segment = segments[self.index];
                self.index += 1;
                Some(segment)
            }
            DmaSegmentLayout::Contiguous { segment } => {
                if self.index != 0 {
                    return None;
                }

                self.index = 1;
                Some(*segment)
            }
            DmaSegmentLayout::PageChunks {
                iova_base,
                page_offset,
                byte_len,
                page_size,
            } => {
                if !self.initialized {
                    self.remaining = *byte_len;
                    self.page_offset = *page_offset;
                    self.page_size = *page_size;
                    self.iova_cursor = *iova_base;
                    self.initialized = true;
                }

                next_page_chunk_segment(
                    self.iova_cursor,
                    self.page_offset,
                    self.page_size,
                    &mut self.index,
                    &mut self.remaining,
                )
            }
            DmaSegmentLayout::ScatterGather {
                iova_base,
                page_size,
            } => {
                if !self.initialized {
                    self.iova_cursor = *iova_base;
                    self.page_size = *page_size;
                    self.initialized = true;
                }

                next_scatter_gather_segment(
                    self.extents,
                    self.page_size,
                    &mut self.extent_index,
                    &mut self.iova_cursor,
                    &mut self.page_index,
                    &mut self.page_count,
                    &mut self.page_offset,
                    &mut self.remaining,
                )
            }
            DmaSegmentLayout::FixedChunks {
                dma_addr,
                chunk_len,
                count,
            } => {
                if self.index >= *count {
                    return None;
                }

                let segment = IoBufferDmaSegment {
                    dma_addr: *dma_addr + self.index as u64 * *chunk_len as u64,
                    byte_len: *chunk_len,
                    reserved: 0,
                };

                self.index += 1;
                Some(segment)
            }
            DmaSegmentLayout::Identity {
                frame_offset,
                byte_len,
            } => {
                if !self.initialized {
                    self.frame_offset = *frame_offset;
                    self.remaining = *byte_len;
                    self.frame_end = self.page_frames.len();
                    self.initialized = true;
                }

                next_identity_segment_limited(
                    self.page_frames,
                    self.frame_end,
                    &mut self.frame_index,
                    &mut self.frame_offset,
                    &mut self.remaining,
                )
            }
            DmaSegmentLayout::IdentityExtents => next_identity_extent_segment(
                self.extents,
                self.page_frames,
                &mut self.extent_index,
                &mut self.frame_index,
                &mut self.frame_end,
                &mut self.frame_offset,
                &mut self.remaining,
            ),
        }
    }
}

fn page_chunk_segment_count(page_offset: usize, byte_len: usize, page_size: usize) -> usize {
    if byte_len == 0 || page_size == 0 {
        0
    } else {
        page_offset.saturating_add(byte_len).div_ceil(page_size)
    }
}

fn scatter_gather_segment_count(extents: &[IoBufferExtent], page_size: usize) -> usize {
    if page_size == 0 {
        return 0;
    }

    let mut count = 0usize;
    for extent in extents {
        if extent.byte_len == 0 {
            continue;
        }

        let page_offset = extent.frame_offset % page_size;
        count = count.saturating_add(page_chunk_segment_count(
            page_offset,
            extent.byte_len,
            page_size,
        ));
    }

    count
}

fn identity_extents_segment_count(
    extents: &[IoBufferExtent],
    page_frames: &[IoBufferPageFrame],
) -> usize {
    let mut count = 0usize;

    for extent in extents {
        if extent.byte_len == 0 {
            continue;
        }

        let Some(end_frame) = extent.first_frame.checked_add(extent.frame_count) else {
            break;
        };

        if end_frame > page_frames.len() {
            break;
        }

        count = count.saturating_add(identity_segment_count_in_range(
            page_frames,
            extent.first_frame,
            end_frame,
            extent.frame_offset,
            extent.byte_len,
        ));
    }

    count
}

fn identity_segment_count(
    page_frames: &[IoBufferPageFrame],
    frame_offset: usize,
    byte_len: usize,
) -> usize {
    identity_segment_count_in_range(page_frames, 0, page_frames.len(), frame_offset, byte_len)
}

fn identity_segment_count_in_range(
    page_frames: &[IoBufferPageFrame],
    frame_index: usize,
    frame_end: usize,
    frame_offset: usize,
    byte_len: usize,
) -> usize {
    let mut frame_index = frame_index;
    let mut current_offset = frame_offset;
    let mut remaining = byte_len;
    let mut count = 0;

    while next_identity_segment_limited(
        page_frames,
        frame_end,
        &mut frame_index,
        &mut current_offset,
        &mut remaining,
    )
    .is_some()
    {
        count += 1;
    }

    count
}

fn next_page_chunk_segment(
    iova_base: u64,
    page_offset: usize,
    page_size: usize,
    index: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if *remaining == 0 || page_size == 0 {
        return None;
    }

    let start_in_page = if *index == 0 { page_offset } else { 0 };
    if start_in_page >= page_size {
        return None;
    }

    let bytes = (*remaining).min(page_size - start_in_page);
    let dma_addr = iova_base + (*index * page_size + start_in_page) as u64;

    *remaining -= bytes;
    *index += 1;

    Some(IoBufferDmaSegment {
        dma_addr,
        byte_len: bytes as u32,
        reserved: 0,
    })
}

fn next_scatter_gather_segment(
    extents: &[IoBufferExtent],
    page_size: usize,
    extent_index: &mut usize,
    iova_cursor: &mut u64,
    page_index: &mut usize,
    page_count: &mut usize,
    page_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if page_size == 0 {
        return None;
    }

    loop {
        if *remaining != 0 {
            let segment = next_page_chunk_segment(
                *iova_cursor,
                *page_offset,
                page_size,
                page_index,
                remaining,
            );

            if *remaining == 0 {
                let advance = (*page_count).checked_mul(page_size)? as u64;
                *iova_cursor = iova_cursor.checked_add(advance)?;
                *page_index = 0;
                *page_count = 0;
                *page_offset = 0;
            }

            return segment;
        }

        while *extent_index < extents.len() && extents[*extent_index].byte_len == 0 {
            *extent_index += 1;
        }

        if *extent_index >= extents.len() {
            return None;
        }

        let extent = extents[*extent_index];
        *extent_index += 1;

        *page_offset = extent.frame_offset % page_size;
        *remaining = extent.byte_len;
        *page_count = page_chunk_segment_count(*page_offset, extent.byte_len, page_size);
        *page_index = 0;
    }
}

fn next_identity_extent_segment(
    extents: &[IoBufferExtent],
    page_frames: &[IoBufferPageFrame],
    extent_index: &mut usize,
    frame_index: &mut usize,
    frame_end: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    loop {
        if *remaining != 0 {
            return next_identity_segment_limited(
                page_frames,
                *frame_end,
                frame_index,
                frame_offset,
                remaining,
            );
        }

        while *extent_index < extents.len() && extents[*extent_index].byte_len == 0 {
            *extent_index += 1;
        }

        if *extent_index >= extents.len() {
            return None;
        }

        let extent = extents[*extent_index];
        *extent_index += 1;

        let end_frame = extent.first_frame.checked_add(extent.frame_count)?;
        if end_frame > page_frames.len() {
            return None;
        }

        *frame_index = extent.first_frame;
        *frame_end = end_frame;
        *frame_offset = extent.frame_offset;
        *remaining = extent.byte_len;
    }
}

fn next_identity_segment_limited(
    page_frames: &[IoBufferPageFrame],
    frame_end: usize,
    frame_index: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if *remaining == 0 {
        return None;
    }

    while *frame_index < frame_end && *frame_offset >= page_frames[*frame_index].byte_len as usize {
        *frame_offset -= page_frames[*frame_index].byte_len as usize;
        *frame_index += 1;
    }

    if *frame_index >= frame_end {
        return None;
    }

    let first = page_frames[*frame_index];
    let start_offset = *frame_offset;
    let dma_addr = first.phys_addr + start_offset as u64;
    let first_available = first.byte_len as usize - start_offset;
    let mut byte_len = (*remaining).min(first_available).min(u32::MAX as usize);

    *remaining -= byte_len;

    if byte_len == first_available {
        *frame_index += 1;
        *frame_offset = 0;
    } else {
        *frame_offset += byte_len;
    }

    while *remaining > 0 && *frame_index < frame_end {
        let next = page_frames[*frame_index];
        let expected = dma_addr + byte_len as u64;
        if next.phys_addr != expected {
            break;
        }

        let add_len = (*remaining).min(next.byte_len as usize);
        let Some(merged_len) = byte_len.checked_add(add_len) else {
            break;
        };

        if merged_len > u32::MAX as usize {
            break;
        }

        byte_len = merged_len;
        *remaining -= add_len;
        *frame_index += 1;
    }

    Some(IoBufferDmaSegment {
        dma_addr,
        byte_len: byte_len as u32,
        reserved: 0,
    })
}

struct InlineStorage<T: Copy, const INLINE_CAPACITY: usize> {
    inline: [T; INLINE_CAPACITY],
    heap: Option<Box<[T]>>,
}

impl<T: Copy, const INLINE_CAPACITY: usize> InlineStorage<T, INLINE_CAPACITY> {
    fn empty(empty: T) -> Self {
        Self {
            inline: [empty; INLINE_CAPACITY],
            heap: None,
        }
    }

    fn from_slice(items: &[T], empty: T) -> Self {
        let mut storage = Self::empty(empty);
        storage.replace(items, empty);
        storage
    }

    fn as_slice(&self, len: usize) -> &[T] {
        match self.heap.as_ref() {
            Some(items) => &items[..len],
            None => &self.inline[..len],
        }
    }

    fn replace(&mut self, items: &[T], empty: T) {
        self.inline.fill(empty);

        if items.len() <= INLINE_CAPACITY {
            self.heap = None;
            self.inline[..items.len()].copy_from_slice(items);
        } else {
            let mut heap = Self::boxed_empty(items.len(), empty);
            heap.copy_from_slice(items);
            self.heap = Some(heap);
        }
    }

    fn boxed_empty(capacity: usize, empty: T) -> Box<[T]> {
        let mut items = Vec::with_capacity(capacity);
        items.resize(capacity, empty);
        items.into_boxed_slice()
    }
}

type PageFrameStorage = InlineStorage<IoBufferPageFrame, IOBUFFER_INLINE_PAGE_CAPACITY>;

type ExtentStorage = InlineStorage<IoBufferExtent, IOBUFFER_INLINE_EXTENT_CAPACITY>;

fn page_frame_storage_from_slice(
    frames: &[IoBufferPageFrame],
) -> Result<PageFrameStorage, IoBufferError> {
    Ok(PageFrameStorage::from_slice(frames, EMPTY_PAGE_FRAME))
}

fn extent_storage_from_slice(extents: &[IoBufferExtent]) -> Result<ExtentStorage, IoBufferError> {
    Ok(ExtentStorage::from_slice(extents, EMPTY_EXTENT))
}
fn validate_physical_extents(
    frames: &[IoBufferPageFrame],
    extents: &[IoBufferExtent],
) -> Result<usize, IoBufferError> {
    let mut total_len = 0usize;

    for (idx, extent) in extents.iter().copied().enumerate() {
        let Some(end_frame) = extent.first_frame.checked_add(extent.frame_count) else {
            return Err(IoBufferError::InvalidExtentLayout { extent_index: idx });
        };

        if end_frame > frames.len() {
            return Err(IoBufferError::InvalidExtentLayout { extent_index: idx });
        }

        validate_physical_frames(
            extent.frame_offset,
            extent.byte_len,
            &frames[extent.first_frame..end_frame],
        )?;

        total_len = total_len
            .checked_add(extent.byte_len)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok(total_len)
}
#[repr(C)]
pub struct IoBufferRepr<'a> {
    borrow: IoBufferBorrow<'a>,
    byte_len: usize,
    extents: ExtentStorage,
    extents_len: usize,
    page_frames: PageFrameStorage,
    page_frames_len: usize,
    dma_segments: DmaSegmentLayout,
    mapped_by: Option<Arc<DeviceObject>>,
    dma_drop: Option<DmaDropContext>,
}

impl<'a> IoBufferRepr<'a> {
    fn new_source(src: &'a [u8]) -> Self {
        Self::try_new_source(src).expect("IoBuffer<Described> could not describe virtual backing")
    }

    fn try_new_source(src: &'a [u8]) -> Result<Self, IoBufferError> {
        Self::new_source_segments(&[src])
    }

    fn new_source_segments(segments: &[&'a [u8]]) -> Result<Self, IoBufferError> {
        let mut regions = Vec::with_capacity(segments.len());
        let mut owned = Vec::with_capacity(segments.len());

        for &segment in segments {
            regions.push((segment.as_ptr() as usize, segment.len()));
            owned.push(segment);
        }

        let (page_frames, page_frames_len, extents, extents_len, byte_len) =
            describe_virtual_extents(&regions)?;

        let borrow = if owned.len() == 1 {
            IoBufferBorrow::Source(owned[0])
        } else {
            IoBufferBorrow::SourceSegments(owned.into_boxed_slice())
        };

        Ok(Self {
            borrow,
            byte_len,
            extents,
            extents_len,
            page_frames,
            page_frames_len,
            dma_segments: DmaSegmentLayout::empty(),
            mapped_by: None,
            dma_drop: None,
        })
    }

    fn new_destination(dst: &'a mut [u8]) -> Self {
        Self::try_new_destination(dst)
            .expect("IoBuffer<Described> could not describe virtual backing")
    }

    fn try_new_destination(dst: &'a mut [u8]) -> Result<Self, IoBufferError> {
        let mut segments = Vec::with_capacity(1);
        segments.push(dst);
        Self::new_destination_segments(segments)
    }

    fn new_destination_segments(mut segments: Vec<&'a mut [u8]>) -> Result<Self, IoBufferError> {
        let mut regions = Vec::with_capacity(segments.len());

        for segment in &segments {
            regions.push((segment.as_ptr() as usize, segment.len()));
        }

        validate_virtual_ranges_disjoint(&regions)?;
        let (page_frames, page_frames_len, extents, extents_len, byte_len) =
            describe_virtual_extents(&regions)?;

        let borrow = if segments.len() == 1 {
            IoBufferBorrow::Destination(segments.remove(0))
        } else {
            IoBufferBorrow::DestinationSegments(segments.into_boxed_slice())
        };

        Ok(Self {
            borrow,
            byte_len,
            extents,
            extents_len,
            page_frames,
            page_frames_len,
            dma_segments: DmaSegmentLayout::empty(),
            mapped_by: None,
            dma_drop: None,
        })
    }

    fn new_physical(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
    ) -> Result<Self, IoBufferError> {
        validate_physical_frames(frame_offset, byte_len, frames)?;
        let virtual_addr = frames.first().and_then(|frame| {
            let va = frame.cpu_address().as_u64();
            if va == 0 {
                None
            } else {
                Some((va as usize).checked_add(frame_offset)?)
            }
        });
        let extent = IoBufferExtent::new(virtual_addr, frame_offset, byte_len, 0, frames.len());
        Self::new_physical_extents(frames, &[extent])
    }

    fn new_physical_extents(
        frames: &[IoBufferPageFrame],
        extents: &[IoBufferExtent],
    ) -> Result<Self, IoBufferError> {
        let byte_len = validate_physical_extents(frames, extents)?;
        let extents_len = extents.len();
        let page_frames = page_frame_storage_from_slice(frames)?;
        let extents = extent_storage_from_slice(extents)?;

        Ok(Self {
            borrow: IoBufferBorrow::None,
            byte_len,
            extents,
            extents_len,
            page_frames,
            page_frames_len: frames.len(),
            dma_segments: DmaSegmentLayout::empty(),
            mapped_by: None,
            dma_drop: None,
        })
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn extent_count(&self) -> usize {
        self.extents_len
    }

    pub fn is_single_extent(&self) -> bool {
        self.extents_len == 1
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.try_as_slice()
            .expect("IoBuffer is not backed by exactly one virtual extent")
    }

    pub fn try_as_slice(&self) -> Option<&[u8]> {
        self.borrow.single_slice()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_slice().as_mut_ptr()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.try_as_mut_slice()
            .expect("IoBuffer is not backed by exactly one writable virtual extent")
    }

    pub fn try_as_mut_slice(&mut self) -> Option<&mut [u8]> {
        self.borrow.single_mut_slice()
    }

    pub fn virtual_address(&self) -> Option<usize> {
        if self.extents_len != 1 {
            return None;
        }
        self.extents()
            .first()
            .and_then(|extent| extent.virtual_addr)
    }

    pub fn extents(&self) -> &[IoBufferExtent] {
        self.extents.as_slice(self.extents_len)
    }

    pub fn page_frames(&self) -> &[IoBufferPageFrame] {
        self.page_frames.as_slice(self.page_frames_len)
    }

    pub fn iter(&self) -> IoBufferRegionIter<'_> {
        IoBufferRegionIter::new(self.extents(), self.page_frames())
    }

    pub fn replace_dma_segments(
        &mut self,
        segments: &[IoBufferDmaSegment],
    ) -> Result<(), IoBufferError> {
        if segments.is_empty() {
            self.dma_segments = DmaSegmentLayout::empty();
        } else {
            self.dma_segments = DmaSegmentLayout::Stored(StoredDmaSegments::from_slice(segments));
        }

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
        let virt_addr = self
            .virtual_address()
            .expect("IoBuffer is not backed by exactly one virtual extent");
        let frame_offset = self
            .extents()
            .first()
            .map_or(0, |extent| extent.frame_offset);
        virt_addr
            .checked_sub(frame_offset)
            .expect("IoBuffer extent frame offset exceeds virtual address")
    }

    pub fn page_offset(&self) -> usize {
        self.extents()
            .first()
            .map_or(0, |extent| extent.frame_offset)
    }

    pub fn frame_offset(&self) -> usize {
        self.page_offset()
    }

    pub fn page_count(&self) -> usize {
        self.page_frames_len
    }

    pub fn frame_count(&self) -> usize {
        self.page_frames_len
    }

    pub fn dma_segments(&self) -> IoBufferDmaSegments<'_> {
        IoBufferDmaSegments::new(&self.dma_segments, self.extents(), self.page_frames())
    }
    pub fn segment_count(&self) -> usize {
        self.dma_segments().len()
    }
}

impl<'inner, 'a> IntoIterator for &'inner IoBufferRepr<'a> {
    type Item = IoBufferRegion<'inner>;
    type IntoIter = IoBufferRegionIter<'inner>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
#[derive(Clone, Debug)]
pub enum IoBufferDmaMappingLayout {
    None,
    Explicit(Box<[IoBufferDmaSegment]>),
    Contiguous {
        dma_addr: u64,
        byte_len: usize,
    },
    PageChunks {
        iova_base: u64,
        page_offset: usize,
        byte_len: usize,
        page_size: usize,
    },
    ScatterGather {
        iova_base: u64,
        page_size: usize,
    },
    FixedChunks {
        dma_addr: u64,
        chunk_len: u32,
        count: usize,
    },
    Identity {
        frame_offset: usize,
        byte_len: usize,
    },
    IdentityExtents,
}

impl From<IoBufferDmaMappingLayout> for DmaSegmentLayout {
    fn from(layout: IoBufferDmaMappingLayout) -> Self {
        match layout {
            IoBufferDmaMappingLayout::None => Self::None,
            IoBufferDmaMappingLayout::Explicit(segments) => {
                Self::Stored(StoredDmaSegments::from_box(segments))
            }
            IoBufferDmaMappingLayout::Contiguous { dma_addr, byte_len } => {
                if byte_len == 0 {
                    Self::None
                } else {
                    Self::Contiguous {
                        segment: IoBufferDmaSegment {
                            dma_addr,
                            byte_len: byte_len as u32,
                            reserved: 0,
                        },
                    }
                }
            }
            IoBufferDmaMappingLayout::PageChunks {
                iova_base,
                page_offset,
                byte_len,
                page_size,
            } => Self::PageChunks {
                iova_base,
                page_offset,
                byte_len,
                page_size,
            },
            IoBufferDmaMappingLayout::ScatterGather {
                iova_base,
                page_size,
            } => Self::ScatterGather {
                iova_base,
                page_size,
            },
            IoBufferDmaMappingLayout::FixedChunks {
                dma_addr,
                chunk_len,
                count,
            } => Self::FixedChunks {
                dma_addr,
                chunk_len,
                count,
            },
            IoBufferDmaMappingLayout::Identity {
                frame_offset,
                byte_len,
            } => Self::Identity {
                frame_offset,
                byte_len,
            },
            IoBufferDmaMappingLayout::IdentityExtents => Self::IdentityExtents,
        }
    }
}

fn validate_dma_mapping_layout(layout: &IoBufferDmaMappingLayout) -> Result<(), IoBufferError> {
    match layout {
        IoBufferDmaMappingLayout::None => Ok(()),
        IoBufferDmaMappingLayout::Explicit(_) => Ok(()),
        IoBufferDmaMappingLayout::Contiguous { byte_len, .. } => {
            if *byte_len > u32::MAX as usize {
                return Err(IoBufferError::SegmentCapacityExceeded {
                    required: *byte_len,
                    capacity: u32::MAX as usize,
                });
            }

            Ok(())
        }
        IoBufferDmaMappingLayout::PageChunks {
            page_offset,
            page_size,
            ..
        } => {
            if *page_size == 0 || *page_size > u32::MAX as usize || *page_offset >= *page_size {
                return Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: *page_offset,
                    byte_len: *page_size,
                });
            }

            Ok(())
        }
        IoBufferDmaMappingLayout::ScatterGather { page_size, .. } => {
            if *page_size == 0 || *page_size > u32::MAX as usize {
                return Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: 0,
                    byte_len: *page_size,
                });
            }

            Ok(())
        }
        IoBufferDmaMappingLayout::FixedChunks { chunk_len, .. } => {
            if *chunk_len == 0 {
                return Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: 0,
                    byte_len: 0,
                });
            }

            Ok(())
        }
        IoBufferDmaMappingLayout::Identity { .. } => Ok(()),
        IoBufferDmaMappingLayout::IdentityExtents => Ok(()),
    }
}

#[repr(C)]
#[derive(RequestPayload)]
#[request_view(
    IoBuffer<'a, Described, Direction> => IoBuffer<'a, PhysFramed, Direction>
    where Direction: IoBufferDirection
)]
#[request_view_mut(
    IoBuffer<'a, Described, Direction> => IoBuffer<'a, PhysFramed, Direction>
    where Direction: IoBufferDirection
)]
pub struct IoBuffer<'a, State: IoBufferState, Direction: IoBufferDirection> {
    inner: IoBufferRepr<'a>,
    _state: PhantomData<fn() -> State>,
    _direction: PhantomData<fn() -> Direction>,
}

impl<'a, State: IoBufferState, Direction: IoBufferDirection> IoBuffer<'a, State, Direction> {
    pub fn from_inner(inner: IoBufferRepr<'a>) -> Self {
        Self {
            inner,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }

    pub fn into_inner(self) -> IoBufferRepr<'a> {
        let this = ManuallyDrop::new(self);
        unsafe { ptr::read(&this.inner) }
    }

    pub fn as_inner(&self) -> &IoBufferRepr<'a> {
        &self.inner
    }

    fn cast_state<NextState: IoBufferState>(self) -> IoBuffer<'a, NextState, Direction> {
        IoBuffer::<'a, NextState, Direction>::from_inner(self.into_inner())
    }

    fn cast_direction<NextDirection: IoBufferDirection>(
        self,
    ) -> IoBuffer<'a, State, NextDirection> {
        IoBuffer::<'a, State, NextDirection>::from_inner(self.into_inner())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn extent_count(&self) -> usize {
        self.inner.extent_count()
    }

    pub fn is_single_extent(&self) -> bool {
        self.inner.is_single_extent()
    }

    pub fn page_offset(&self) -> usize {
        self.inner.page_offset()
    }

    pub fn page_count(&self) -> usize {
        self.inner.page_count()
    }

    pub fn frame_offset(&self) -> usize {
        self.inner.frame_offset()
    }

    pub fn frame_count(&self) -> usize {
        self.inner.frame_count()
    }

    pub fn extents(&self) -> &[IoBufferExtent] {
        self.inner.extents()
    }

    pub fn page_frames(&self) -> &[IoBufferPageFrame] {
        self.inner.page_frames()
    }

    pub fn physical_frames(&self) -> &[IoBufferPageFrame] {
        self.inner.page_frames()
    }
    pub fn dma_segments(&self) -> IoBufferDmaSegments<'_> {
        self.inner.dma_segments()
    }

    pub fn segment_count(&self) -> usize {
        self.inner.segment_count()
    }

    pub fn iter(&self) -> IoBufferRegionIter<'_> {
        self.inner.iter()
    }
}

impl<'iter, 'a, State: IoBufferState, Direction: IoBufferDirection> IntoIterator
    for &'iter IoBuffer<'a, State, Direction>
{
    type Item = IoBufferRegion<'iter>;
    type IntoIter = IoBufferRegionIter<'iter>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, State: VirtualBackedIoBufferState, Direction: IoBufferDirection>
    IoBuffer<'a, State, Direction>
{
    pub fn virtual_address(&self) -> usize {
        self.inner
            .virtual_address()
            .expect("IoBuffer is not backed by exactly one virtual extent")
    }

    pub fn try_virtual_address(&self) -> Option<usize> {
        self.inner.virtual_address()
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

    pub fn try_as_slice(&self) -> Option<&[u8]> {
        self.inner.try_as_slice()
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

    pub fn try_as_mut_slice(&mut self) -> Option<&mut [u8]> {
        self.inner.try_as_mut_slice()
    }
}

impl<'a> IoBuffer<'a, Described, ToDevice> {
    pub fn from_slice(source: &'a [u8]) -> Self {
        Self::from_inner(IoBufferRepr::new_source(source))
    }

    pub fn try_from_slice(source: &'a [u8]) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::try_new_source(source)?))
    }

    pub fn from_segments(segments: &[&'a [u8]]) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::new_source_segments(
            segments,
        )?))
    }
}

impl<'a> IoBuffer<'a, Described, FromDevice> {
    pub fn from_slice_mut(destination: &'a mut [u8]) -> Self {
        Self::from_inner(IoBufferRepr::new_destination(destination))
    }

    pub fn try_from_slice_mut(destination: &'a mut [u8]) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::try_new_destination(
            destination,
        )?))
    }

    pub fn from_segments_mut(segments: Vec<&'a mut [u8]>) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::new_destination_segments(
            segments,
        )?))
    }
}

impl<'a> IoBuffer<'a, Described, Bidirectional> {
    pub fn from_slice_mut(memory: &'a mut [u8]) -> Self {
        Self::from_inner(IoBufferRepr::new_destination(memory))
    }

    pub fn try_from_slice_mut(memory: &'a mut [u8]) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::try_new_destination(memory)?))
    }

    pub fn from_segments_mut(segments: Vec<&'a mut [u8]>) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::new_destination_segments(
            segments,
        )?))
    }
}

impl<'a, Direction: IoBufferDirection> IoBuffer<'a, PhysFramed, Direction> {
    pub fn from_frames(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
    ) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::new_physical(
            frame_offset,
            byte_len,
            frames,
        )?))
    }

    pub fn from_physical_extents(
        frames: &[IoBufferPageFrame],
        extents: &[IoBufferExtent],
    ) -> Result<Self, IoBufferError> {
        Ok(Self::from_inner(IoBufferRepr::new_physical_extents(
            frames, extents,
        )?))
    }
}

impl<'a, Direction: IoBufferDirection> IoBuffer<'a, Described, Direction> {
    pub fn as_phys_framed(&self) -> &IoBuffer<'a, PhysFramed, Direction> {
        unsafe { &*(self as *const Self as *const IoBuffer<'a, PhysFramed, Direction>) }
    }

    pub fn as_phys_framed_mut(&mut self) -> &mut IoBuffer<'a, PhysFramed, Direction> {
        unsafe { &mut *(self as *mut Self as *mut IoBuffer<'a, PhysFramed, Direction>) }
    }

    pub fn into_phys_framed(self) -> IoBuffer<'a, PhysFramed, Direction> {
        self.cast_state()
    }
}

impl<'a, Direction: IoBufferDirection> core::convert::AsRef<IoBuffer<'a, PhysFramed, Direction>>
    for IoBuffer<'a, Described, Direction>
{
    fn as_ref(&self) -> &IoBuffer<'a, PhysFramed, Direction> {
        self.as_phys_framed()
    }
}

impl<'a, Direction: IoBufferDirection> core::convert::AsMut<IoBuffer<'a, PhysFramed, Direction>>
    for IoBuffer<'a, Described, Direction>
{
    fn as_mut(&mut self) -> &mut IoBuffer<'a, PhysFramed, Direction> {
        self.as_phys_framed_mut()
    }
}

impl<'a, Direction: IoBufferDirection> From<IoBuffer<'a, Described, Direction>>
    for IoBuffer<'a, PhysFramed, Direction>
{
    fn from(buffer: IoBuffer<'a, Described, Direction>) -> Self {
        buffer.into_phys_framed()
    }
}

impl<'a, State: IoBufferState> IoBuffer<'a, State, FromDevice> {
    pub fn into_to_device(self) -> IoBuffer<'a, State, ToDevice> {
        self.cast_direction()
    }
}

impl<'a, State: IoBufferState> IoBuffer<'a, State, Bidirectional> {
    pub fn into_to_device(self) -> IoBuffer<'a, State, ToDevice> {
        self.cast_direction()
    }

    pub fn into_from_device(self) -> IoBuffer<'a, State, FromDevice> {
        self.cast_direction()
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
    pub fn apply_dma_mapping(
        self,
        layout: IoBufferDmaMappingLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<IoBuffer<'a, DmaMapped<S>, D>, (Self, IoBufferError)> {
        let mut inner = self.into_inner();

        if let Err(err) = validate_dma_mapping_layout(&layout) {
            return Err((IoBuffer::<'a, S, D>::from_inner(inner), err));
        }

        inner.dma_segments = DmaSegmentLayout::from(layout);
        inner.set_dma_drop(mapped_by, unmap, cookie);

        Ok(IoBuffer::<'a, DmaMapped<S>, D>::from_inner(inner))
    }

    pub fn apply_dma_mapping_segments(
        self,
        segments: &[IoBufferDmaSegment],
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<IoBuffer<'a, DmaMapped<S>, D>, (Self, IoBufferError)> {
        let layout = IoBufferDmaMappingLayout::Explicit(segments.into());
        self.apply_dma_mapping(layout, mapped_by, unmap, cookie)
    }
}

impl<'a, S: MappableIoBufferState, D: IoBufferDirection> IoBuffer<'a, DmaMapped<S>, D> {
    pub fn remove_dma_mapping(self) -> IoBuffer<'a, S, D> {
        let mut inner = self.into_inner();
        if let Some(ctx) = inner.dma_drop.take() {
            (ctx.unmap)(&ctx.mapped_by, ctx.cookie);
        }
        inner.mapped_by = None;
        inner.dma_segments = DmaSegmentLayout::empty();
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
            .field("virtual_address", &self.inner.virtual_address())
            .field("len", &self.inner.len())
            .field(
                "has_virtual_backing",
                &self.inner.borrow.is_virtual_backed(),
            )
            .field("extent_count", &self.inner.extent_count())
            .field("page_frames_len", &self.inner.page_frames_len)
            .field("dma_segments_len", &self.inner.dma_segments().len())
            .field("mapped", &self.inner.mapped_by.is_some())
            .finish()
    }
}

pub fn copy_from_io_buffer_frames(
    frames: &[IoBufferPageFrame],
    buffer_offset: usize,
    dst: *mut u8,
    len: usize,
) -> bool {
    let mut done = 0;
    let mut remaining = len;
    let mut current_offset = buffer_offset;

    for frame in frames {
        if remaining == 0 {
            break;
        }

        let frame_len = frame.byte_len as usize;
        if current_offset >= frame_len {
            current_offset -= frame_len;
            continue;
        }

        let frame_remaining = frame_len - current_offset;
        let n = core::cmp::min(frame_remaining, remaining);

        unsafe {
            core::ptr::copy_nonoverlapping(
                (frame.cpu_address().as_u64() + current_offset as u64) as *const u8,
                dst.add(done),
                n,
            );
        }

        done += n;
        remaining -= n;
        current_offset = 0;
    }

    remaining == 0
}

pub fn copy_to_io_buffer_frames(
    frames: &[IoBufferPageFrame],
    buffer_offset: usize,
    src: *const u8,
    len: usize,
) -> bool {
    let mut done = 0;
    let mut remaining = len;
    let mut current_offset = buffer_offset;

    for frame in frames {
        if remaining == 0 {
            break;
        }

        let frame_len = frame.byte_len as usize;
        if current_offset >= frame_len {
            current_offset -= frame_len;
            continue;
        }

        let frame_remaining = frame_len - current_offset;
        let n = core::cmp::min(frame_remaining, remaining);

        unsafe {
            core::ptr::copy_nonoverlapping(
                src.add(done),
                (frame.cpu_address().as_u64() + current_offset as u64) as *mut u8,
                n,
            );
        }

        done += n;
        remaining -= n;
        current_offset = 0;
    }

    remaining == 0
}
