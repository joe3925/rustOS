use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr;
use core::slice;
use kernel_macros::RequestPayload;
use spin::Mutex;

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
pub const IOBUFFER_MAX_DMA_SEGMENT_CAPACITY: usize = 128;
pub const IOBUFFER_DEFAULT_LEASE_CAPACITY: usize = 32;
pub const IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY: usize = 8;
pub const IOBUFFER_WORST_CASE_LEASE_GRANULARITY: usize = 4096;

pub const fn iobuffer_worst_case_lease_count(byte_len: usize) -> usize {
    if byte_len == 0 {
        0
    } else {
        ((byte_len - 1) / IOBUFFER_WORST_CASE_LEASE_GRANULARITY) + 1
    }
}

pub enum Described {}
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

impl sealed::IoBufferDirection for ToDevice {}
impl sealed::IoBufferDirection for FromDevice {}
impl sealed::IoBufferDirection for Bidirectional {}

impl sealed::WritableDirection for FromDevice {}
impl sealed::WritableDirection for Bidirectional {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaMappingStrategy {
    SingleContiguous,
    ContiguousChunks { chunk_size: usize },
    FullIdentity,
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoBufferPageFrame {
    pub phys_addr: u64,
    pub byte_len: u64,
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
    LeaseCapacityExceeded {
        capacity: usize,
    },
    DmaRecordCapacityExceeded {
        capacity: usize,
    },
    LeaseConflict {
        start: usize,
        len: usize,
    },
    InvalidLease,
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

const EMPTY_DMA_SEGMENT: IoBufferDmaSegment = IoBufferDmaSegment {
    dma_addr: 0,
    byte_len: 0,
    reserved: 0,
};

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
#[derive(Clone)]
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
        IoBufferDmaSegments::new(
            &self.layout,
            self.extents,
            self.page_frames,
            0,
            logical_len(self.extents),
        )
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

        let offset = usize::try_from(translated.offset)
            .map_err(|_| IoBufferError::TranslationFailed { virt_addr: current })?;
        let frame_len = usize::try_from(translated.byte_len)
            .map_err(|_| IoBufferError::TranslationFailed { virt_addr: current })?;

        if frame_len <= offset {
            return Err(IoBufferError::TranslationFailed { virt_addr: current });
        }

        if frame_count == 0 {
            first_frame_offset = offset;
        }

        let current_base_va = current
            .checked_sub(offset)
            .ok_or(IoBufferError::TranslationFailed { virt_addr: current })?;

        frames.push(IoBufferPageFrame::new(
            translated.phys_addr,
            translated.byte_len,
            crate::arch::VirtAddr::new(current_base_va as u64),
        ));

        frame_count += 1;

        let bytes_in_frame = frame_len - offset;
        let bytes = (byte_len - consumed).min(bytes_in_frame);

        consumed = consumed
            .checked_add(bytes)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok((frame_count, first_frame_offset))
}

fn count_virtual_buffer_frames(virt_addr: usize, byte_len: usize) -> Result<usize, IoBufferError> {
    let mut consumed = 0usize;
    let mut frame_count = 0usize;

    while consumed < byte_len {
        let current = virt_addr
            .checked_add(consumed)
            .ok_or(IoBufferError::TranslationFailed { virt_addr })?;
        let translated = translate_virtual_frame(current)
            .ok_or(IoBufferError::TranslationFailed { virt_addr: current })?;
        let offset = usize::try_from(translated.offset)
            .map_err(|_| IoBufferError::TranslationFailed { virt_addr: current })?;
        let frame_len = usize::try_from(translated.byte_len)
            .map_err(|_| IoBufferError::TranslationFailed { virt_addr: current })?;

        if frame_len <= offset {
            return Err(IoBufferError::TranslationFailed { virt_addr: current });
        }

        let bytes = (byte_len - consumed).min(frame_len - offset);
        consumed = consumed
            .checked_add(bytes)
            .ok_or(IoBufferError::LengthOverflow)?;
        frame_count = frame_count
            .checked_add(1)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok(frame_count)
}

fn describe_virtual_extent_into_vecs(
    virt_addr: usize,
    byte_len: usize,
    page_frames: &mut Vec<IoBufferPageFrame>,
    extents: &mut Vec<IoBufferExtent>,
) -> Result<(), IoBufferError> {
    let first_frame = page_frames.len();
    let (frame_count, frame_offset) =
        describe_virtual_buffer_to_frames(virt_addr, byte_len, page_frames)?;

    extents.push(IoBufferExtent::new(
        Some(virt_addr),
        frame_offset,
        byte_len,
        first_frame,
        frame_count,
    ));

    Ok(())
}

fn validate_mut_segments_disjoint(segments: &[&mut [u8]]) -> Result<(), IoBufferError> {
    for first in 0..segments.len() {
        let first_addr = segments[first].as_ptr() as usize;
        let first_len = segments[first].len();

        if first_len == 0 {
            continue;
        }

        let first_end =
            first_addr
                .checked_add(first_len)
                .ok_or(IoBufferError::TranslationFailed {
                    virt_addr: first_addr,
                })?;

        for second in first + 1..segments.len() {
            let second_addr = segments[second].as_ptr() as usize;
            let second_len = segments[second].len();

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

fn logical_len(extents: &[IoBufferExtent]) -> usize {
    extents
        .iter()
        .fold(0usize, |acc, extent| acc.saturating_add(extent.byte_len))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseAccess {
    Read,
    Write,
    ReadWrite,
}

impl LeaseAccess {
    fn conflicts_with(self, other: Self) -> bool {
        !matches!((self, other), (Self::Read, Self::Read))
    }
}

pub trait DirectionAccess {
    const ACCESS: LeaseAccess;
}

impl DirectionAccess for ToDevice {
    const ACCESS: LeaseAccess = LeaseAccess::Read;
}

impl DirectionAccess for FromDevice {
    const ACCESS: LeaseAccess = LeaseAccess::Write;
}

impl DirectionAccess for Bidirectional {
    const ACCESS: LeaseAccess = LeaseAccess::ReadWrite;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LeaseHandle {
    index: usize,
    generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DmaRecordHandle {
    index: usize,
    generation: u32,
}

#[derive(Clone, Copy, Debug)]
struct LeaseSlot {
    start: usize,
    len: usize,
    access: LeaseAccess,
    generation: u32,
    active: bool,
    dma_record: Option<DmaRecordHandle>,
}

impl LeaseSlot {
    const fn empty() -> Self {
        Self {
            start: 0,
            len: 0,
            access: LeaseAccess::Read,
            generation: 1,
            active: false,
            dma_record: None,
        }
    }

    fn end(&self) -> Option<usize> {
        self.start.checked_add(self.len)
    }
}

struct LeaseTable {
    slots: Box<[LeaseSlot]>,
    active_count: usize,
}

impl LeaseTable {
    fn new(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(LeaseSlot::empty());
        }

        Self {
            slots: slots.into_boxed_slice(),
            active_count: 0,
        }
    }

    fn active_count(&self) -> usize {
        self.active_count
    }

    fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn grow_to(&mut self, count: usize) {
        if count <= self.slots.len() {
            return;
        }

        let mut slots = Vec::with_capacity(count);
        slots.extend_from_slice(&self.slots);
        while slots.len() < count {
            slots.push(LeaseSlot::empty());
        }
        self.slots = slots.into_boxed_slice();
    }

    fn reserve(
        &mut self,
        backing_len: usize,
        start: usize,
        len: usize,
        access: LeaseAccess,
    ) -> Result<LeaseHandle, IoBufferError> {
        let end = start
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;
        if end > backing_len {
            return Err(IoBufferError::InvalidFrameLayout {
                frame_offset: start,
                byte_len: len,
            });
        }

        for slot in self.slots.iter() {
            if !slot.active || len == 0 || slot.len == 0 {
                continue;
            }

            let Some(slot_end) = slot.end() else {
                return Err(IoBufferError::LengthOverflow);
            };

            if start < slot_end && slot.start < end && access.conflicts_with(slot.access) {
                return Err(IoBufferError::LeaseConflict { start, len });
            }
        }

        let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.active)
        else {
            return Err(IoBufferError::LeaseCapacityExceeded {
                capacity: self.slots.len(),
            });
        };

        slot.start = start;
        slot.len = len;
        slot.access = access;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.active = true;
        slot.dma_record = None;
        self.active_count += 1;

        Ok(LeaseHandle {
            index,
            generation: slot.generation,
        })
    }

    fn release(&mut self, handle: LeaseHandle) -> Result<Option<DmaRecordHandle>, IoBufferError> {
        let Some(slot) = self.slots.get_mut(handle.index) else {
            return Err(IoBufferError::InvalidLease);
        };

        if !slot.active || slot.generation != handle.generation {
            return Err(IoBufferError::InvalidLease);
        }

        let dma_record = slot.dma_record.take();
        slot.active = false;
        slot.len = 0;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        self.active_count = self.active_count.saturating_sub(1);
        Ok(dma_record)
    }

    fn set_dma_record(
        &mut self,
        handle: LeaseHandle,
        dma_record: DmaRecordHandle,
    ) -> Result<(), IoBufferError> {
        let slot = self.get_mut(handle)?;
        if slot.dma_record.is_some() {
            return Err(IoBufferError::InvalidLease);
        }
        slot.dma_record = Some(dma_record);
        Ok(())
    }

    fn dma_record(&self, handle: LeaseHandle) -> Result<Option<DmaRecordHandle>, IoBufferError> {
        Ok(self.get(handle)?.dma_record)
    }

    fn take_dma_record(
        &mut self,
        handle: LeaseHandle,
    ) -> Result<Option<DmaRecordHandle>, IoBufferError> {
        Ok(self.get_mut(handle)?.dma_record.take())
    }

    fn split(
        &mut self,
        handle: LeaseHandle,
        mid: usize,
    ) -> Result<(LeaseHandle, LeaseHandle, Option<DmaRecordHandle>), IoBufferError> {
        let parent = *self.get(handle)?;
        if mid > parent.len {
            return Err(IoBufferError::InvalidFrameLayout {
                frame_offset: mid,
                byte_len: parent.len,
            });
        }

        let Some((right_index, _)) = self.slots.iter().enumerate().find(|(_, slot)| !slot.active)
        else {
            return Err(IoBufferError::LeaseCapacityExceeded {
                capacity: self.slots.len(),
            });
        };

        let right_start = parent
            .start
            .checked_add(mid)
            .ok_or(IoBufferError::LengthOverflow)?;
        let right_len = parent.len - mid;

        let left_generation = self.slots[handle.index].generation.wrapping_add(1).max(1);
        self.slots[handle.index].len = mid;
        self.slots[handle.index].generation = left_generation;

        let right_generation = self.slots[right_index].generation.wrapping_add(1).max(1);
        self.slots[right_index] = LeaseSlot {
            start: right_start,
            len: right_len,
            access: parent.access,
            generation: right_generation,
            active: true,
            dma_record: parent.dma_record,
        };
        self.active_count += 1;

        Ok((
            LeaseHandle {
                index: handle.index,
                generation: left_generation,
            },
            LeaseHandle {
                index: right_index,
                generation: right_generation,
            },
            parent.dma_record,
        ))
    }

    fn get(&self, handle: LeaseHandle) -> Result<&LeaseSlot, IoBufferError> {
        let Some(slot) = self.slots.get(handle.index) else {
            return Err(IoBufferError::InvalidLease);
        };

        if !slot.active || slot.generation != handle.generation {
            return Err(IoBufferError::InvalidLease);
        }

        Ok(slot)
    }

    fn get_mut(&mut self, handle: LeaseHandle) -> Result<&mut LeaseSlot, IoBufferError> {
        let Some(slot) = self.slots.get_mut(handle.index) else {
            return Err(IoBufferError::InvalidLease);
        };

        if !slot.active || slot.generation != handle.generation {
            return Err(IoBufferError::InvalidLease);
        }

        Ok(slot)
    }
}

#[derive(Clone)]
struct DmaRecordSlot {
    active: bool,
    generation: u32,
    ref_count: usize,
    layout: DmaSegmentLayout,
    drop_ctx: Option<DmaDropContext>,
}

impl DmaRecordSlot {
    fn empty() -> Self {
        Self {
            active: false,
            generation: 1,
            ref_count: 0,
            layout: DmaSegmentLayout::empty(),
            drop_ctx: None,
        }
    }
}

struct DmaRecordTable {
    slots: Box<[DmaRecordSlot]>,
}

impl DmaRecordTable {
    fn new(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(DmaRecordSlot::empty());
        }

        Self {
            slots: slots.into_boxed_slice(),
        }
    }

    fn alloc(
        &mut self,
        layout: DmaSegmentLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<DmaRecordHandle, IoBufferError> {
        let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.active)
        else {
            return Err(IoBufferError::DmaRecordCapacityExceeded {
                capacity: self.slots.len(),
            });
        };

        slot.active = true;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.ref_count = 1;
        slot.layout = layout;
        slot.drop_ctx = Some(DmaDropContext {
            mapped_by,
            unmap,
            cookie,
        });

        Ok(DmaRecordHandle {
            index,
            generation: slot.generation,
        })
    }

    fn inc_ref(&mut self, handle: DmaRecordHandle) -> Result<(), IoBufferError> {
        let slot = self.get_mut(handle)?;
        slot.ref_count = slot
            .ref_count
            .checked_add(1)
            .ok_or(IoBufferError::LengthOverflow)?;
        Ok(())
    }

    fn release(
        &mut self,
        handle: DmaRecordHandle,
    ) -> Result<Option<DmaDropContext>, IoBufferError> {
        let slot = self.get_mut(handle)?;
        if slot.ref_count == 0 {
            return Err(IoBufferError::InvalidLease);
        }

        slot.ref_count -= 1;
        if slot.ref_count != 0 {
            return Ok(None);
        }

        slot.active = false;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.layout = DmaSegmentLayout::empty();
        Ok(slot.drop_ctx.take())
    }

    fn layout(&self, handle: DmaRecordHandle) -> Result<DmaSegmentLayout, IoBufferError> {
        Ok(self.get(handle)?.layout.clone())
    }

    fn mapped_by(
        &self,
        handle: DmaRecordHandle,
    ) -> Result<Option<Arc<DeviceObject>>, IoBufferError> {
        Ok(self
            .get(handle)?
            .drop_ctx
            .as_ref()
            .map(|ctx| ctx.mapped_by.clone()))
    }

    fn get(&self, handle: DmaRecordHandle) -> Result<&DmaRecordSlot, IoBufferError> {
        let Some(slot) = self.slots.get(handle.index) else {
            return Err(IoBufferError::InvalidLease);
        };

        if !slot.active || slot.generation != handle.generation {
            return Err(IoBufferError::InvalidLease);
        }

        Ok(slot)
    }

    fn get_mut(&mut self, handle: DmaRecordHandle) -> Result<&mut DmaRecordSlot, IoBufferError> {
        let Some(slot) = self.slots.get_mut(handle.index) else {
            return Err(IoBufferError::InvalidLease);
        };

        if !slot.active || slot.generation != handle.generation {
            return Err(IoBufferError::InvalidLease);
        }

        Ok(slot)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoBufferBackingConfig {
    pub lease_capacity: usize,
    pub dma_record_capacity: usize,
    pub preallocate_worst_case_virtual_extents_for_physical: bool,
}

impl Default for IoBufferBackingConfig {
    fn default() -> Self {
        Self {
            lease_capacity: IOBUFFER_DEFAULT_LEASE_CAPACITY,
            dma_record_capacity: IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY,
            preallocate_worst_case_virtual_extents_for_physical: false,
        }
    }
}

pub struct IoBufferBacking<'data> {
    byte_len: usize,
    virtual_backed: bool,
    writable: bool,
    extents: Vec<IoBufferExtent>,
    page_frames: Vec<IoBufferPageFrame>,
    leases: Mutex<LeaseTable>,
    dma_records: Mutex<DmaRecordTable>,
    _data: PhantomData<&'data mut [u8]>,
}

impl<'data> IoBufferBacking<'data> {
    pub fn try_from_slice(source: &'data [u8]) -> Result<Self, IoBufferError> {
        Self::try_from_slice_with_config(source, IoBufferBackingConfig::default())
    }

    pub fn try_from_slice_with_config(
        source: &'data [u8],
        config: IoBufferBackingConfig,
    ) -> Result<Self, IoBufferError> {
        let mut extents = Vec::with_capacity(IOBUFFER_INLINE_EXTENT_CAPACITY.max(1));
        let mut page_frames = Vec::with_capacity(IOBUFFER_INLINE_PAGE_CAPACITY.max(1));
        describe_virtual_extent_into_vecs(
            source.as_ptr() as usize,
            source.len(),
            &mut page_frames,
            &mut extents,
        )?;

        Ok(Self::new_unchecked(
            source.len(),
            true,
            false,
            false,
            extents,
            page_frames,
            config,
        ))
    }

    pub fn try_from_slice_mut(destination: &'data mut [u8]) -> Result<Self, IoBufferError> {
        Self::try_from_slice_mut_with_config(destination, IoBufferBackingConfig::default())
    }

    pub fn try_from_slice_mut_with_config(
        destination: &'data mut [u8],
        config: IoBufferBackingConfig,
    ) -> Result<Self, IoBufferError> {
        let mut extents = Vec::with_capacity(IOBUFFER_INLINE_EXTENT_CAPACITY.max(1));
        let mut page_frames = Vec::with_capacity(IOBUFFER_INLINE_PAGE_CAPACITY.max(1));
        describe_virtual_extent_into_vecs(
            destination.as_ptr() as usize,
            destination.len(),
            &mut page_frames,
            &mut extents,
        )?;

        Ok(Self::new_unchecked(
            destination.len(),
            true,
            true,
            false,
            extents,
            page_frames,
            config,
        ))
    }

    pub fn try_from_segments(segments: &[&'data [u8]]) -> Result<Self, IoBufferError> {
        Self::try_from_segments_with_config(segments, IoBufferBackingConfig::default())
    }

    pub fn try_from_segments_with_config(
        segments: &[&'data [u8]],
        config: IoBufferBackingConfig,
    ) -> Result<Self, IoBufferError> {
        let mut extents = Vec::with_capacity(segments.len().max(IOBUFFER_INLINE_EXTENT_CAPACITY));
        let mut page_frames = Vec::with_capacity(IOBUFFER_INLINE_PAGE_CAPACITY);
        let mut byte_len = 0usize;

        for &segment in segments {
            describe_virtual_extent_into_vecs(
                segment.as_ptr() as usize,
                segment.len(),
                &mut page_frames,
                &mut extents,
            )?;
            byte_len = byte_len
                .checked_add(segment.len())
                .ok_or(IoBufferError::LengthOverflow)?;
        }

        Ok(Self::new_unchecked(
            byte_len,
            true,
            false,
            false,
            extents,
            page_frames,
            config,
        ))
    }

    pub fn try_from_segments_mut(segments: Vec<&'data mut [u8]>) -> Result<Self, IoBufferError> {
        Self::try_from_segments_mut_with_config(segments, IoBufferBackingConfig::default())
    }

    pub fn try_from_segments_mut_with_config(
        segments: Vec<&'data mut [u8]>,
        config: IoBufferBackingConfig,
    ) -> Result<Self, IoBufferError> {
        validate_mut_segments_disjoint(&segments)?;

        let mut extents = Vec::with_capacity(segments.len().max(IOBUFFER_INLINE_EXTENT_CAPACITY));
        let mut page_frames = Vec::with_capacity(IOBUFFER_INLINE_PAGE_CAPACITY);
        let mut byte_len = 0usize;

        for segment in &segments {
            describe_virtual_extent_into_vecs(
                segment.as_ptr() as usize,
                segment.len(),
                &mut page_frames,
                &mut extents,
            )?;
            byte_len = byte_len
                .checked_add(segment.len())
                .ok_or(IoBufferError::LengthOverflow)?;
        }

        Ok(Self::new_unchecked(
            byte_len,
            true,
            true,
            false,
            extents,
            page_frames,
            config,
        ))
    }

    pub fn try_from_frames(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
    ) -> Result<Self, IoBufferError> {
        Self::try_from_frames_with_config(
            frame_offset,
            byte_len,
            frames,
            IoBufferBackingConfig::default(),
        )
    }

    pub fn try_from_frames_with_config(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
        config: IoBufferBackingConfig,
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
        Self::try_from_physical_extents_with_config(frames, &[extent], config)
    }

    pub fn try_from_physical_extents(
        frames: &[IoBufferPageFrame],
        extents: &[IoBufferExtent],
    ) -> Result<Self, IoBufferError> {
        Self::try_from_physical_extents_with_config(
            frames,
            extents,
            IoBufferBackingConfig::default(),
        )
    }

    pub fn try_from_physical_extents_with_config(
        frames: &[IoBufferPageFrame],
        extents: &[IoBufferExtent],
        config: IoBufferBackingConfig,
    ) -> Result<Self, IoBufferError> {
        let byte_len = validate_physical_extents(frames, extents)?;

        Ok(Self::new_unchecked(
            byte_len,
            extents.iter().any(|extent| extent.virtual_addr.is_some()),
            true,
            true,
            extents.to_vec(),
            frames.to_vec(),
            config,
        ))
    }

    fn new_unchecked(
        byte_len: usize,
        virtual_backed: bool,
        writable: bool,
        physical_backing: bool,
        mut extents: Vec<IoBufferExtent>,
        page_frames: Vec<IoBufferPageFrame>,
        config: IoBufferBackingConfig,
    ) -> Self {
        let worst_case = iobuffer_worst_case_lease_count(byte_len);
        if physical_backing && config.preallocate_worst_case_virtual_extents_for_physical {
            if extents.capacity() < worst_case {
                extents.reserve_exact(worst_case - extents.capacity());
            }
        }

        let dma_record_capacity = config.dma_record_capacity;

        Self {
            byte_len,
            virtual_backed,
            writable,
            extents,
            page_frames,
            leases: Mutex::new(LeaseTable::new(config.lease_capacity)),
            dma_records: Mutex::new(DmaRecordTable::new(dma_record_capacity)),
            _data: PhantomData,
        }
    }

    pub fn redescribe_from_slice(&mut self, source: &'data [u8]) -> Result<(), IoBufferError> {
        self.ensure_redescribe_ready()?;
        self.ensure_extent_capacity(1)?;
        let frame_count = count_virtual_buffer_frames(source.as_ptr() as usize, source.len())?;
        self.ensure_page_capacity(frame_count)?;

        self.extents.clear();
        self.page_frames.clear();
        describe_virtual_extent_into_vecs(
            source.as_ptr() as usize,
            source.len(),
            &mut self.page_frames,
            &mut self.extents,
        )?;
        self.byte_len = source.len();
        self.virtual_backed = true;
        self.writable = false;
        Ok(())
    }

    pub fn redescribe_from_slice_mut(
        &mut self,
        destination: &'data mut [u8],
    ) -> Result<(), IoBufferError> {
        self.ensure_redescribe_ready()?;
        self.ensure_extent_capacity(1)?;
        let frame_count =
            count_virtual_buffer_frames(destination.as_ptr() as usize, destination.len())?;
        self.ensure_page_capacity(frame_count)?;

        self.extents.clear();
        self.page_frames.clear();
        describe_virtual_extent_into_vecs(
            destination.as_ptr() as usize,
            destination.len(),
            &mut self.page_frames,
            &mut self.extents,
        )?;
        self.byte_len = destination.len();
        self.virtual_backed = true;
        self.writable = true;
        Ok(())
    }

    pub fn redescribe_from_physical_extents(
        &mut self,
        frames: &[IoBufferPageFrame],
        extents: &[IoBufferExtent],
    ) -> Result<(), IoBufferError> {
        let byte_len = validate_physical_extents(frames, extents)?;
        self.ensure_redescribe_ready()?;
        self.ensure_extent_capacity(extents.len())?;
        self.ensure_page_capacity(frames.len())?;

        self.extents.clear();
        self.extents.extend_from_slice(extents);
        self.page_frames.clear();
        self.page_frames.extend_from_slice(frames);
        self.byte_len = byte_len;
        self.virtual_backed = extents.iter().any(|extent| extent.virtual_addr.is_some());
        self.writable = true;
        Ok(())
    }

    fn ensure_redescribe_ready(&mut self) -> Result<(), IoBufferError> {
        if self.leases.get_mut().active_count() != 0 {
            return Err(IoBufferError::LeaseConflict {
                start: 0,
                len: self.byte_len,
            });
        }
        Ok(())
    }

    fn ensure_extent_capacity(&self, required: usize) -> Result<(), IoBufferError> {
        if required > self.extents.capacity() {
            return Err(IoBufferError::ExtentCapacityExceeded {
                required,
                capacity: self.extents.capacity(),
            });
        }
        Ok(())
    }

    fn ensure_page_capacity(&self, required: usize) -> Result<(), IoBufferError> {
        if required > self.page_frames.capacity() {
            return Err(IoBufferError::PageCapacityExceeded {
                required,
                capacity: self.page_frames.capacity(),
            });
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn worst_case_max_lease_count(&self) -> usize {
        iobuffer_worst_case_lease_count(self.byte_len)
    }

    pub fn lease_capacity(&self) -> usize {
        self.leases.lock().capacity()
    }

    pub fn active_lease_count(&self) -> usize {
        self.leases.lock().active_count()
    }

    pub fn grow_lease_list(&self, count: usize) {
        self.leases.lock().grow_to(count);
    }

    pub fn create_to_device_buffer(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, Described, ToDevice>, IoBufferError> {
        self.create_buffer_no_alloc(offset, len)
    }

    pub fn create_to_device_buffer_alloc(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, Described, ToDevice>, IoBufferError> {
        self.create_buffer_alloc(offset, len)
    }

    pub fn create_from_device_buffer(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, Described, FromDevice>, IoBufferError> {
        self.create_buffer_no_alloc(offset, len)
    }

    pub fn create_from_device_buffer_alloc(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, Described, FromDevice>, IoBufferError> {
        self.create_buffer_alloc(offset, len)
    }

    pub fn create_bidirectional_buffer(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, Described, Bidirectional>, IoBufferError> {
        self.create_buffer_no_alloc(offset, len)
    }

    pub fn create_bidirectional_buffer_alloc(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, Described, Bidirectional>, IoBufferError> {
        self.create_buffer_alloc(offset, len)
    }

    pub fn create_phys_to_device_buffer(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, PhysFramed, ToDevice>, IoBufferError> {
        self.create_buffer_no_alloc(offset, len)
    }

    pub fn create_phys_to_device_buffer_alloc(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, PhysFramed, ToDevice>, IoBufferError> {
        self.create_buffer_alloc(offset, len)
    }

    pub fn create_phys_from_device_buffer(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, PhysFramed, FromDevice>, IoBufferError> {
        self.create_buffer_no_alloc(offset, len)
    }

    pub fn create_phys_from_device_buffer_alloc(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, PhysFramed, FromDevice>, IoBufferError> {
        self.create_buffer_alloc(offset, len)
    }

    pub fn create_buffer_no_alloc<State, Direction>(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, State, Direction>, IoBufferError>
    where
        State: IoBufferState,
        Direction: IoBufferDirection + DirectionAccess,
    {
        self.check_access::<Direction>()?;
        let lease = self.reserve_lease_no_alloc(offset, len, Direction::ACCESS)?;
        Ok(IoBuffer::new_borrowed(self, lease, offset, len))
    }

    pub fn create_buffer_alloc<State, Direction>(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, State, Direction>, IoBufferError>
    where
        State: IoBufferState,
        Direction: IoBufferDirection + DirectionAccess,
    {
        self.check_access::<Direction>()?;
        let lease = self.reserve_lease_alloc(offset, len, Direction::ACCESS)?;
        Ok(IoBuffer::new_borrowed(self, lease, offset, len))
    }

    pub fn create_buffer<State, Direction>(
        &'data self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'data, State, Direction>, IoBufferError>
    where
        State: IoBufferState,
        Direction: IoBufferDirection + DirectionAccess,
    {
        self.create_buffer_no_alloc(offset, len)
    }

    fn check_access<Direction>(&self) -> Result<(), IoBufferError>
    where
        Direction: IoBufferDirection + DirectionAccess,
    {
        if !self.writable && !matches!(Direction::ACCESS, LeaseAccess::Read) {
            return Err(IoBufferError::LeaseConflict {
                start: 0,
                len: self.byte_len,
            });
        }

        Ok(())
    }

    fn reserve_lease_no_alloc(
        &self,
        offset: usize,
        len: usize,
        access: LeaseAccess,
    ) -> Result<LeaseHandle, IoBufferError> {
        self.leases
            .lock()
            .reserve(self.byte_len, offset, len, access)
    }

    fn reserve_lease_alloc(
        &self,
        offset: usize,
        len: usize,
        access: LeaseAccess,
    ) -> Result<LeaseHandle, IoBufferError> {
        let mut leases = self.leases.lock();
        match leases.reserve(self.byte_len, offset, len, access) {
            Ok(lease) => Ok(lease),
            Err(IoBufferError::LeaseCapacityExceeded { .. }) => {
                let required = leases
                    .active_count()
                    .checked_add(1)
                    .ok_or(IoBufferError::LengthOverflow)?;
                let doubled = leases.capacity().saturating_mul(2).max(1);
                leases.grow_to(required.max(doubled));
                leases.reserve(self.byte_len, offset, len, access)
            }
            Err(err) => Err(err),
        }
    }

    fn release_lease(&self, handle: LeaseHandle) {
        let dma_record = self.leases.lock().release(handle).ok().flatten();
        if let Some(dma_record) = dma_record {
            self.release_dma_record(dma_record);
        }
    }

    fn split_lease_no_alloc(
        &self,
        handle: LeaseHandle,
        mid: usize,
    ) -> Result<(LeaseHandle, LeaseHandle), IoBufferError> {
        let (left, right, dma_record) = self.leases.lock().split(handle, mid)?;
        if let Some(dma_record) = dma_record {
            self.dma_records.lock().inc_ref(dma_record)?;
        }
        Ok((left, right))
    }

    fn split_lease_alloc(
        &self,
        handle: LeaseHandle,
        mid: usize,
    ) -> Result<(LeaseHandle, LeaseHandle), IoBufferError> {
        let mut leases = self.leases.lock();
        let split = leases.split(handle, mid);
        let (left, right, dma_record) = match split {
            Ok(result) => result,
            Err(IoBufferError::LeaseCapacityExceeded { .. }) => {
                let required = leases
                    .active_count()
                    .checked_add(1)
                    .ok_or(IoBufferError::LengthOverflow)?;
                let doubled = leases.capacity().saturating_mul(2).max(1);
                leases.grow_to(required.max(doubled));
                leases.split(handle, mid)?
            }
            Err(err) => return Err(err),
        };
        drop(leases);
        if let Some(dma_record) = dma_record {
            self.dma_records.lock().inc_ref(dma_record)?;
        }
        Ok((left, right))
    }

    fn attach_dma_record(
        &self,
        lease: LeaseHandle,
        layout: DmaSegmentLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<(), IoBufferError> {
        let dma_record = self
            .dma_records
            .lock()
            .alloc(layout, mapped_by, unmap, cookie)?;
        let result = self.leases.lock().set_dma_record(lease, dma_record);
        if result.is_err() {
            self.release_dma_record(dma_record);
        }
        result
    }

    fn release_dma_record(&self, handle: DmaRecordHandle) {
        let drop_ctx = self.dma_records.lock().release(handle).ok().flatten();
        if let Some(drop_ctx) = drop_ctx {
            (drop_ctx.unmap)(&drop_ctx.mapped_by, drop_ctx.cookie);
        }
    }

    fn detach_dma_record(&self, handle: LeaseHandle) {
        let dma_record = self.leases.lock().take_dma_record(handle).ok().flatten();
        if let Some(dma_record) = dma_record {
            self.release_dma_record(dma_record);
        }
    }

    fn dma_layout_for_lease(&self, lease: LeaseHandle) -> DmaSegmentLayout {
        let dma_record = self.leases.lock().dma_record(lease).ok().flatten();
        let Some(dma_record) = dma_record else {
            return DmaSegmentLayout::empty();
        };
        self.dma_records
            .lock()
            .layout(dma_record)
            .unwrap_or_else(|_| DmaSegmentLayout::empty())
    }

    fn mapped_by_for_lease(&self, lease: LeaseHandle) -> Option<Arc<DeviceObject>> {
        let dma_record = self.leases.lock().dma_record(lease).ok().flatten()?;
        self.dma_records.lock().mapped_by(dma_record).ok().flatten()
    }

    fn extents(&self) -> &[IoBufferExtent] {
        self.extents.as_slice()
    }

    fn page_frames(&self) -> &[IoBufferPageFrame] {
        self.page_frames.as_slice()
    }
}

#[derive(Clone)]
enum IoBufferBackingRef<'data> {
    Borrowed(&'data IoBufferBacking<'data>),
    Owned(Arc<IoBufferBacking<'data>>),
}

impl<'data> IoBufferBackingRef<'data> {
    fn as_ref(&self) -> &IoBufferBacking<'data> {
        match self {
            Self::Borrowed(backing) => backing,
            Self::Owned(backing) => backing.as_ref(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameWindow {
    first_frame: usize,
    frame_count: usize,
    frame_offset: usize,
}

fn extent_subrange_frames(
    extent: IoBufferExtent,
    frames: &[IoBufferPageFrame],
    offset_in_extent: usize,
    len: usize,
) -> Option<FrameWindow> {
    let mut frame_index = extent.first_frame;
    let frame_end = extent.first_frame.checked_add(extent.frame_count)?;
    let mut frame_offset = extent.frame_offset.checked_add(offset_in_extent)?;

    while frame_index < frame_end {
        let frame_len = frames.get(frame_index)?.byte_len as usize;
        if frame_offset < frame_len {
            break;
        }
        frame_offset -= frame_len;
        frame_index += 1;
    }

    if frame_index >= frame_end {
        return None;
    }

    let first_frame = frame_index;
    let first_offset = frame_offset;
    let mut remaining = len;

    while frame_index < frame_end && remaining != 0 {
        let frame_len = frames.get(frame_index)?.byte_len as usize;
        let available = frame_len.checked_sub(frame_offset)?;
        let take = available.min(remaining);
        remaining -= take;
        frame_index += 1;
        frame_offset = 0;
    }

    if remaining != 0 {
        return None;
    }

    Some(FrameWindow {
        first_frame,
        frame_count: frame_index - first_frame,
        frame_offset: first_offset,
    })
}

pub struct IoBufferExtentIter<'a> {
    extents: &'a [IoBufferExtent],
    frames: &'a [IoBufferPageFrame],
    next_extent: usize,
    logical_cursor: usize,
    view_start: usize,
    view_end: usize,
}

impl<'a> IoBufferExtentIter<'a> {
    fn new(
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
        view_start: usize,
        view_len: usize,
    ) -> Self {
        Self {
            extents,
            frames,
            next_extent: 0,
            logical_cursor: 0,
            view_start,
            view_end: view_start.saturating_add(view_len),
        }
    }
}

impl Iterator for IoBufferExtentIter<'_> {
    type Item = IoBufferExtent;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_extent < self.extents.len() {
            let extent = self.extents[self.next_extent];
            self.next_extent += 1;

            let extent_start = self.logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;
            self.logical_cursor = extent_end;

            let start = extent_start.max(self.view_start);
            let end = extent_end.min(self.view_end);
            if start >= end {
                continue;
            }

            let offset_in_extent = start - extent_start;
            let len = end - start;
            let frame_window = extent_subrange_frames(extent, self.frames, offset_in_extent, len)?;
            let virtual_addr = extent
                .virtual_addr
                .and_then(|addr| addr.checked_add(offset_in_extent));

            return Some(IoBufferExtent::new(
                virtual_addr,
                frame_window.frame_offset,
                len,
                frame_window.first_frame,
                frame_window.frame_count,
            ));
        }

        None
    }
}

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
    extents: IoBufferExtentIter<'a>,
    frames: &'a [IoBufferPageFrame],
}

impl<'a> IoBufferRegionIter<'a> {
    fn new(
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
        view_start: usize,
        view_len: usize,
    ) -> Self {
        Self {
            extents: IoBufferExtentIter::new(extents, frames, view_start, view_len),
            frames,
        }
    }
}

impl<'a> Iterator for IoBufferRegionIter<'a> {
    type Item = IoBufferRegion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let extent = self.extents.next()?;
        let end_frame = extent.first_frame.checked_add(extent.frame_count)?;
        let page_frames = self.frames.get(extent.first_frame..end_frame)?;

        Some(IoBufferRegion {
            virtual_addr: extent.virtual_addr,
            frame_offset: extent.frame_offset,
            byte_len: extent.byte_len,
            page_frames,
        })
    }
}

pub struct IoBufferDmaSegments<'a> {
    layout: DmaSegmentLayout,
    extents: &'a [IoBufferExtent],
    page_frames: &'a [IoBufferPageFrame],
    view_start: usize,
    view_len: usize,
}

impl<'a> IoBufferDmaSegments<'a> {
    fn new(
        layout: &DmaSegmentLayout,
        extents: &'a [IoBufferExtent],
        page_frames: &'a [IoBufferPageFrame],
        view_start: usize,
        view_len: usize,
    ) -> Self {
        Self {
            layout: layout.clone(),
            extents,
            page_frames,
            view_start,
            view_len,
        }
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn first(&self) -> Option<IoBufferDmaSegment> {
        self.iter().next()
    }

    pub fn iter(&self) -> IoBufferDmaSegmentViewIter<'a> {
        IoBufferDmaSegmentViewIter {
            inner: IoBufferDmaSegmentIter::new(&self.layout, self.extents, self.page_frames),
            skip: self.view_start,
            remaining: self.view_len,
        }
    }
}

impl<'a> IntoIterator for IoBufferDmaSegments<'a> {
    type Item = IoBufferDmaSegment;
    type IntoIter = IoBufferDmaSegmentViewIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'segments, 'a> IntoIterator for &'segments IoBufferDmaSegments<'a> {
    type Item = IoBufferDmaSegment;
    type IntoIter = IoBufferDmaSegmentViewIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct IoBufferDmaSegmentViewIter<'a> {
    inner: IoBufferDmaSegmentIter<'a>,
    skip: usize,
    remaining: usize,
}

impl Iterator for IoBufferDmaSegmentViewIter<'_> {
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let mut segment = self.inner.next()?;
            let segment_len = segment.byte_len as usize;

            if self.skip >= segment_len {
                self.skip -= segment_len;
                continue;
            }

            if self.skip != 0 {
                segment.dma_addr = segment.dma_addr.checked_add(self.skip as u64)?;
                segment.byte_len = segment.byte_len.checked_sub(self.skip as u32)?;
                self.skip = 0;
            }

            let take = (segment.byte_len as usize).min(self.remaining);
            segment.byte_len = take as u32;
            self.remaining -= take;
            return Some(segment);
        }

        None
    }
}

pub struct IoBufferDmaSegmentIter<'a> {
    layout: DmaSegmentLayout,
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

impl<'a> IoBufferDmaSegmentIter<'a> {
    fn new(
        layout: &DmaSegmentLayout,
        extents: &'a [IoBufferExtent],
        page_frames: &'a [IoBufferPageFrame],
    ) -> Self {
        Self {
            layout: layout.clone(),
            extents,
            page_frames,
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

impl<'a> Iterator for IoBufferDmaSegmentIter<'a> {
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.layout {
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

#[repr(C)]
#[derive(RequestPayload)]
#[request_view(
    IoBuffer<'a, Described, Direction> => IoBuffer<'a, PhysFramed, Direction>
    where Direction: IoBufferDirection + DirectionAccess
)]
#[request_view_mut(
    IoBuffer<'a, Described, Direction> => IoBuffer<'a, PhysFramed, Direction>
    where Direction: IoBufferDirection + DirectionAccess
)]
pub struct IoBuffer<'a, State: IoBufferState, Direction: IoBufferDirection> {
    backing: IoBufferBackingRef<'a>,
    lease: LeaseHandle,
    offset: usize,
    byte_len: usize,
    _state: PhantomData<fn() -> State>,
    _direction: PhantomData<fn() -> Direction>,
}

impl<'a, State, Direction> IoBuffer<'a, State, Direction>
where
    State: IoBufferState,
    Direction: IoBufferDirection,
{
    fn new_borrowed(
        backing: &'a IoBufferBacking<'a>,
        lease: LeaseHandle,
        offset: usize,
        byte_len: usize,
    ) -> Self {
        Self {
            backing: IoBufferBackingRef::Borrowed(backing),
            lease,
            offset,
            byte_len,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }

    fn new_owned(
        backing: Arc<IoBufferBacking<'a>>,
        lease: LeaseHandle,
        offset: usize,
        byte_len: usize,
    ) -> Self {
        Self {
            backing: IoBufferBackingRef::Owned(backing),
            lease,
            offset,
            byte_len,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }

    fn backing(&self) -> &IoBufferBacking<'a> {
        self.backing.as_ref()
    }

    fn into_parts(self) -> (IoBufferBackingRef<'a>, LeaseHandle, usize, usize) {
        let this = ManuallyDrop::new(self);
        unsafe {
            (
                ptr::read(&this.backing),
                this.lease,
                this.offset,
                this.byte_len,
            )
        }
    }

    fn cast_state<NextState: IoBufferState>(self) -> IoBuffer<'a, NextState, Direction> {
        let (backing, lease, offset, byte_len) = self.into_parts();
        IoBuffer {
            backing,
            lease,
            offset,
            byte_len,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }

    fn cast_direction<NextDirection: IoBufferDirection>(
        self,
    ) -> IoBuffer<'a, State, NextDirection> {
        let (backing, lease, offset, byte_len) = self.into_parts();
        IoBuffer {
            backing,
            lease,
            offset,
            byte_len,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn extent_count(&self) -> usize {
        self.extents().count()
    }

    pub fn is_single_extent(&self) -> bool {
        self.extent_count() == 1
    }

    pub fn page_offset(&self) -> usize {
        self.extents()
            .next()
            .map_or(0, |extent| extent.frame_offset)
    }

    pub fn page_count(&self) -> usize {
        self.page_frames().len()
    }

    pub fn frame_offset(&self) -> usize {
        self.page_offset()
    }

    pub fn frame_count(&self) -> usize {
        self.page_count()
    }

    pub fn extents(&self) -> IoBufferExtentIter<'_> {
        IoBufferExtentIter::new(
            self.backing().extents(),
            self.backing().page_frames(),
            self.offset,
            self.byte_len,
        )
    }

    pub fn page_frames(&self) -> &[IoBufferPageFrame] {
        let backing = self.backing();
        let frames = backing.page_frames();
        let mut first = usize::MAX;
        let mut end = 0usize;

        for extent in self.extents() {
            if extent.frame_count == 0 {
                continue;
            }

            first = first.min(extent.first_frame);
            end = end.max(extent.first_frame + extent.frame_count);
        }

        if first == usize::MAX || end > frames.len() {
            &[]
        } else {
            &frames[first..end]
        }
    }

    pub fn physical_frames(&self) -> &[IoBufferPageFrame] {
        self.page_frames()
    }

    pub fn dma_segments(&self) -> IoBufferDmaSegments<'_> {
        let backing = self.backing();
        let layout = backing.dma_layout_for_lease(self.lease);
        IoBufferDmaSegments::new(
            &layout,
            backing.extents(),
            backing.page_frames(),
            self.offset,
            self.byte_len,
        )
    }

    pub fn segment_count(&self) -> usize {
        self.dma_segments().len()
    }

    pub fn iter(&self) -> IoBufferRegionIter<'_> {
        IoBufferRegionIter::new(
            self.backing().extents(),
            self.backing().page_frames(),
            self.offset,
            self.byte_len,
        )
    }

    pub fn split_at(self, mid: usize) -> Result<(Self, Self), (Self, IoBufferError)> {
        if mid > self.byte_len {
            let len = self.byte_len;

            return Err((
                self,
                IoBufferError::InvalidFrameLayout {
                    frame_offset: mid,
                    byte_len: len,
                },
            ));
        }

        let this = ManuallyDrop::new(self);
        let backing_ref = unsafe { ptr::read(&this.backing) };
        let backing = backing_ref.as_ref();
        let split = backing.split_lease_no_alloc(this.lease, mid);

        match split {
            Ok((left_lease, right_lease)) => {
                let right_backing = backing_ref.clone();
                let left = IoBuffer {
                    backing: backing_ref,
                    lease: left_lease,
                    offset: this.offset,
                    byte_len: mid,
                    _state: PhantomData,
                    _direction: PhantomData,
                };
                let right = IoBuffer {
                    backing: right_backing,
                    lease: right_lease,
                    offset: this.offset + mid,
                    byte_len: this.byte_len - mid,
                    _state: PhantomData,
                    _direction: PhantomData,
                };
                Ok((left, right))
            }
            Err(err) => {
                let original = IoBuffer {
                    backing: backing_ref,
                    lease: this.lease,
                    offset: this.offset,
                    byte_len: this.byte_len,
                    _state: PhantomData,
                    _direction: PhantomData,
                };
                Err((original, err))
            }
        }
    }

    pub fn split_at_alloc(self, mid: usize) -> Result<(Self, Self), (Self, IoBufferError)> {
        if mid > self.byte_len {
            let len = self.byte_len;
            return Err((
                self,
                IoBufferError::InvalidFrameLayout {
                    frame_offset: mid,
                    byte_len: len,
                },
            ));
        }

        let this = ManuallyDrop::new(self);
        let backing_ref = unsafe { ptr::read(&this.backing) };
        let backing = backing_ref.as_ref();
        let split = backing.split_lease_alloc(this.lease, mid);

        match split {
            Ok((left_lease, right_lease)) => {
                let right_backing = backing_ref.clone();
                Ok((
                    IoBuffer {
                        backing: backing_ref,
                        lease: left_lease,
                        offset: this.offset,
                        byte_len: mid,
                        _state: PhantomData,
                        _direction: PhantomData,
                    },
                    IoBuffer {
                        backing: right_backing,
                        lease: right_lease,
                        offset: this.offset + mid,
                        byte_len: this.byte_len - mid,
                        _state: PhantomData,
                        _direction: PhantomData,
                    },
                ))
            }
            Err(err) => Err((
                IoBuffer {
                    backing: backing_ref,
                    lease: this.lease,
                    offset: this.offset,
                    byte_len: this.byte_len,
                    _state: PhantomData,
                    _direction: PhantomData,
                },
                err,
            )),
        }
    }
}

impl<'iter, 'a, State, Direction> IntoIterator for &'iter IoBuffer<'a, State, Direction>
where
    State: IoBufferState,
    Direction: IoBufferDirection,
{
    type Item = IoBufferRegion<'iter>;
    type IntoIter = IoBufferRegionIter<'iter>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, State, Direction> IoBuffer<'a, State, Direction>
where
    State: VirtualBackedIoBufferState,
    Direction: IoBufferDirection,
{
    pub fn virtual_address(&self) -> usize {
        self.try_virtual_address()
            .expect("IoBuffer is not backed by exactly one virtual extent")
    }

    pub fn try_virtual_address(&self) -> Option<usize> {
        let mut iter = self.extents();
        let first = iter.next()?;
        if iter.next().is_some() {
            return None;
        }
        first.virtual_addr
    }

    pub fn page_base_address(&self) -> usize {
        self.virtual_address()
            .checked_sub(self.page_offset())
            .expect("IoBuffer extent frame offset exceeds virtual address")
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.try_as_slice()
            .expect("IoBuffer is not backed by exactly one virtual extent")
    }

    pub fn try_as_slice(&self) -> Option<&[u8]> {
        let addr = self.try_virtual_address()?;
        unsafe { Some(slice::from_raw_parts(addr as *const u8, self.byte_len)) }
    }
}

impl<'a, State, Direction> IoBuffer<'a, State, Direction>
where
    State: VirtualBackedIoBufferState,
    Direction: WritableIoBufferDirection,
{
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_slice().as_mut_ptr()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.try_as_mut_slice()
            .expect("IoBuffer is not backed by exactly one writable virtual extent")
    }

    pub fn try_as_mut_slice(&mut self) -> Option<&mut [u8]> {
        let addr = self.try_virtual_address()?;
        unsafe { Some(slice::from_raw_parts_mut(addr as *mut u8, self.byte_len)) }
    }
}

impl<'a, Source, Direction> IoBuffer<'a, DmaMapped<Source>, Direction>
where
    Source: MappableIoBufferState,
    Direction: IoBufferDirection,
{
    pub fn mapped_by(&self) -> Option<Arc<DeviceObject>> {
        self.backing().mapped_by_for_lease(self.lease)
    }
}

impl<'a> IoBuffer<'a, Described, ToDevice> {
    pub fn from_slice(source: &'a [u8]) -> Self {
        Self::try_from_slice(source).expect("IoBufferBacking could not describe source")
    }

    pub fn try_from_slice(source: &'a [u8]) -> Result<Self, IoBufferError> {
        let backing = Arc::new(IoBufferBacking::try_from_slice(source)?);
        let lease = backing.reserve_lease_no_alloc(0, source.len(), LeaseAccess::Read)?;
        Ok(Self::new_owned(backing, lease, 0, source.len()))
    }

    pub fn from_segments(segments: &[&'a [u8]]) -> Result<Self, IoBufferError> {
        let backing = Arc::new(IoBufferBacking::try_from_segments(segments)?);
        let len = backing.len();
        let lease = backing.reserve_lease_no_alloc(0, len, LeaseAccess::Read)?;
        Ok(Self::new_owned(backing, lease, 0, len))
    }
}

impl<'a> IoBuffer<'a, Described, FromDevice> {
    pub fn from_slice_mut(destination: &'a mut [u8]) -> Self {
        Self::try_from_slice_mut(destination)
            .expect("IoBufferBacking could not describe destination")
    }

    pub fn try_from_slice_mut(destination: &'a mut [u8]) -> Result<Self, IoBufferError> {
        let len = destination.len();
        let backing = Arc::new(IoBufferBacking::try_from_slice_mut(destination)?);
        let lease = backing.reserve_lease_no_alloc(0, len, LeaseAccess::Write)?;
        Ok(Self::new_owned(backing, lease, 0, len))
    }

    pub fn from_segments_mut(segments: Vec<&'a mut [u8]>) -> Result<Self, IoBufferError> {
        let backing = Arc::new(IoBufferBacking::try_from_segments_mut(segments)?);
        let len = backing.len();
        let lease = backing.reserve_lease_no_alloc(0, len, LeaseAccess::Write)?;
        Ok(Self::new_owned(backing, lease, 0, len))
    }
}

impl<'a> IoBuffer<'a, Described, Bidirectional> {
    pub fn from_slice_mut(memory: &'a mut [u8]) -> Self {
        Self::try_from_slice_mut(memory).expect("IoBufferBacking could not describe memory")
    }

    pub fn try_from_slice_mut(memory: &'a mut [u8]) -> Result<Self, IoBufferError> {
        let len = memory.len();
        let backing = Arc::new(IoBufferBacking::try_from_slice_mut(memory)?);
        let lease = backing.reserve_lease_no_alloc(0, len, LeaseAccess::ReadWrite)?;
        Ok(Self::new_owned(backing, lease, 0, len))
    }

    pub fn from_segments_mut(segments: Vec<&'a mut [u8]>) -> Result<Self, IoBufferError> {
        let backing = Arc::new(IoBufferBacking::try_from_segments_mut(segments)?);
        let len = backing.len();
        let lease = backing.reserve_lease_no_alloc(0, len, LeaseAccess::ReadWrite)?;
        Ok(Self::new_owned(backing, lease, 0, len))
    }
}

impl<'a, Direction> IoBuffer<'a, PhysFramed, Direction>
where
    Direction: IoBufferDirection + DirectionAccess,
{
    pub fn from_frames(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
    ) -> Result<Self, IoBufferError> {
        let backing = Arc::new(IoBufferBacking::try_from_frames(
            frame_offset,
            byte_len,
            frames,
        )?);
        let lease = backing.reserve_lease_no_alloc(0, byte_len, Direction::ACCESS)?;
        Ok(Self::new_owned(backing, lease, 0, byte_len))
    }

    pub fn from_physical_extents(
        frames: &[IoBufferPageFrame],
        extents: &[IoBufferExtent],
    ) -> Result<Self, IoBufferError> {
        let backing = Arc::new(IoBufferBacking::try_from_physical_extents(frames, extents)?);
        let len = backing.len();
        let lease = backing.reserve_lease_no_alloc(0, len, Direction::ACCESS)?;
        Ok(Self::new_owned(backing, lease, 0, len))
    }
}

impl<'a, Direction> IoBuffer<'a, Described, Direction>
where
    Direction: IoBufferDirection + DirectionAccess,
{
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

impl<'a, Direction> core::convert::AsRef<IoBuffer<'a, PhysFramed, Direction>>
    for IoBuffer<'a, Described, Direction>
where
    Direction: IoBufferDirection + DirectionAccess,
{
    fn as_ref(&self) -> &IoBuffer<'a, PhysFramed, Direction> {
        self.as_phys_framed()
    }
}

impl<'a, Direction> core::convert::AsMut<IoBuffer<'a, PhysFramed, Direction>>
    for IoBuffer<'a, Described, Direction>
where
    Direction: IoBufferDirection + DirectionAccess,
{
    fn as_mut(&mut self) -> &mut IoBuffer<'a, PhysFramed, Direction> {
        self.as_phys_framed_mut()
    }
}

impl<'a, Direction> From<IoBuffer<'a, Described, Direction>> for IoBuffer<'a, PhysFramed, Direction>
where
    Direction: IoBufferDirection + DirectionAccess,
{
    fn from(buffer: IoBuffer<'a, Described, Direction>) -> Self {
        buffer.into_phys_framed()
    }
}

impl<'a, State> IoBuffer<'a, State, FromDevice>
where
    State: IoBufferState,
{
    pub fn into_to_device(self) -> IoBuffer<'a, State, ToDevice> {
        self.cast_direction()
    }
}

impl<'a, State> IoBuffer<'a, State, Bidirectional>
where
    State: IoBufferState,
{
    pub fn into_to_device(self) -> IoBuffer<'a, State, ToDevice> {
        self.cast_direction()
    }

    pub fn into_from_device(self) -> IoBuffer<'a, State, FromDevice> {
        self.cast_direction()
    }
}

impl<'a, State, Direction> Drop for IoBuffer<'a, State, Direction>
where
    State: IoBufferState,
    Direction: IoBufferDirection,
{
    fn drop(&mut self) {
        self.backing().release_lease(self.lease);
    }
}

impl<'a, S, D> IoBuffer<'a, S, D>
where
    S: MappableIoBufferState,
    D: IoBufferDirection,
{
    pub fn apply_dma_mapping(
        self,
        layout: IoBufferDmaMappingLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<IoBuffer<'a, DmaMapped<S>, D>, (Self, IoBufferError)> {
        if let Err(err) = validate_dma_mapping_layout(&layout) {
            return Err((self, err));
        }

        let this = ManuallyDrop::new(self);
        let backing = unsafe { ptr::read(&this.backing) };
        let layout = DmaSegmentLayout::from(layout);
        let result = backing
            .as_ref()
            .attach_dma_record(this.lease, layout, mapped_by, unmap, cookie);

        match result {
            Ok(()) => Ok(IoBuffer {
                backing,
                lease: this.lease,
                offset: this.offset,
                byte_len: this.byte_len,
                _state: PhantomData,
                _direction: PhantomData,
            }),
            Err(err) => Err((
                IoBuffer {
                    backing,
                    lease: this.lease,
                    offset: this.offset,
                    byte_len: this.byte_len,
                    _state: PhantomData,
                    _direction: PhantomData,
                },
                err,
            )),
        }
    }

    pub fn apply_dma_mapping_segments(
        self,
        segments: &[IoBufferDmaSegment],
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<IoBuffer<'a, DmaMapped<S>, D>, (Self, IoBufferError)> {
        if segments.len() > IOBUFFER_INLINE_SEGMENT_CAPACITY {
            return Err((
                self,
                IoBufferError::SegmentCapacityExceeded {
                    required: segments.len(),
                    capacity: IOBUFFER_INLINE_SEGMENT_CAPACITY,
                },
            ));
        }

        let this = ManuallyDrop::new(self);
        let backing = unsafe { ptr::read(&this.backing) };
        let layout = DmaSegmentLayout::Stored(StoredDmaSegments::from_slice(segments));
        let result = backing
            .as_ref()
            .attach_dma_record(this.lease, layout, mapped_by, unmap, cookie);

        match result {
            Ok(()) => Ok(IoBuffer {
                backing,
                lease: this.lease,
                offset: this.offset,
                byte_len: this.byte_len,
                _state: PhantomData,
                _direction: PhantomData,
            }),
            Err(err) => Err((
                IoBuffer {
                    backing,
                    lease: this.lease,
                    offset: this.offset,
                    byte_len: this.byte_len,
                    _state: PhantomData,
                    _direction: PhantomData,
                },
                err,
            )),
        }
    }
}

impl<'a, S, D> IoBuffer<'a, DmaMapped<S>, D>
where
    S: MappableIoBufferState,
    D: IoBufferDirection,
{
    pub fn remove_dma_mapping(self) -> IoBuffer<'a, S, D> {
        let (backing, lease, offset, byte_len) = self.into_parts();
        backing.as_ref().detach_dma_record(lease);
        IoBuffer {
            backing,
            lease,
            offset,
            byte_len,
            _state: PhantomData,
            _direction: PhantomData,
        }
    }
}

impl<'a, State, Direction> fmt::Debug for IoBuffer<'a, State, Direction>
where
    State: IoBufferState,
    Direction: IoBufferDirection,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoBuffer")
            .field("state", &core::any::type_name::<State>())
            .field("direction", &core::any::type_name::<Direction>())
            .field("offset", &self.offset)
            .field("len", &self.byte_len)
            .field("extent_count", &self.extent_count())
            .field("page_frames_len", &self.page_count())
            .field("dma_segments_len", &self.dma_segments().len())
            .finish()
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
