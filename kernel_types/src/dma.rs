use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
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
pub const IOBUFFER_INLINE_PAGE_CAPACITY: usize = 8;
pub const IOBUFFER_MAX_PAGE_CAPACITY: usize = 512;
pub const IOBUFFER_INLINE_FRAME_CAPACITY: usize = IOBUFFER_INLINE_PAGE_CAPACITY;
pub const IOBUFFER_MAX_FRAME_CAPACITY: usize = IOBUFFER_MAX_PAGE_CAPACITY;
pub const IOBUFFER_INLINE_SEGMENT_CAPACITY: usize = 32;

/// Region described from a virtual borrow.
///
/// A `Described` buffer has both virtual backing and physical frame backing.
pub enum Described {}

/// Region described directly from physical frames.
///
/// A `PhysFramed` buffer has physical frame backing, but no required virtual
/// backing. This can represent a region that is not mapped in this address
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
    /// Buffer spans more frames than frame storage can describe
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
    /// Base virtual address for this physical frame, if it has virtual backing
    /// in the current address space.
    pub virt_addr: Option<usize>,
}

impl IoBufferPageFrame {
    pub const fn new(phys_addr: u64, byte_len: u64) -> Self {
        Self {
            phys_addr,
            byte_len,
            virt_addr: None,
        }
    }

    pub const fn with_virtual(phys_addr: u64, byte_len: u64, virt_addr: usize) -> Self {
        Self {
            phys_addr,
            byte_len,
            virt_addr: Some(virt_addr),
        }
    }

    pub fn virtual_address(&self) -> Option<usize> {
        self.virt_addr
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoBufferDmaSegment {
    pub dma_addr: u64,
    pub byte_len: u32,
    pub reserved: u32,
}

const IOBUFFER_INLINE_STORED_SEGMENT_CAPACITY: usize = 4;

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

const EMPTY_PAGE_FRAME: IoBufferPageFrame = IoBufferPageFrame::new(0, 0);
const EMPTY_DMA_SEGMENT: IoBufferDmaSegment = IoBufferDmaSegment {
    dma_addr: 0,
    byte_len: 0,
    reserved: 0,
};

#[derive(Clone, Copy, Debug)]
enum DmaSegmentLayout {
    None,
    Inline {
        segments: [IoBufferDmaSegment; IOBUFFER_INLINE_STORED_SEGMENT_CAPACITY],
        len: usize,
    },
    Contiguous {
        segment: IoBufferDmaSegment,
    },
    PageChunks {
        iova_base: u64,
        page_offset: usize,
        byte_len: usize,
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
}

impl DmaSegmentLayout {
    const fn empty() -> Self {
        Self::None
    }
}

pub type DmaUnmapFn = extern "win64" fn(&Arc<DeviceObject>, usize);

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
) -> Result<(PageFrameStorage, usize, usize), IoBufferError> {
    let mut inline_frames = [EMPTY_PAGE_FRAME; IOBUFFER_INLINE_PAGE_CAPACITY];
    let mut heap_frames: Option<Vec<IoBufferPageFrame>> = None;

    if byte_len == 0 {
        return Ok((PageFrameStorage::empty(), 0, 0));
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

        if frame_count >= IOBUFFER_MAX_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: frame_count + 1,
                capacity: IOBUFFER_MAX_PAGE_CAPACITY,
            });
        }

        if frame_count == 0 {
            first_frame_offset = translated.offset as usize;
        }

        let frame = IoBufferPageFrame::with_virtual(
            translated.phys_addr,
            translated.byte_len,
            current - translated.offset as usize,
        );

        if let Some(frames) = heap_frames.as_mut() {
            frames.push(frame);
        } else if frame_count < IOBUFFER_INLINE_PAGE_CAPACITY {
            inline_frames[frame_count] = frame;
        } else {
            let mut frames = Vec::with_capacity(
                (IOBUFFER_INLINE_PAGE_CAPACITY * 2).min(IOBUFFER_MAX_PAGE_CAPACITY),
            );
            frames.extend_from_slice(&inline_frames);
            frames.push(frame);
            heap_frames = Some(frames);
        }

        frame_count += 1;

        let bytes_in_frame = (translated.byte_len - translated.offset) as usize;
        consumed += (byte_len - consumed).min(bytes_in_frame);
    }

    let storage = match heap_frames {
        Some(frames) => PageFrameStorage::from_boxed(frames.into_boxed_slice()),
        None => PageFrameStorage::from_inline(inline_frames),
    };

    Ok((storage, frame_count, first_frame_offset))
}

fn validate_physical_frames(
    frame_offset: usize,
    byte_len: usize,
    frames: &[IoBufferPageFrame],
) -> Result<(), IoBufferError> {
    if frames.len() > IOBUFFER_MAX_PAGE_CAPACITY {
        return Err(IoBufferError::PageCapacityExceeded {
            required: frames.len(),
            capacity: IOBUFFER_MAX_PAGE_CAPACITY,
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

/// A run of `IoBufferPageFrame`s with one virtual-backing shape.
///
/// A mapped run stays in the same region only while every next frame's virtual
/// base is exactly the previous frame's virtual base plus its byte length.
/// Consecutive unmapped frames are grouped into one physical-only region.
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
    page_frames: &'a [IoBufferPageFrame],
    next_frame: usize,
    frame_offset: usize,
    remaining: usize,
}

impl<'a> IoBufferRegionIter<'a> {
    fn new(page_frames: &'a [IoBufferPageFrame], frame_offset: usize, byte_len: usize) -> Self {
        Self {
            page_frames,
            next_frame: 0,
            frame_offset,
            remaining: byte_len,
        }
    }
}

impl<'a> Iterator for IoBufferRegionIter<'a> {
    type Item = IoBufferRegion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.next_frame >= self.page_frames.len() {
            return None;
        }

        let start_frame = self.next_frame;
        let start_offset = self.frame_offset;
        let first_frame = self.page_frames[start_frame];
        let first_frame_len = first_frame.byte_len as usize;
        if start_offset >= first_frame_len {
            self.remaining = 0;
            return None;
        }

        let virtual_addr = first_frame
            .virtual_address()
            .and_then(|addr| addr.checked_add(start_offset));
        let mut byte_len = 0usize;
        let mut current_frame = start_frame;
        let mut current_offset = start_offset;

        loop {
            let frame = self.page_frames[current_frame];
            let frame_len = frame.byte_len as usize;
            if current_offset >= frame_len {
                self.remaining = 0;
                return None;
            }

            let frame_bytes = (frame_len - current_offset).min(self.remaining);
            byte_len += frame_bytes;
            self.remaining -= frame_bytes;
            current_frame += 1;

            if self.remaining == 0 || current_frame >= self.page_frames.len() {
                break;
            }

            let next_frame = self.page_frames[current_frame];
            let same_region = match (frame.virtual_address(), next_frame.virtual_address()) {
                (Some(current), Some(next)) => current
                    .checked_add(frame_len)
                    .map_or(false, |expected| expected == next),
                (None, None) => true,
                _ => false,
            };

            if !same_region {
                break;
            }

            current_offset = 0;
        }

        self.next_frame = current_frame;
        self.frame_offset = 0;

        Some(IoBufferRegion {
            virtual_addr,
            frame_offset: start_offset,
            byte_len,
            page_frames: &self.page_frames[start_frame..current_frame],
        })
    }
}

pub struct IoBufferDmaSegments<'a> {
    layout: DmaSegmentLayout,
    page_frames: &'a [IoBufferPageFrame],
}

impl<'a> IoBufferDmaSegments<'a> {
    fn new(layout: DmaSegmentLayout, page_frames: &'a [IoBufferPageFrame]) -> Self {
        Self {
            layout,
            page_frames,
        }
    }

    pub fn len(&self) -> usize {
        match self.layout {
            DmaSegmentLayout::None => 0,
            DmaSegmentLayout::Inline { len, .. } => len,
            DmaSegmentLayout::Contiguous { .. } => 1,
            DmaSegmentLayout::PageChunks {
                page_offset,
                byte_len,
                ..
            } => page_chunk_segment_count(page_offset, byte_len),
            DmaSegmentLayout::FixedChunks { count, .. } => count,
            DmaSegmentLayout::Identity {
                frame_offset,
                byte_len,
            } => identity_segment_count(self.page_frames, frame_offset, byte_len),
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
            page_frames: self.page_frames,
            index: 0,
            frame_index: 0,
            frame_offset: 0,
            remaining: 0,
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
    layout: DmaSegmentLayout,
    page_frames: &'a [IoBufferPageFrame],
    index: usize,
    frame_index: usize,
    frame_offset: usize,
    remaining: usize,
    initialized: bool,
}

impl<'a> Iterator for IoBufferDmaSegmentIter<'a> {
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        match self.layout {
            DmaSegmentLayout::None => None,
            DmaSegmentLayout::Inline { segments, len } => {
                if self.index >= len {
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
                Some(segment)
            }
            DmaSegmentLayout::PageChunks {
                iova_base,
                page_offset,
                byte_len,
            } => {
                if !self.initialized {
                    self.remaining = byte_len;
                    self.initialized = true;
                }
                if self.remaining == 0 {
                    return None;
                }

                let start_in_page = if self.index == 0 { page_offset } else { 0 };
                let bytes = self.remaining.min(IOBUFFER_PAGE_SIZE - start_in_page);
                let dma_addr =
                    iova_base + (self.index * IOBUFFER_PAGE_SIZE + start_in_page) as u64;
                self.remaining -= bytes;
                self.index += 1;
                Some(IoBufferDmaSegment {
                    dma_addr,
                    byte_len: bytes as u32,
                    reserved: 0,
                })
            }
            DmaSegmentLayout::FixedChunks {
                dma_addr,
                chunk_len,
                count,
            } => {
                if self.index >= count {
                    return None;
                }
                let segment = IoBufferDmaSegment {
                    dma_addr: dma_addr + (self.index as u64 * chunk_len as u64),
                    byte_len: chunk_len,
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
                    self.frame_offset = frame_offset;
                    self.remaining = byte_len;
                    self.initialized = true;
                }
                next_identity_segment(
                    self.page_frames,
                    &mut self.frame_index,
                    &mut self.frame_offset,
                    &mut self.remaining,
                )
            }
        }
    }
}

fn page_chunk_segment_count(page_offset: usize, byte_len: usize) -> usize {
    if byte_len == 0 {
        0
    } else {
        page_offset.saturating_add(byte_len).div_ceil(IOBUFFER_PAGE_SIZE)
    }
}

fn identity_segment_count(
    page_frames: &[IoBufferPageFrame],
    frame_offset: usize,
    byte_len: usize,
) -> usize {
    let mut frame_index = 0;
    let mut current_offset = frame_offset;
    let mut remaining = byte_len;
    let mut count = 0;
    while next_identity_segment(page_frames, &mut frame_index, &mut current_offset, &mut remaining)
        .is_some()
    {
        count += 1;
    }
    count
}

fn next_identity_segment(
    page_frames: &[IoBufferPageFrame],
    frame_index: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if *remaining == 0 {
        return None;
    }

    while *frame_index < page_frames.len()
        && *frame_offset >= page_frames[*frame_index].byte_len as usize
    {
        *frame_offset -= page_frames[*frame_index].byte_len as usize;
        *frame_index += 1;
    }

    if *frame_index >= page_frames.len() {
        return None;
    }

    let first = page_frames[*frame_index];
    let start_offset = *frame_offset;
    let dma_addr = first.phys_addr + start_offset as u64;
    let mut byte_len = (*remaining).min(first.byte_len as usize - start_offset);
    *remaining -= byte_len;
    *frame_index += 1;
    *frame_offset = 0;

    while *remaining > 0 && *frame_index < page_frames.len() {
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

    if byte_len > u32::MAX as usize {
        byte_len = u32::MAX as usize;
    }

    Some(IoBufferDmaSegment {
        dma_addr,
        byte_len: byte_len as u32,
        reserved: 0,
    })
}

struct PageFrameStorage {
    inline: [IoBufferPageFrame; IOBUFFER_INLINE_PAGE_CAPACITY],
    heap: Option<Box<[IoBufferPageFrame]>>,
}

impl PageFrameStorage {
    fn empty() -> Self {
        Self {
            inline: [EMPTY_PAGE_FRAME; IOBUFFER_INLINE_PAGE_CAPACITY],
            heap: None,
        }
    }

    fn from_inline(inline: [IoBufferPageFrame; IOBUFFER_INLINE_PAGE_CAPACITY]) -> Self {
        Self { inline, heap: None }
    }

    fn from_boxed(heap: Box<[IoBufferPageFrame]>) -> Self {
        Self {
            inline: [EMPTY_PAGE_FRAME; IOBUFFER_INLINE_PAGE_CAPACITY],
            heap: Some(heap),
        }
    }

    fn boxed_empty(capacity: usize) -> Box<[IoBufferPageFrame]> {
        let mut frames = Vec::with_capacity(capacity);
        frames.resize(capacity, EMPTY_PAGE_FRAME);
        frames.into_boxed_slice()
    }

    fn from_slice(frames: &[IoBufferPageFrame]) -> Result<Self, IoBufferError> {
        if frames.len() > IOBUFFER_MAX_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: frames.len(),
                capacity: IOBUFFER_MAX_PAGE_CAPACITY,
            });
        }

        let mut storage = Self::empty();
        storage.replace(frames)?;
        Ok(storage)
    }

    fn as_slice(&self, len: usize) -> &[IoBufferPageFrame] {
        match self.heap.as_ref() {
            Some(frames) => &frames[..len],
            None => &self.inline[..len],
        }
    }

    fn replace(&mut self, frames: &[IoBufferPageFrame]) -> Result<(), IoBufferError> {
        if frames.len() > IOBUFFER_MAX_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: frames.len(),
                capacity: IOBUFFER_MAX_PAGE_CAPACITY,
            });
        }

        self.inline.fill(EMPTY_PAGE_FRAME);
        if frames.len() <= IOBUFFER_INLINE_PAGE_CAPACITY {
            self.heap = None;
            self.inline[..frames.len()].copy_from_slice(frames);
        } else {
            let mut heap = Self::boxed_empty(frames.len());
            heap.copy_from_slice(frames);
            self.heap = Some(heap);
        }
        Ok(())
    }

    fn ensure_capacity(&mut self, capacity: usize) -> Result<(), IoBufferError> {
        if capacity > IOBUFFER_MAX_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: capacity,
                capacity: IOBUFFER_MAX_PAGE_CAPACITY,
            });
        }

        if capacity <= IOBUFFER_INLINE_PAGE_CAPACITY {
            return Ok(());
        }

        let needs_heap = self
            .heap
            .as_ref()
            .map(|frames| frames.len() < capacity)
            .unwrap_or(true);
        if needs_heap {
            let mut heap = Self::boxed_empty(capacity);
            heap[..IOBUFFER_INLINE_PAGE_CAPACITY].copy_from_slice(&self.inline);
            self.heap = Some(heap);
        }
        Ok(())
    }

    fn capacity_slice_mut(&mut self) -> &mut [IoBufferPageFrame] {
        match self.heap.as_mut() {
            Some(frames) => frames,
            None => &mut self.inline,
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
    page_frames: PageFrameStorage,
    page_frames_len: usize,
    dma_segments: DmaSegmentLayout,
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
        let (page_frames, page_frames_len, frame_offset) = describe_virtual_buffer(virt_addr, len)
            .expect("IoBuffer<Described> could not describe virtual backing");

        Self {
            borrow: Some(borrow),
            virt_addr,
            byte_len: len,
            frame_offset,
            page_frames,
            page_frames_len,
            dma_segments: DmaSegmentLayout::empty(),
            mapped_by: None,
            dma_drop: None,
        }
    }
    /// Creates a new `IoBuffer` from physical page frames.
    ///
    /// The frames are the required physical backing and should be in order
    /// from start to end of the buffer. Virtual backing is optional.
    fn new_physical(
        frame_offset: usize,
        byte_len: usize,
        frames: &[IoBufferPageFrame],
    ) -> Result<Self, IoBufferError> {
        validate_physical_frames(frame_offset, byte_len, frames)?;
        let page_frames = PageFrameStorage::from_slice(frames)?;

        Ok(Self {
            borrow: None,
            virt_addr: 0,
            byte_len,
            frame_offset,
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
        self.page_frames.as_slice(self.page_frames_len)
    }

    pub fn dma_segments(&self) -> IoBufferDmaSegments<'_> {
        IoBufferDmaSegments::new(self.dma_segments, self.page_frames())
    }

    pub fn iter(&self) -> IoBufferRegionIter<'_> {
        IoBufferRegionIter::new(self.page_frames(), self.frame_offset, self.byte_len)
    }

    pub fn replace_page_frames(
        &mut self,
        frames: &[IoBufferPageFrame],
    ) -> Result<(), IoBufferError> {
        self.page_frames.replace(frames)?;
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

        if segments.len() <= IOBUFFER_INLINE_STORED_SEGMENT_CAPACITY {
            let mut inline = [EMPTY_DMA_SEGMENT; IOBUFFER_INLINE_STORED_SEGMENT_CAPACITY];
            inline[..segments.len()].copy_from_slice(segments);
            self.dma_segments = DmaSegmentLayout::Inline {
                segments: inline,
                len: segments.len(),
            };
            return Ok(());
        }

        let first = segments[0];
        let is_contiguous = segments.windows(2).all(|pair| {
            pair[0].dma_addr + pair[0].byte_len as u64 == pair[1].dma_addr && pair[0].reserved == 0
        }) && segments[segments.len() - 1].reserved == 0;
        if is_contiguous {
            let total_len = segments.iter().try_fold(0usize, |total, segment| {
                total.checked_add(segment.byte_len as usize)
            });
            if let Some(total_len) = total_len {
                if total_len <= u32::MAX as usize {
                    self.dma_segments = DmaSegmentLayout::Contiguous {
                        segment: IoBufferDmaSegment {
                            dma_addr: first.dma_addr,
                            byte_len: total_len as u32,
                            reserved: 0,
                        },
                    };
                    return Ok(());
                }
            }
        }

        let is_fixed_chunks = first.byte_len != 0
            && segments.iter().enumerate().all(|(idx, segment)| {
                segment.byte_len == first.byte_len
                    && segment.dma_addr == first.dma_addr + (idx as u64 * first.byte_len as u64)
                    && segment.reserved == 0
            });
        if is_fixed_chunks {
            self.dma_segments = DmaSegmentLayout::FixedChunks {
                dma_addr: first.dma_addr,
                chunk_len: first.byte_len,
                count: segments.len(),
            };
            return Ok(());
        }

        Err(IoBufferError::SegmentCapacityExceeded {
            required: segments.len(),
            capacity: IOBUFFER_INLINE_STORED_SEGMENT_CAPACITY,
        })
    }

    pub fn set_dma_segments_contiguous(
        &mut self,
        dma_addr: u64,
        byte_len: usize,
    ) -> Result<(), IoBufferError> {
        if byte_len > u32::MAX as usize {
            return Err(IoBufferError::SegmentCapacityExceeded {
                required: byte_len,
                capacity: u32::MAX as usize,
            });
        }
        self.dma_segments = DmaSegmentLayout::Contiguous {
            segment: IoBufferDmaSegment {
                dma_addr,
                byte_len: byte_len as u32,
                reserved: 0,
            },
        };
        Ok(())
    }

    pub fn set_dma_segments_page_chunks(
        &mut self,
        iova_base: u64,
        page_offset: usize,
        byte_len: usize,
    ) -> Result<(), IoBufferError> {
        let count = page_chunk_segment_count(page_offset, byte_len);
        if count > IOBUFFER_INLINE_SEGMENT_CAPACITY {
            return Err(IoBufferError::SegmentCapacityExceeded {
                required: count,
                capacity: IOBUFFER_INLINE_SEGMENT_CAPACITY,
            });
        }
        self.dma_segments = DmaSegmentLayout::PageChunks {
            iova_base,
            page_offset,
            byte_len,
        };
        Ok(())
    }

    pub fn set_dma_segments_fixed_chunks(
        &mut self,
        dma_addr: u64,
        chunk_len: usize,
        count: usize,
    ) -> Result<(), IoBufferError> {
        if count > IOBUFFER_INLINE_SEGMENT_CAPACITY {
            return Err(IoBufferError::SegmentCapacityExceeded {
                required: count,
                capacity: IOBUFFER_INLINE_SEGMENT_CAPACITY,
            });
        }
        if chunk_len > u32::MAX as usize {
            return Err(IoBufferError::SegmentCapacityExceeded {
                required: chunk_len,
                capacity: u32::MAX as usize,
            });
        }
        self.dma_segments = DmaSegmentLayout::FixedChunks {
            dma_addr,
            chunk_len: chunk_len as u32,
            count,
        };
        Ok(())
    }

    pub fn set_dma_segments_identity(
        &mut self,
        frame_offset: usize,
        byte_len: usize,
    ) -> Result<(), IoBufferError> {
        let count = identity_segment_count(self.page_frames(), frame_offset, byte_len);
        if count > IOBUFFER_INLINE_SEGMENT_CAPACITY {
            return Err(IoBufferError::SegmentCapacityExceeded {
                required: count,
                capacity: IOBUFFER_INLINE_SEGMENT_CAPACITY,
            });
        }
        self.dma_segments = DmaSegmentLayout::Identity {
            frame_offset,
            byte_len,
        };
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

    pub fn page_frames_storage_mut(&mut self) -> &mut [IoBufferPageFrame] {
        self.page_frames
            .ensure_capacity(IOBUFFER_MAX_PAGE_CAPACITY)
            .expect("IoBuffer page frame storage could not grow to max capacity");
        self.page_frames.capacity_slice_mut()
    }

    pub fn set_page_frames_len(&mut self, len: usize) -> Result<(), IoBufferError> {
        if len > IOBUFFER_MAX_PAGE_CAPACITY {
            return Err(IoBufferError::PageCapacityExceeded {
                required: len,
                capacity: IOBUFFER_MAX_PAGE_CAPACITY,
            });
        }
        self.page_frames.ensure_capacity(len)?;
        self.page_frames_len = len;
        Ok(())
    }

    pub fn remove_dma_mapping_in_place(&mut self) {
        if let Some(ctx) = self.dma_drop.take() {
            (ctx.unmap)(&ctx.mapped_by, ctx.cookie);
        }
        self.mapped_by = None;
        self.dma_segments = DmaSegmentLayout::empty();
    }

    pub fn remove_virtual_backing_in_place(&mut self) {
        self.borrow = None;
        self.virt_addr = 0;
    }
}

impl<'inner, 'a> IntoIterator for &'inner IoBufferInner<'a> {
    type Item = IoBufferRegion<'inner>;
    type IntoIter = IoBufferRegionIter<'inner>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[repr(C)]
#[derive(RequestPayload)]
#[request_view(
    IoBuffer<'a, Described, Direction> => IoBuffer<'a, PhysFramed, Direction>
    where Direction: WritableIoBufferDirection
)]
#[request_view_mut(
    IoBuffer<'a, Described, Direction> => IoBuffer<'a, PhysFramed, Direction>
    where Direction: WritableIoBufferDirection
)]
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

    pub fn dma_segments(&self) -> IoBufferDmaSegments<'_> {
        self.inner.dma_segments()
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
    /// Reborrow this described buffer as a physical-frame-only view.
    ///
    /// `Described` already carries valid physical frame backing. This conversion
    /// only hides the virtual-backed API at the type level; it does not rebuild
    /// frame storage or remove the underlying virtual borrow.
    pub fn as_phys_framed(&self) -> &IoBuffer<'a, PhysFramed, Direction> {
        // SAFETY: `IoBuffer` stores its state marker only in zero-sized
        // `PhantomData` fields. `Described` satisfies the `PhysFramed`
        // invariant because described buffers always carry physical frames.
        unsafe { &*(self as *const Self as *const IoBuffer<'a, PhysFramed, Direction>) }
    }

    /// Mutably reborrow this described buffer as a physical-frame-only view.
    ///
    /// This is the mutable counterpart to [`Self::as_phys_framed`].
    pub fn as_phys_framed_mut(&mut self) -> &mut IoBuffer<'a, PhysFramed, Direction> {
        // SAFETY: same type-state-only cast as `as_phys_framed`, with the
        // caller's exclusive borrow preserving mutable aliasing rules.
        unsafe { &mut *(self as *mut Self as *mut IoBuffer<'a, PhysFramed, Direction>) }
    }

    /// Convert this described buffer into a physical-frame-only buffer.
    ///
    /// This is a zero-cost type-state conversion. The virtual backing remains
    /// owned by the buffer, but the returned type exposes only the APIs common
    /// to physical-frame-backed buffers.
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
            .field("virt_addr", &self.inner.virt_addr)
            .field("len", &self.inner.len())
            .field("has_virtual_backing", &self.inner.borrow.is_some())
            .field("frame_offset", &self.inner.frame_offset)
            .field("page_frames_len", &self.inner.page_frames_len)
            .field("dma_segments_len", &self.inner.dma_segments().len())
            .field("mapped", &self.inner.mapped_by.is_some())
            .finish()
    }
}
