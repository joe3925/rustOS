use alloc::vec::Vec;

use crate::arch::VirtAddr;

pub const IOBUFFER_INLINE_SEGMENT_CAPACITY: usize = 32;
pub const IOBUFFER_DEFAULT_LEASE_CAPACITY: usize = 32;
pub const IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY: usize = 8;
pub const IOBUFFER_WORST_CASE_LEASE_GRANULARITY: usize = 4096;

pub const fn iobuffer_worst_case_lease_count(byte_len: usize) -> usize {
    if byte_len == 0 {
        0
    } else {
        let chunks = ((byte_len - 1) / IOBUFFER_WORST_CASE_LEASE_GRANULARITY) + 1;
        // A consumer that owns a buffer must be able to retain a remainder
        // while forwarding a split prefix.
        if chunks < 2 { 2 } else { chunks }
    }
}

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
    pub cpu_addr: VirtAddr,
}

impl IoBufferPageFrame {
    pub const fn new(phys_addr: u64, byte_len: u64, cpu_addr: VirtAddr) -> Self {
        Self {
            phys_addr,
            byte_len,
            cpu_addr,
        }
    }

    pub fn cpu_address(&self) -> VirtAddr {
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
    AllocationFailed,
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
    ActiveLeases,
    InvalidLease,
    InvalidBackingKind,
    InvalidRange,
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
    DmaMappingNotFound,
    DmaMappingAccessDenied,
    DmaMappingRangeNotCovered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoBufferBackingConfig {
    pub lease_capacity: usize,
    pub dma_record_capacity: usize,
}

impl Default for IoBufferBackingConfig {
    fn default() -> Self {
        Self {
            lease_capacity: IOBUFFER_DEFAULT_LEASE_CAPACITY,
            dma_record_capacity: IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY,
        }
    }
}

impl IoBufferBackingConfig {
    pub const fn worst_case_for_len(byte_len: usize) -> Self {
        Self {
            lease_capacity: iobuffer_worst_case_lease_count(byte_len),
            dma_record_capacity: IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY,
        }
    }
}

pub enum IoBufferBackingDesc<'data> {
    Slice(&'data [u8]),
    SliceMut(&'data mut [u8]),
    Segments(&'data [&'data [u8]]),
    SegmentsMut(Vec<&'data mut [u8]>),
    Frames {
        frame_offset: usize,
        byte_len: usize,
        frames: &'data [IoBufferPageFrame],
    },
    PhysicalExtents {
        frames: &'data [IoBufferPageFrame],
        extents: &'data [IoBufferExtent],
    },
}
