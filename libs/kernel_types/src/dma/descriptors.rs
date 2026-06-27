pub enum ToDevice {}
pub enum FromDevice {}
pub enum Bidirectional {}

mod sealed {
    pub trait IoBufferAccess {}
    pub trait WritableAccess {}
}

pub trait IoBufferAccess: sealed::IoBufferAccess {}
impl<T: sealed::IoBufferAccess> IoBufferAccess for T {}

pub trait WritableIoBufferAccess: IoBufferAccess + sealed::WritableAccess {}
impl<T: IoBufferAccess + sealed::WritableAccess> WritableIoBufferAccess for T {}

impl sealed::IoBufferAccess for ToDevice {}
impl sealed::IoBufferAccess for FromDevice {}
impl sealed::IoBufferAccess for Bidirectional {}

impl sealed::WritableAccess for FromDevice {}
impl sealed::WritableAccess for Bidirectional {}

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
    PhysicalDescriptionMissing,
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

pub type DmaUnmapFn = extern "C" fn(&Arc<DeviceObject>, usize);

struct DmaDropContext {
    mapped_by: Arc<DeviceObject>,
    unmap: DmaUnmapFn,
    cookie: usize,
}

impl DmaDropContext {
    fn run(self) {
        (self.unmap)(&self.mapped_by, self.cookie);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoBufferDmaMappingLayout {
    None,
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
    IdentityExtents,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DmaSegmentLayout {
    None,
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
    IdentityExtents,
}

impl From<IoBufferDmaMappingLayout> for DmaSegmentLayout {
    fn from(layout: IoBufferDmaMappingLayout) -> Self {
        match layout {
            IoBufferDmaMappingLayout::None => Self::None,
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
            IoBufferDmaMappingLayout::IdentityExtents => Self::IdentityExtents,
        }
    }
}

struct DmaRecord {
    active: bool,
    persistent: bool,
    ref_count: usize,
    mapped_start: usize,
    mapped_len: usize,
    access: u8,
    layout: DmaSegmentLayout,
    drop_ctx: Option<DmaDropContext>,
}

impl DmaRecord {
    fn empty() -> Self {
        Self {
            active: false,
            persistent: false,
            ref_count: 0,
            mapped_start: 0,
            mapped_len: 0,
            access: 0,
            layout: DmaSegmentLayout::None,
            drop_ctx: None,
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct DmaMappedBuffer {
    pub layout: IoBufferDmaMappingLayout,
    pub mapped_by: Arc<DeviceObject>,
    pub unmap: DmaUnmapFn,
    pub cookie: usize,
}
