use super::*;

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
pub const DMA_IOMMU_VENDOR_ARM_SMMU: u8 = 3;

pub const DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE: u32 = 1 << 0;
pub const DMA_PCI_IDENTITY_FLAG_BUS_MASTER_ENABLED: u32 = 1 << 1;

pub const IOBUFFER_INLINE_SEGMENT_CAPACITY: usize = 32;
pub const IOBUFFER_DEFAULT_LEASE_CAPACITY: usize = 32;
pub const IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY: usize = 8;
pub const IOBUFFER_DEFAULT_OVERLAP_GRANULARITY: usize = 128;

pub const fn iobuffer_worst_case_lease_count(byte_len: usize, granularity: usize) -> usize {
    if byte_len == 0 || granularity == 0 {
        0
    } else {
        let chunks = ((byte_len - 1) / granularity) + 1;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalFrameExtent {
    pub(super) phys_addr: u64,
    pub(super) byte_len: u64,
    pub(super) cpu_addr: VirtAddr,
}

impl PhysicalFrameExtent {
    /// # Safety
    /// `cpu_addr`, when nonzero, must map this physical frame for at least
    /// `byte_len` bytes and remain valid while the descriptor is in use.
    pub const unsafe fn new(phys_addr: u64, byte_len: u64, cpu_addr: VirtAddr) -> Self {
        Self {
            phys_addr,
            byte_len,
            cpu_addr,
        }
    }

    pub fn cpu_address(&self) -> VirtAddr {
        self.cpu_addr
    }

    pub const fn physical_address(&self) -> u64 {
        self.phys_addr
    }

    pub const fn len(&self) -> u64 {
        self.byte_len
    }

    pub const fn is_empty(&self) -> bool {
        self.byte_len == 0
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoBufferExtent {
    pub(super) virtual_addr: Option<usize>,
    pub(super) frame_offset: usize,
    pub(super) byte_len: usize,
    pub(super) first_frame: usize,
    pub(super) frame_count: usize,
}

impl IoBufferExtent {
    /// # Safety
    /// The virtual address, frame range, and offsets must describe the same
    /// live backing memory without creating overlapping mutable extents.
    pub const unsafe fn new(
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
    InvalidOverlapGranularity,
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
    pub overlap_granularity: usize,
}

impl Default for IoBufferBackingConfig {
    fn default() -> Self {
        Self {
            lease_capacity: IOBUFFER_DEFAULT_LEASE_CAPACITY,
            dma_record_capacity: IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY,
            overlap_granularity: IOBUFFER_DEFAULT_OVERLAP_GRANULARITY,
        }
    }
}

impl IoBufferBackingConfig {
    pub const fn worst_case_for_len(byte_len: usize) -> Self {
        Self {
            lease_capacity: iobuffer_worst_case_lease_count(
                byte_len,
                IOBUFFER_DEFAULT_OVERLAP_GRANULARITY,
            ),
            dma_record_capacity: IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY,
            overlap_granularity: IOBUFFER_DEFAULT_OVERLAP_GRANULARITY,
        }
    }

    pub const fn worst_case_for_len_with_granularity(byte_len: usize, granularity: usize) -> Self {
        Self {
            lease_capacity: iobuffer_worst_case_lease_count(byte_len, granularity),
            dma_record_capacity: IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY,
            overlap_granularity: granularity,
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
        frames: &'data [PhysicalFrameExtent],
    },
    PhysicalExtents {
        frames: &'data [PhysicalFrameExtent],
        extents: &'data [IoBufferExtent],
    },
}

pub type DmaUnmapFn = extern "C" fn(&Arc<DeviceObject>, usize);

pub(super) struct DmaDropContext {
    pub(super) mapped_by: Arc<DeviceObject>,
    pub(super) unmap: DmaUnmapFn,
    pub(super) cookie: usize,
}

impl DmaDropContext {
    pub(super) fn run(self) {
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

const DMA_RECORD_FREE: usize = 0;
const DMA_RECORD_INITIALIZING: usize = 1;
const DMA_RECORD_RECLAIMING: usize = 2;
const DMA_RECORD_ACTIVE: usize = 3;
const DMA_RECORD_STATE_MASK: usize = 3;
const DMA_RECORD_PERSISTENT: usize = 4;
const DMA_RECORD_REF_SHIFT: u32 = 3;
const DMA_RECORD_REF_ONE: usize = 1 << DMA_RECORD_REF_SHIFT;

pub(super) struct DmaRecordPayload {
    pub(super) mapped_start: usize,
    pub(super) mapped_len: usize,
    pub(super) access: u8,
    pub(super) layout: IoBufferDmaMappingLayout,
    pub(super) drop_ctx: DmaDropContext,
}

pub(super) struct DmaRecord {
    control: AtomicUsize,
    payload: UnsafeCell<MaybeUninit<DmaRecordPayload>>,
}

impl DmaRecord {
    pub(super) fn empty() -> Self {
        Self {
            control: AtomicUsize::new(DMA_RECORD_FREE),
            payload: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub(super) fn is_active(&self) -> bool {
        self.control.load(Ordering::Acquire) & DMA_RECORD_STATE_MASK == DMA_RECORD_ACTIVE
    }

    pub(super) fn try_initialize(
        &self,
        persistent: bool,
        payload: DmaRecordPayload,
    ) -> Result<(), DmaRecordPayload> {
        if self
            .control
            .compare_exchange(
                DMA_RECORD_FREE,
                DMA_RECORD_INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(payload);
        }

        unsafe { (*self.payload.get()).write(payload) };
        let persistent = if persistent { DMA_RECORD_PERSISTENT } else { 0 };
        self.control.store(
            DMA_RECORD_ACTIVE | persistent | DMA_RECORD_REF_ONE,
            Ordering::Release,
        );
        Ok(())
    }

    pub(super) fn try_retain(&self) -> Result<bool, IoBufferError> {
        let mut control = self.control.load(Ordering::Acquire);
        loop {
            if control & DMA_RECORD_STATE_MASK != DMA_RECORD_ACTIVE {
                return Ok(false);
            }
            let Some(next) = control.checked_add(DMA_RECORD_REF_ONE) else {
                return Err(IoBufferError::LengthOverflow);
            };
            match self.control.compare_exchange_weak(
                control,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(true),
                Err(actual) => control = actual,
            }
        }
    }

    pub(super) fn try_retain_persistent(&self) -> Result<bool, IoBufferError> {
        let mut control = self.control.load(Ordering::Acquire);
        loop {
            if control & DMA_RECORD_STATE_MASK != DMA_RECORD_ACTIVE
                || control & DMA_RECORD_PERSISTENT == 0
            {
                return Ok(false);
            }
            let Some(next) = control.checked_add(DMA_RECORD_REF_ONE) else {
                return Err(IoBufferError::LengthOverflow);
            };
            match self.control.compare_exchange_weak(
                control,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(true),
                Err(actual) => control = actual,
            }
        }
    }

    pub(super) unsafe fn payload(&self) -> &DmaRecordPayload {
        unsafe { (&*self.payload.get()).assume_init_ref() }
    }

    pub(super) fn release(&self) -> Option<DmaDropContext> {
        let mut control = self.control.load(Ordering::Acquire);
        loop {
            if control & DMA_RECORD_STATE_MASK != DMA_RECORD_ACTIVE {
                return None;
            }
            let refs = control >> DMA_RECORD_REF_SHIFT;
            if refs > 1 {
                match self.control.compare_exchange_weak(
                    control,
                    control - DMA_RECORD_REF_ONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return None,
                    Err(actual) => control = actual,
                }
                continue;
            }
            if refs != 1 {
                return None;
            }
            match self.control.compare_exchange_weak(
                control,
                DMA_RECORD_RECLAIMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let payload = unsafe { (&mut *self.payload.get()).assume_init_read() };
                    self.control.store(DMA_RECORD_FREE, Ordering::Release);
                    return Some(payload.drop_ctx);
                }
                Err(actual) => control = actual,
            }
        }
    }

    pub(super) fn take_exclusive(&mut self) -> Option<DmaDropContext> {
        if *self.control.get_mut() & DMA_RECORD_STATE_MASK != DMA_RECORD_ACTIVE {
            return None;
        }
        *self.control.get_mut() = DMA_RECORD_FREE;
        let payload = unsafe { self.payload.get_mut().assume_init_read() };
        Some(payload.drop_ctx)
    }
}

unsafe impl Sync for DmaRecord {}

#[repr(C)]
#[derive(Clone)]
pub struct DmaMappedBuffer {
    pub layout: IoBufferDmaMappingLayout,
    pub mapped_by: Arc<DeviceObject>,
    pub unmap: DmaUnmapFn,
    pub cookie: usize,
}
