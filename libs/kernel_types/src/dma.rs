use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::{max, min};
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

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

pub const IOBUFFER_INLINE_SEGMENT_CAPACITY: usize = 32;
pub const IOBUFFER_DEFAULT_LEASE_CAPACITY: usize = 32;
pub const IOBUFFER_DEFAULT_DMA_RECORD_CAPACITY: usize = 8;
pub const IOBUFFER_WORST_CASE_LEASE_GRANULARITY: usize = 4096;

const LEASE_FREE: u8 = 0;
const LEASE_ACTIVE: u8 = 1;
const LEASE_RELEASING: u8 = 2;
const ACCESS_TO_DEVICE: u8 = 1;
const ACCESS_FROM_DEVICE: u8 = 2;
const ACCESS_BIDIRECTIONAL: u8 = 3;
const STATE_DESCRIBED: u8 = 1;
const STATE_PHYS_FRAMED: u8 = 2;
const STATE_DMA_MAPPED: u8 = 3;
const NO_DMA_RECORD: usize = usize::MAX;

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
    pub trait IoBufferState {
        const KIND: u8;
    }
    pub trait IoBufferAccess {}
    pub trait WritableAccess {}
    pub trait MappableState {}
    pub trait VirtualBackedState {}
}

pub trait IoBufferState: sealed::IoBufferState {}
impl<T: sealed::IoBufferState> IoBufferState for T {}

pub trait IoBufferAccess: sealed::IoBufferAccess {}
impl<T: sealed::IoBufferAccess> IoBufferAccess for T {}

pub trait WritableIoBufferAccess: IoBufferAccess + sealed::WritableAccess {}
impl<T: IoBufferAccess + sealed::WritableAccess> WritableIoBufferAccess for T {}

pub trait MappableIoBufferState: IoBufferState + sealed::MappableState {}
impl<T: IoBufferState + sealed::MappableState> MappableIoBufferState for T {}

pub trait VirtualBackedIoBufferState: IoBufferState + sealed::VirtualBackedState {}
impl<T: IoBufferState + sealed::VirtualBackedState> VirtualBackedIoBufferState for T {}

impl sealed::IoBufferState for Described {
    const KIND: u8 = STATE_DESCRIBED;
}

impl sealed::IoBufferState for PhysFramed {
    const KIND: u8 = STATE_PHYS_FRAMED;
}

impl<S: sealed::IoBufferState> sealed::IoBufferState for DmaMapped<S> {
    const KIND: u8 = STATE_DMA_MAPPED;
}

impl sealed::MappableState for Described {}
impl sealed::MappableState for PhysFramed {}

impl sealed::VirtualBackedState for Described {}
impl<S: sealed::VirtualBackedState> sealed::VirtualBackedState for DmaMapped<S> {}

impl sealed::IoBufferAccess for ToDevice {}
impl sealed::IoBufferAccess for FromDevice {}
impl sealed::IoBufferAccess for Bidirectional {}

impl sealed::WritableAccess for FromDevice {}
impl sealed::WritableAccess for Bidirectional {}

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

#[derive(Clone, Copy)]
enum BackingMemory<'data> {
    None,
    SingleRead {
        ptr: *const u8,
        len: usize,
        _data: PhantomData<&'data [u8]>,
    },
    SingleWrite {
        ptr: *mut u8,
        len: usize,
        _data: PhantomData<&'data mut [u8]>,
    },
    SegmentedRead(PhantomData<&'data [u8]>),
    SegmentedWrite(PhantomData<&'data mut [u8]>),
}

struct BuiltBacking<'data> {
    memory: BackingMemory<'data>,
    byte_len: usize,
    extents: Vec<IoBufferExtent>,
    frames: Vec<IoBufferPageFrame>,
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
    ref_count: usize,
    mapped_start: usize,
    mapped_len: usize,
    layout: DmaSegmentLayout,
    drop_ctx: Option<DmaDropContext>,
}

impl DmaRecord {
    fn empty() -> Self {
        Self {
            active: false,
            ref_count: 0,
            mapped_start: 0,
            mapped_len: 0,
            layout: DmaSegmentLayout::None,
            drop_ctx: None,
        }
    }
}

struct LeaseSlot {
    state: AtomicU8,
    generation: AtomicU32,
    start: AtomicUsize,
    len: AtomicUsize,
    access: AtomicU8,
    desc_state: AtomicU8,
    dma_record: AtomicUsize,
}

impl LeaseSlot {
    fn free() -> Self {
        Self {
            state: AtomicU8::new(LEASE_FREE),
            generation: AtomicU32::new(1),
            start: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
            access: AtomicU8::new(0),
            desc_state: AtomicU8::new(0),
            dma_record: AtomicUsize::new(NO_DMA_RECORD),
        }
    }

    fn copy_from(slot: &Self) -> Self {
        Self {
            state: AtomicU8::new(slot.state.load(Ordering::Acquire)),
            generation: AtomicU32::new(slot.generation.load(Ordering::Acquire)),
            start: AtomicUsize::new(slot.start.load(Ordering::Acquire)),
            len: AtomicUsize::new(slot.len.load(Ordering::Acquire)),
            access: AtomicU8::new(slot.access.load(Ordering::Acquire)),
            desc_state: AtomicU8::new(slot.desc_state.load(Ordering::Acquire)),
            dma_record: AtomicUsize::new(slot.dma_record.load(Ordering::Acquire)),
        }
    }

    fn snapshot(&self) -> Option<LeaseSnapshot> {
        if self.state.load(Ordering::Acquire) != LEASE_ACTIVE {
            return None;
        }

        Some(LeaseSnapshot {
            generation: self.generation.load(Ordering::Acquire),
            start: self.start.load(Ordering::Acquire),
            len: self.len.load(Ordering::Acquire),
            access: self.access.load(Ordering::Acquire),
            desc_state: self.desc_state.load(Ordering::Acquire),
            dma_record: self.dma_record.load(Ordering::Acquire),
        })
    }

    fn activate(
        &self,
        start: usize,
        len: usize,
        access: u8,
        desc_state: u8,
        dma_record: usize,
    ) -> Result<u32, IoBufferError> {
        self.state
            .compare_exchange(
                LEASE_FREE,
                LEASE_RELEASING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| IoBufferError::InvalidLease)?;

        let generation = self.generation.load(Ordering::Relaxed);
        self.start.store(start, Ordering::Relaxed);
        self.len.store(len, Ordering::Relaxed);
        self.access.store(access, Ordering::Relaxed);
        self.desc_state.store(desc_state, Ordering::Relaxed);
        self.dma_record.store(dma_record, Ordering::Relaxed);
        self.state.store(LEASE_ACTIVE, Ordering::Release);
        Ok(generation)
    }

    fn release(&self, generation: u32) -> Option<usize> {
        let snapshot = self.snapshot()?;
        if snapshot.generation != generation {
            return None;
        }

        if self
            .state
            .compare_exchange(
                LEASE_ACTIVE,
                LEASE_RELEASING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }

        self.start.store(0, Ordering::Relaxed);
        self.len.store(0, Ordering::Relaxed);
        self.access.store(0, Ordering::Relaxed);
        self.desc_state.store(0, Ordering::Relaxed);
        let dma_record = self.dma_record.swap(NO_DMA_RECORD, Ordering::AcqRel);
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.state.store(LEASE_FREE, Ordering::Release);

        if dma_record == NO_DMA_RECORD {
            None
        } else {
            Some(dma_record)
        }
    }
}

#[derive(Clone, Copy)]
struct LeaseSnapshot {
    generation: u32,
    start: usize,
    len: usize,
    access: u8,
    desc_state: u8,
    dma_record: usize,
}

impl LeaseSnapshot {
    fn end(self) -> Option<usize> {
        self.start.checked_add(self.len)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LeaseHandle {
    index: usize,
    generation: u32,
}

pub struct IoBufferBacking<'data> {
    memory: BackingMemory<'data>,
    byte_len: usize,
    extents: Vec<IoBufferExtent>,
    frames: Vec<IoBufferPageFrame>,
    leases: RwLock<Box<[LeaseSlot]>>,
    lease_alloc_lock: Mutex<()>,
    dma_records: Mutex<Vec<DmaRecord>>,
}

impl<'data> IoBufferBacking<'data> {
    pub fn new(
        desc: IoBufferBackingDesc<'data>,
        config: IoBufferBackingConfig,
    ) -> Result<Self, IoBufferError> {
        let built = build_backing(desc)?;
        Ok(Self {
            memory: built.memory,
            byte_len: built.byte_len,
            extents: built.extents,
            frames: built.frames,
            leases: RwLock::new(make_lease_slots(config.lease_capacity)),
            lease_alloc_lock: Mutex::new(()),
            dma_records: Mutex::new(make_dma_records(config.dma_record_capacity)),
        })
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn lease_capacity(&self) -> usize {
        self.leases.read().len()
    }

    pub fn active_lease_count(&self) -> usize {
        self.leases
            .read()
            .iter()
            .filter(|slot| slot.state.load(Ordering::Acquire) == LEASE_ACTIVE)
            .count()
    }

    pub fn grow_lease_list(&self, count: usize) -> Result<(), IoBufferError> {
        let mut leases = self.leases.write();
        if leases.len() >= count {
            return Ok(());
        }

        let mut grown = Vec::with_capacity(count);
        for slot in leases.iter() {
            grown.push(LeaseSlot::copy_from(slot));
        }
        for _ in leases.len()..count {
            grown.push(LeaseSlot::free());
        }

        *leases = grown.into_boxed_slice();
        Ok(())
    }

    pub fn redescribe(&mut self, desc: IoBufferBackingDesc<'data>) -> Result<(), IoBufferError> {
        self.reject_active_leases()?;
        self.reject_active_dma_records()?;

        let built = build_backing(desc)?;
        self.memory = built.memory;
        self.byte_len = built.byte_len;

        self.extents.clear();
        self.extents.reserve(built.extents.len());
        self.extents.extend_from_slice(&built.extents);

        self.frames.clear();
        self.frames.reserve(built.frames.len());
        self.frames.extend_from_slice(&built.frames);

        self.clear_dma_records();
        Ok(())
    }

    pub fn redescribe_and_realloc(
        &mut self,
        desc: IoBufferBackingDesc<'data>,
    ) -> Result<(), IoBufferError> {
        self.reject_active_leases()?;
        self.reject_active_dma_records()?;

        let built = build_backing(desc)?;
        self.memory = built.memory;
        self.byte_len = built.byte_len;
        self.extents = built.extents;
        self.frames = built.frames;
        self.extents.shrink_to_fit();
        self.frames.shrink_to_fit();
        self.clear_dma_records();
        Ok(())
    }

    pub fn create_to_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'data, Described, ToDevice>, IoBufferError> {
        self.ensure_virtual_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_TO_DEVICE, STATE_DESCRIBED)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_from_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'data, Described, FromDevice>, IoBufferError> {
        self.ensure_writable_virtual_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_FROM_DEVICE, STATE_DESCRIBED)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_bidirectional<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'data, Described, Bidirectional>, IoBufferError> {
        self.ensure_writable_virtual_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_BIDIRECTIONAL, STATE_DESCRIBED)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_phys_to_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'data, PhysFramed, ToDevice>, IoBufferError> {
        self.ensure_phys_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_TO_DEVICE, STATE_PHYS_FRAMED)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_phys_from_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'data, PhysFramed, FromDevice>, IoBufferError> {
        self.ensure_phys_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_FROM_DEVICE, STATE_PHYS_FRAMED)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_phys_bidirectional<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'data, PhysFramed, Bidirectional>, IoBufferError> {
        self.ensure_phys_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_BIDIRECTIONAL, STATE_PHYS_FRAMED)?;
        Ok(IoBuffer::new(self, handle))
    }

    fn create_lease(
        &self,
        start: usize,
        len: usize,
        access: u8,
        desc_state: u8,
    ) -> Result<LeaseHandle, IoBufferError> {
        self.validate_range(start, len)?;
        let leases = self.leases.read();
        let _alloc_guard = self.lease_alloc_lock.lock();

        reject_conflicting_leases(&leases, start, len, access)?;

        for (index, slot) in leases.iter().enumerate() {
            if slot.state.load(Ordering::Acquire) != LEASE_FREE {
                continue;
            }

            let generation = slot.activate(start, len, access, desc_state, NO_DMA_RECORD)?;
            return Ok(LeaseHandle { index, generation });
        }

        Err(IoBufferError::LeaseCapacityExceeded {
            capacity: leases.len(),
        })
    }

    fn split_lease(&self, handle: LeaseHandle, mid: usize) -> Result<LeaseHandle, IoBufferError> {
        let leases = self.leases.read();
        let _alloc_guard = self.lease_alloc_lock.lock();
        let parent = leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        let snapshot = validate_snapshot(parent, handle)?;

        if mid > snapshot.len {
            return Err(IoBufferError::InvalidRange);
        }

        let right_start = snapshot
            .start
            .checked_add(mid)
            .ok_or(IoBufferError::LengthOverflow)?;
        let right_len = snapshot.len - mid;

        for (index, slot) in leases.iter().enumerate() {
            if slot.state.load(Ordering::Acquire) != LEASE_FREE {
                continue;
            }

            if snapshot.dma_record != NO_DMA_RECORD {
                self.retain_dma_record(snapshot.dma_record)?;
            }

            match slot.activate(
                right_start,
                right_len,
                snapshot.access,
                snapshot.desc_state,
                snapshot.dma_record,
            ) {
                Ok(generation) => {
                    parent.len.store(mid, Ordering::Release);
                    return Ok(LeaseHandle { index, generation });
                }
                Err(err) => {
                    if snapshot.dma_record != NO_DMA_RECORD {
                        self.release_dma_record(snapshot.dma_record);
                    }
                    return Err(err);
                }
            }
        }

        Err(IoBufferError::LeaseCapacityExceeded {
            capacity: leases.len(),
        })
    }

    fn release_lease(&self, handle: LeaseHandle) {
        let dma_record = {
            let leases = self.leases.read();
            leases
                .get(handle.index)
                .and_then(|slot| slot.release(handle.generation))
        };

        if let Some(record) = dma_record {
            self.release_dma_record(record);
        }
    }

    fn lease_snapshot(&self, handle: LeaseHandle) -> Result<LeaseSnapshot, IoBufferError> {
        let leases = self.leases.read();
        let slot = leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        validate_snapshot(slot, handle)
    }

    fn set_lease_state(
        &self,
        handle: LeaseHandle,
        expected: u8,
        new_state: u8,
    ) -> Result<(), IoBufferError> {
        let leases = self.leases.read();
        let slot = leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        let snapshot = validate_snapshot(slot, handle)?;

        if snapshot.desc_state != expected {
            return Err(IoBufferError::InvalidLease);
        }

        slot.desc_state.store(new_state, Ordering::Release);
        Ok(())
    }

    fn set_lease_dma_record(
        &self,
        handle: LeaseHandle,
        record: usize,
    ) -> Result<(), IoBufferError> {
        let leases = self.leases.read();
        let slot = leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        validate_snapshot(slot, handle)?;

        let old = slot.dma_record.swap(record, Ordering::AcqRel);
        if old != NO_DMA_RECORD {
            self.release_dma_record(old);
        }
        slot.desc_state.store(STATE_DMA_MAPPED, Ordering::Release);
        Ok(())
    }

    fn clear_lease_dma_record(
        &self,
        handle: LeaseHandle,
        new_state: u8,
    ) -> Result<(), IoBufferError> {
        let leases = self.leases.read();
        let slot = leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        validate_snapshot(slot, handle)?;

        let old = slot.dma_record.swap(NO_DMA_RECORD, Ordering::AcqRel);
        slot.desc_state.store(new_state, Ordering::Release);
        if old != NO_DMA_RECORD {
            self.release_dma_record(old);
        }
        Ok(())
    }

    fn allocate_dma_record(
        &self,
        mapped_start: usize,
        mapped_len: usize,
        layout: IoBufferDmaMappingLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<usize, IoBufferError> {
        validate_dma_mapping_layout(&layout)?;

        let mut records = self.dma_records.lock();
        for (index, record) in records.iter_mut().enumerate() {
            if record.active {
                continue;
            }

            record.active = true;
            record.ref_count = 1;
            record.mapped_start = mapped_start;
            record.mapped_len = mapped_len;
            record.layout = DmaSegmentLayout::from(layout);
            record.drop_ctx = Some(DmaDropContext {
                mapped_by,
                unmap,
                cookie,
            });
            return Ok(index);
        }

        Err(IoBufferError::DmaRecordCapacityExceeded {
            capacity: records.len(),
        })
    }

    fn retain_dma_record(&self, index: usize) -> Result<(), IoBufferError> {
        let mut records = self.dma_records.lock();
        let record = records.get_mut(index).ok_or(IoBufferError::InvalidLease)?;
        if !record.active {
            return Err(IoBufferError::InvalidLease);
        }
        record.ref_count = record
            .ref_count
            .checked_add(1)
            .ok_or(IoBufferError::LengthOverflow)?;
        Ok(())
    }

    fn release_dma_record(&self, index: usize) {
        let drop_ctx = {
            let mut records = self.dma_records.lock();
            let Some(record) = records.get_mut(index) else {
                return;
            };

            if !record.active || record.ref_count == 0 {
                return;
            }

            record.ref_count -= 1;
            if record.ref_count != 0 {
                return;
            }

            record.active = false;
            record.mapped_start = 0;
            record.mapped_len = 0;
            record.layout = DmaSegmentLayout::None;
            record.drop_ctx.take()
        };

        if let Some(ctx) = drop_ctx {
            ctx.run();
        }
    }

    fn dma_record_snapshot(
        &self,
        index: usize,
    ) -> Result<(usize, usize, DmaSegmentLayout), IoBufferError> {
        let records = self.dma_records.lock();
        let record = records.get(index).ok_or(IoBufferError::InvalidLease)?;
        if !record.active {
            return Err(IoBufferError::InvalidLease);
        }
        Ok((record.mapped_start, record.mapped_len, record.layout))
    }

    fn reject_active_leases(&self) -> Result<(), IoBufferError> {
        if self.active_lease_count() == 0 {
            Ok(())
        } else {
            Err(IoBufferError::ActiveLeases)
        }
    }

    fn reject_active_dma_records(&self) -> Result<(), IoBufferError> {
        if self.dma_records.lock().iter().any(|record| record.active) {
            Err(IoBufferError::ActiveLeases)
        } else {
            Ok(())
        }
    }

    fn clear_dma_records(&self) {
        for record in self.dma_records.lock().iter_mut() {
            *record = DmaRecord::empty();
        }
    }

    fn ensure_virtual_backed(&self) -> Result<(), IoBufferError> {
        match self.memory {
            BackingMemory::None => Err(IoBufferError::InvalidBackingKind),
            _ => Ok(()),
        }
    }

    fn ensure_writable_virtual_backed(&self) -> Result<(), IoBufferError> {
        match self.memory {
            BackingMemory::SingleWrite { .. } | BackingMemory::SegmentedWrite(_) => Ok(()),
            _ => Err(IoBufferError::InvalidBackingKind),
        }
    }

    fn ensure_phys_backed(&self) -> Result<(), IoBufferError> {
        if self.frames.is_empty() && self.byte_len != 0 {
            Err(IoBufferError::InvalidBackingKind)
        } else {
            Ok(())
        }
    }

    fn validate_range(&self, start: usize, len: usize) -> Result<(), IoBufferError> {
        let end = start
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;
        if end > self.byte_len {
            Err(IoBufferError::InvalidRange)
        } else {
            Ok(())
        }
    }
}

pub struct IoBuffer<'backing, 'data, State: IoBufferState, Access: IoBufferAccess> {
    backing: &'backing IoBufferBacking<'data>,
    lease: LeaseHandle,
    _state: PhantomData<fn() -> State>,
    _access: PhantomData<fn() -> Access>,
}

impl<'backing, 'data, State: IoBufferState, Access: IoBufferAccess>
    IoBuffer<'backing, 'data, State, Access>
{
    fn new(backing: &'backing IoBufferBacking<'data>, lease: LeaseHandle) -> Self {
        Self {
            backing,
            lease,
            _state: PhantomData,
            _access: PhantomData,
        }
    }

    pub fn backing(&self) -> &'backing IoBufferBacking<'data> {
        self.backing
    }

    pub fn offset(&self) -> usize {
        self.snapshot().map_or(0, |snapshot| snapshot.start)
    }

    pub fn len(&self) -> usize {
        self.snapshot().map_or(0, |snapshot| snapshot.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn split_at(self, mid: usize) -> Result<(Self, Self), (Self, IoBufferError)> {
        let this = ManuallyDrop::new(self);
        let backing = this.backing;
        let left = this.lease;

        match backing.split_lease(left, mid) {
            Ok(right) => Ok((Self::new(backing, left), Self::new(backing, right))),
            Err(err) => Err((ManuallyDrop::into_inner(this), err)),
        }
    }

    pub fn regions(&self) -> IoBufferRegionIter<'_> {
        let snapshot = self.snapshot().unwrap_or(LeaseSnapshot {
            generation: 0,
            start: 0,
            len: 0,
            access: 0,
            desc_state: 0,
            dma_record: NO_DMA_RECORD,
        });

        IoBufferRegionIter::new(
            &self.backing.extents,
            &self.backing.frames,
            snapshot.start,
            snapshot.len,
        )
    }

    fn snapshot(&self) -> Result<LeaseSnapshot, IoBufferError> {
        self.backing.lease_snapshot(self.lease)
    }
}

impl<'backing, 'data, State: VirtualBackedIoBufferState, Access: IoBufferAccess>
    IoBuffer<'backing, 'data, State, Access>
{
    pub fn try_as_slice(&self) -> Option<&[u8]> {
        let snapshot = self.snapshot().ok()?;
        match self.backing.memory {
            BackingMemory::SingleRead { ptr, len, .. } => {
                checked_slice(ptr, len, snapshot.start, snapshot.len)
            }
            BackingMemory::SingleWrite { ptr, len, .. } => {
                checked_slice(ptr as *const u8, len, snapshot.start, snapshot.len)
            }
            _ => None,
        }
    }
}

impl<'backing, 'data, State: VirtualBackedIoBufferState, Access: WritableIoBufferAccess>
    IoBuffer<'backing, 'data, State, Access>
{
    pub fn try_as_mut_slice(&mut self) -> Option<&mut [u8]> {
        let snapshot = self.snapshot().ok()?;
        match self.backing.memory {
            BackingMemory::SingleWrite { ptr, len, .. } => {
                checked_slice_mut(ptr, len, snapshot.start, snapshot.len)
            }
            _ => None,
        }
    }
}

impl<'backing, 'data, Access: IoBufferAccess> IoBuffer<'backing, 'data, Described, Access> {
    pub fn into_phys_framed(
        self,
    ) -> Result<IoBuffer<'backing, 'data, PhysFramed, Access>, (Self, IoBufferError)> {
        let this = ManuallyDrop::new(self);
        let backing = this.backing;
        let lease = this.lease;

        match backing.set_lease_state(lease, STATE_DESCRIBED, STATE_PHYS_FRAMED) {
            Ok(()) => Ok(IoBuffer::new(backing, lease)),
            Err(err) => Err((ManuallyDrop::into_inner(this), err)),
        }
    }
}

impl<'backing, 'data, Source: MappableIoBufferState, Access: IoBufferAccess>
    IoBuffer<'backing, 'data, Source, Access>
{
    pub fn apply_dma_mapping(
        self,
        layout: IoBufferDmaMappingLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<IoBuffer<'backing, 'data, DmaMapped<Source>, Access>, (Self, IoBufferError)> {
        let this = ManuallyDrop::new(self);
        let backing = this.backing;
        let lease = this.lease;
        let snapshot = match backing.lease_snapshot(lease) {
            Ok(snapshot) => snapshot,
            Err(err) => return Err((ManuallyDrop::into_inner(this), err)),
        };

        let record = match backing.allocate_dma_record(
            snapshot.start,
            snapshot.len,
            layout,
            mapped_by,
            unmap,
            cookie,
        ) {
            Ok(record) => record,
            Err(err) => return Err((ManuallyDrop::into_inner(this), err)),
        };

        match backing.set_lease_dma_record(lease, record) {
            Ok(()) => Ok(IoBuffer::new(backing, lease)),
            Err(err) => {
                backing.release_dma_record(record);
                Err((ManuallyDrop::into_inner(this), err))
            }
        }
    }
}

impl<'backing, 'data, Source: MappableIoBufferState, Access: IoBufferAccess>
    IoBuffer<'backing, 'data, DmaMapped<Source>, Access>
{
    pub fn remove_dma_mapping(
        self,
    ) -> Result<IoBuffer<'backing, 'data, Source, Access>, (Self, IoBufferError)> {
        let this = ManuallyDrop::new(self);
        let backing = this.backing;
        let lease = this.lease;
        let new_state = <Source as sealed::IoBufferState>::KIND;

        match backing.clear_lease_dma_record(lease, new_state) {
            Ok(()) => Ok(IoBuffer::new(backing, lease)),
            Err(err) => Err((ManuallyDrop::into_inner(this), err)),
        }
    }

    pub fn dma_segments(&self) -> IoBufferDmaSegments<'_> {
        let Ok(snapshot) = self.snapshot() else {
            return IoBufferDmaSegments::empty(&self.backing.extents, &self.backing.frames);
        };

        if snapshot.dma_record == NO_DMA_RECORD {
            return IoBufferDmaSegments::empty(&self.backing.extents, &self.backing.frames);
        }

        let Ok((mapped_start, mapped_len, layout)) =
            self.backing.dma_record_snapshot(snapshot.dma_record)
        else {
            return IoBufferDmaSegments::empty(&self.backing.extents, &self.backing.frames);
        };

        IoBufferDmaSegments::new(
            layout,
            mapped_start,
            mapped_len,
            snapshot.start,
            snapshot.len,
            &self.backing.extents,
            &self.backing.frames,
        )
    }

    pub fn segment_count(&self) -> usize {
        self.dma_segments().len()
    }
}

impl<'backing, 'data, State: IoBufferState, Access: IoBufferAccess> Drop
    for IoBuffer<'backing, 'data, State, Access>
{
    fn drop(&mut self) {
        self.backing.release_lease(self.lease);
    }
}

impl<'backing, 'data, State: IoBufferState, Access: IoBufferAccess> fmt::Debug
    for IoBuffer<'backing, 'data, State, Access>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot = self.snapshot().ok();
        f.debug_struct("IoBuffer")
            .field("state", &core::any::type_name::<State>())
            .field("access", &core::any::type_name::<Access>())
            .field("offset", &snapshot.map(|snapshot| snapshot.start))
            .field("len", &snapshot.map(|snapshot| snapshot.len))
            .finish()
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
    frames: &'a [IoBufferPageFrame],
    next_extent: usize,
    logical_cursor: usize,
    view_start: usize,
    view_end: usize,
}

impl<'a> IoBufferRegionIter<'a> {
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

impl<'a> Iterator for IoBufferRegionIter<'a> {
    type Item = IoBufferRegion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_extent < self.extents.len() {
            let extent = self.extents[self.next_extent];
            let extent_start = self.logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;
            self.logical_cursor = extent_end;
            self.next_extent += 1;

            let start = max(extent_start, self.view_start);
            let end = min(extent_end, self.view_end);
            if start >= end {
                continue;
            }

            let offset_in_extent = start - extent_start;
            let len = end - start;
            let (first_frame, frame_count, frame_offset) =
                extent_subrange_frames(extent, self.frames, offset_in_extent, len)?;
            let frame_end = first_frame.checked_add(frame_count)?;
            let virtual_addr = extent
                .virtual_addr
                .and_then(|addr| addr.checked_add(offset_in_extent));

            return Some(IoBufferRegion {
                virtual_addr,
                frame_offset,
                byte_len: len,
                page_frames: self.frames.get(first_frame..frame_end)?,
            });
        }

        None
    }
}

pub struct IoBufferDmaSegments<'a> {
    layout: DmaSegmentLayout,
    mapped_start: usize,
    mapped_len: usize,
    lease_start: usize,
    lease_len: usize,
    extents: &'a [IoBufferExtent],
    frames: &'a [IoBufferPageFrame],
}

impl<'a> IoBufferDmaSegments<'a> {
    fn empty(extents: &'a [IoBufferExtent], frames: &'a [IoBufferPageFrame]) -> Self {
        Self {
            layout: DmaSegmentLayout::None,
            mapped_start: 0,
            mapped_len: 0,
            lease_start: 0,
            lease_len: 0,
            extents,
            frames,
        }
    }

    fn new(
        layout: DmaSegmentLayout,
        mapped_start: usize,
        mapped_len: usize,
        lease_start: usize,
        lease_len: usize,
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
    ) -> Self {
        Self {
            layout,
            mapped_start,
            mapped_len,
            lease_start,
            lease_len,
            extents,
            frames,
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

    pub fn iter(&self) -> IoBufferDmaSegmentIter<'a> {
        let skip = self.lease_start.saturating_sub(self.mapped_start);
        IoBufferDmaSegmentIter {
            layout: self.layout,
            extents: self.extents,
            frames: self.frames,
            mapped_start: self.mapped_start,
            mapped_end: self.mapped_start.saturating_add(self.mapped_len),
            skip,
            remaining: self.lease_len,
            index: 0,
            initialized: false,
            page_offset: 0,
            page_size: 0,
            iova_cursor: 0,
            page_index: 0,
            page_count: 0,
            extent_index: 0,
            logical_cursor: 0,
            frame_index: 0,
            frame_end: 0,
            frame_offset: 0,
            identity_remaining: 0,
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
    extents: &'a [IoBufferExtent],
    frames: &'a [IoBufferPageFrame],
    mapped_start: usize,
    mapped_end: usize,
    skip: usize,
    remaining: usize,
    index: usize,
    initialized: bool,
    page_offset: usize,
    page_size: usize,
    iova_cursor: u64,
    page_index: usize,
    page_count: usize,
    extent_index: usize,
    logical_cursor: usize,
    frame_index: usize,
    frame_end: usize,
    frame_offset: usize,
    identity_remaining: usize,
}

impl<'a> Iterator for IoBufferDmaSegmentIter<'a> {
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let mut segment = self.next_uncropped()?;
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

            let take = min(segment.byte_len as usize, self.remaining);
            segment.byte_len = take as u32;
            self.remaining -= take;
            return Some(segment);
        }

        None
    }
}

impl<'a> IoBufferDmaSegmentIter<'a> {
    fn next_uncropped(&mut self) -> Option<IoBufferDmaSegment> {
        match self.layout {
            DmaSegmentLayout::None => None,
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
                page_size,
            } => {
                if !self.initialized {
                    self.page_offset = page_offset;
                    self.page_size = page_size;
                    self.iova_cursor = iova_base;
                    self.identity_remaining = byte_len;
                    self.initialized = true;
                }
                next_page_chunk_segment(
                    self.iova_cursor,
                    self.page_offset,
                    self.page_size,
                    &mut self.index,
                    &mut self.identity_remaining,
                )
            }
            DmaSegmentLayout::ScatterGather {
                iova_base,
                page_size,
            } => {
                if !self.initialized {
                    self.iova_cursor = iova_base;
                    self.page_size = page_size;
                    self.initialized = true;
                }
                next_scatter_gather_segment(
                    self.extents,
                    self.mapped_start,
                    self.mapped_end,
                    self.page_size,
                    &mut self.extent_index,
                    &mut self.logical_cursor,
                    &mut self.iova_cursor,
                    &mut self.page_index,
                    &mut self.page_count,
                    &mut self.page_offset,
                    &mut self.identity_remaining,
                )
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
                    dma_addr: dma_addr.checked_add(self.index as u64 * chunk_len as u64)?,
                    byte_len: chunk_len,
                    reserved: 0,
                };
                self.index += 1;
                Some(segment)
            }
            DmaSegmentLayout::IdentityExtents => next_identity_extent_segment_view(
                self.extents,
                self.frames,
                self.mapped_start,
                self.mapped_end,
                &mut self.extent_index,
                &mut self.logical_cursor,
                &mut self.frame_index,
                &mut self.frame_end,
                &mut self.frame_offset,
                &mut self.identity_remaining,
            ),
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
    Some((4096, PhysAddr::new(addr.as_u64())))
}

#[cfg(not(any(test, feature = "hosted-tests")))]
fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    let block = <Platform as PagingPlatform>::translate_addr(addr)?;
    Some((block.block_size, block.phys_addr))
}

fn build_backing<'data>(
    desc: IoBufferBackingDesc<'data>,
) -> Result<BuiltBacking<'data>, IoBufferError> {
    match desc {
        IoBufferBackingDesc::Slice(bytes) => build_virtual_backing(
            BackingMemory::SingleRead {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                _data: PhantomData,
            },
            &[(bytes.as_ptr() as usize, bytes.len())],
        ),
        IoBufferBackingDesc::SliceMut(bytes) => build_virtual_backing(
            BackingMemory::SingleWrite {
                ptr: bytes.as_mut_ptr(),
                len: bytes.len(),
                _data: PhantomData,
            },
            &[(bytes.as_mut_ptr() as usize, bytes.len())],
        ),
        IoBufferBackingDesc::Segments(segments) => {
            let mut regions = Vec::with_capacity(segments.len());
            for segment in segments {
                regions.push((segment.as_ptr() as usize, segment.len()));
            }
            build_virtual_backing(BackingMemory::SegmentedRead(PhantomData), &regions)
        }
        IoBufferBackingDesc::SegmentsMut(segments) => {
            validate_mut_segments_disjoint(&segments)?;
            let mut regions = Vec::with_capacity(segments.len());
            for segment in segments {
                regions.push((segment.as_ptr() as usize, segment.len()));
            }
            build_virtual_backing(BackingMemory::SegmentedWrite(PhantomData), &regions)
        }
        IoBufferBackingDesc::Frames {
            frame_offset,
            byte_len,
            frames,
        } => build_physical_backing(frame_offset, byte_len, frames),
        IoBufferBackingDesc::PhysicalExtents { frames, extents } => {
            build_physical_extent_backing(frames, extents)
        }
    }
}

fn build_virtual_backing<'data>(
    memory: BackingMemory<'data>,
    regions: &[(usize, usize)],
) -> Result<BuiltBacking<'data>, IoBufferError> {
    let mut extents = Vec::new();
    let mut frames = Vec::new();
    let mut byte_len = 0usize;

    for &(virt_addr, len) in regions {
        let first_frame = frames.len();
        let (frame_count, frame_offset) =
            describe_virtual_buffer_to_frames(virt_addr, len, &mut frames)?;
        extents.push(IoBufferExtent::new(
            Some(virt_addr),
            frame_offset,
            len,
            first_frame,
            frame_count,
        ));
        byte_len = byte_len
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok(BuiltBacking {
        memory,
        byte_len,
        extents,
        frames,
    })
}

fn build_physical_backing<'data>(
    frame_offset: usize,
    byte_len: usize,
    frames: &[IoBufferPageFrame],
) -> Result<BuiltBacking<'data>, IoBufferError> {
    validate_physical_frames(frame_offset, byte_len, frames)?;
    let virtual_addr = frames.first().and_then(|frame| {
        let base = frame.cpu_address().as_u64() as usize;
        if base == 0 {
            None
        } else {
            base.checked_add(frame_offset)
        }
    });

    let extents = alloc::vec![IoBufferExtent::new(
        virtual_addr,
        frame_offset,
        byte_len,
        0,
        frames.len(),
    )];

    Ok(BuiltBacking {
        memory: BackingMemory::None,
        byte_len,
        extents,
        frames: frames.to_vec(),
    })
}

fn build_physical_extent_backing<'data>(
    frames: &[IoBufferPageFrame],
    extents: &[IoBufferExtent],
) -> Result<BuiltBacking<'data>, IoBufferError> {
    let byte_len = validate_physical_extents(frames, extents)?;
    Ok(BuiltBacking {
        memory: BackingMemory::None,
        byte_len,
        extents: extents.to_vec(),
        frames: frames.to_vec(),
    })
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
            VirtAddr::new(current_base_va as u64),
        ));

        frame_count += 1;
        let bytes = (byte_len - consumed).min(frame_len - offset);
        consumed = consumed
            .checked_add(bytes)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok((frame_count, first_frame_offset))
}

fn validate_mut_segments_disjoint(segments: &[&mut [u8]]) -> Result<(), IoBufferError> {
    for first in 0..segments.len() {
        let first_addr = segments[first].as_ptr() as usize;
        let first_len = segments[first].len();
        let first_end =
            first_addr
                .checked_add(first_len)
                .ok_or(IoBufferError::TranslationFailed {
                    virt_addr: first_addr,
                })?;

        for second in first + 1..segments.len() {
            let second_addr = segments[second].as_ptr() as usize;
            let second_len = segments[second].len();
            let second_end =
                second_addr
                    .checked_add(second_len)
                    .ok_or(IoBufferError::TranslationFailed {
                        virt_addr: second_addr,
                    })?;

            if first_len != 0
                && second_len != 0
                && first_addr < second_end
                && second_addr < first_end
            {
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
        Err(IoBufferError::InvalidFrameLayout {
            frame_offset,
            byte_len,
        })
    } else {
        Ok(())
    }
}

fn validate_physical_extents(
    frames: &[IoBufferPageFrame],
    extents: &[IoBufferExtent],
) -> Result<usize, IoBufferError> {
    let mut total_len = 0usize;

    for (idx, extent) in extents.iter().copied().enumerate() {
        let end_frame = extent
            .first_frame
            .checked_add(extent.frame_count)
            .ok_or(IoBufferError::InvalidExtentLayout { extent_index: idx })?;
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

fn validate_dma_mapping_layout(layout: &IoBufferDmaMappingLayout) -> Result<(), IoBufferError> {
    match layout {
        IoBufferDmaMappingLayout::None => Ok(()),
        IoBufferDmaMappingLayout::Contiguous { byte_len, .. } => {
            if *byte_len > u32::MAX as usize {
                Err(IoBufferError::SegmentCapacityExceeded {
                    required: *byte_len,
                    capacity: u32::MAX as usize,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::PageChunks {
            page_offset,
            page_size,
            ..
        } => {
            if *page_size == 0 || *page_size > u32::MAX as usize || *page_offset >= *page_size {
                Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: *page_offset,
                    byte_len: *page_size,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::ScatterGather { page_size, .. } => {
            if *page_size == 0 || *page_size > u32::MAX as usize {
                Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: 0,
                    byte_len: *page_size,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::FixedChunks { chunk_len, .. } => {
            if *chunk_len == 0 {
                Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: 0,
                    byte_len: 0,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::IdentityExtents => Ok(()),
    }
}

fn make_lease_slots(count: usize) -> Box<[LeaseSlot]> {
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        slots.push(LeaseSlot::free());
    }
    slots.into_boxed_slice()
}

fn make_dma_records(count: usize) -> Vec<DmaRecord> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(DmaRecord::empty());
    }
    records
}

fn validate_snapshot(
    slot: &LeaseSlot,
    handle: LeaseHandle,
) -> Result<LeaseSnapshot, IoBufferError> {
    let snapshot = slot.snapshot().ok_or(IoBufferError::InvalidLease)?;
    if snapshot.generation == handle.generation {
        Ok(snapshot)
    } else {
        Err(IoBufferError::InvalidLease)
    }
}

fn reject_conflicting_leases(
    leases: &[LeaseSlot],
    start: usize,
    len: usize,
    access: u8,
) -> Result<(), IoBufferError> {
    let end = start
        .checked_add(len)
        .ok_or(IoBufferError::LengthOverflow)?;
    if len == 0 {
        return Ok(());
    }

    for slot in leases {
        let Some(existing) = slot.snapshot() else {
            continue;
        };
        if existing.len == 0 {
            continue;
        }

        let existing_end = existing.end().ok_or(IoBufferError::LengthOverflow)?;
        let overlaps = start < existing_end && existing.start < end;
        if overlaps && lease_access_conflicts(access, existing.access) {
            return Err(IoBufferError::LeaseConflict { start, len });
        }
    }

    Ok(())
}

fn lease_access_conflicts(left: u8, right: u8) -> bool {
    left != ACCESS_TO_DEVICE || right != ACCESS_TO_DEVICE
}

fn checked_slice<'a>(
    ptr: *const u8,
    backing_len: usize,
    offset: usize,
    len: usize,
) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    if end > backing_len {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr.add(offset), len) })
}

fn checked_slice_mut<'a>(
    ptr: *mut u8,
    backing_len: usize,
    offset: usize,
    len: usize,
) -> Option<&'a mut [u8]> {
    let end = offset.checked_add(len)?;
    if end > backing_len {
        return None;
    }
    Some(unsafe { slice::from_raw_parts_mut(ptr.add(offset), len) })
}

fn extent_subrange_frames(
    extent: IoBufferExtent,
    frames: &[IoBufferPageFrame],
    offset_in_extent: usize,
    len: usize,
) -> Option<(usize, usize, usize)> {
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
        let available = frame_len.saturating_sub(frame_offset);
        let take = min(available, remaining);
        remaining -= take;
        frame_index += 1;
        frame_offset = 0;
    }

    if remaining == 0 {
        Some((first_frame, frame_index - first_frame, first_offset))
    } else {
        None
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

    let bytes = (*remaining)
        .min(page_size - start_in_page)
        .min(u32::MAX as usize);
    let dma_addr = iova_base.checked_add((*index * page_size + start_in_page) as u64)?;
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
    mapped_start: usize,
    mapped_end: usize,
    page_size: usize,
    extent_index: &mut usize,
    logical_cursor: &mut usize,
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

        while *extent_index < extents.len() {
            let extent = extents[*extent_index];
            let extent_start = *logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;
            *extent_index += 1;
            *logical_cursor = extent_end;

            let start = max(extent_start, mapped_start);
            let end = min(extent_end, mapped_end);
            if start >= end {
                continue;
            }

            let offset_in_extent = start - extent_start;
            *page_offset = (extent.frame_offset + offset_in_extent) % page_size;
            *remaining = end - start;
            *page_count = page_chunk_segment_count(*page_offset, *remaining, page_size);
            *page_index = 0;
            break;
        }

        if *remaining == 0 {
            return None;
        }
    }
}

fn next_identity_extent_segment_view(
    extents: &[IoBufferExtent],
    frames: &[IoBufferPageFrame],
    view_start: usize,
    view_end: usize,
    extent_index: &mut usize,
    logical_cursor: &mut usize,
    frame_index: &mut usize,
    frame_end: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    loop {
        if *remaining != 0 {
            return next_identity_segment_limited(
                frames,
                *frame_end,
                frame_index,
                frame_offset,
                remaining,
            );
        }

        while *extent_index < extents.len() {
            let extent = extents[*extent_index];
            let extent_start = *logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;
            *extent_index += 1;
            *logical_cursor = extent_end;

            let start = max(extent_start, view_start);
            let end = min(extent_end, view_end);
            if start >= end {
                continue;
            }

            let end_frame = extent.first_frame.checked_add(extent.frame_count)?;
            if end_frame > frames.len() {
                return None;
            }

            *frame_index = extent.first_frame;
            *frame_end = end_frame;
            *frame_offset = extent.frame_offset.checked_add(start - extent_start)?;
            *remaining = end - start;
            break;
        }

        if *remaining == 0 {
            return None;
        }
    }
}

fn next_identity_segment_limited(
    frames: &[IoBufferPageFrame],
    frame_end: usize,
    frame_index: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if *remaining == 0 {
        return None;
    }

    while *frame_index < frame_end && *frame_offset >= frames[*frame_index].byte_len as usize {
        *frame_offset -= frames[*frame_index].byte_len as usize;
        *frame_index += 1;
    }

    if *frame_index >= frame_end {
        return None;
    }

    let first = frames[*frame_index];
    let start_offset = *frame_offset;
    let dma_addr = first.phys_addr.checked_add(start_offset as u64)?;
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
        let next = frames[*frame_index];
        let expected = dma_addr.checked_add(byte_len as u64)?;
        if next.phys_addr != expected {
            break;
        }

        let add_len = (*remaining).min(next.byte_len as usize);
        let merged_len = byte_len.checked_add(add_len)?;
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

pub fn copy_from_io_buffer_frames(
    frames: &[IoBufferPageFrame],
    buffer_offset: usize,
    dst: *mut u8,
    len: usize,
) -> bool {
    let mut done = 0usize;
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

        let n = min(frame_len - current_offset, remaining);
        unsafe {
            ptr::copy_nonoverlapping(
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
    let mut done = 0usize;
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

        let n = min(frame_len - current_offset, remaining);
        unsafe {
            ptr::copy_nonoverlapping(
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
