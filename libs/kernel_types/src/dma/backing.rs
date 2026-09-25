use super::construction::{build_backing_into, validate_dma_mapping_layout, validate_snapshot};
use super::descriptors::{DmaDropContext, DmaRecord, DmaRecordPayload};
use super::*;
use crate::radix_map::{RadixMap, RadixMapError};

const LEASE_FREE: u8 = 0;
const LEASE_ACTIVE: u8 = 1;
const LEASE_RELEASING: u8 = 2;
const LEASE_RESERVED: u8 = 3;
const ACCESS_TO_DEVICE: u8 = 1;
const ACCESS_FROM_DEVICE: u8 = 2;
const ACCESS_BIDIRECTIONAL: u8 = 3;
const NO_DMA_RECORD: usize = usize::MAX;

#[derive(Clone, Copy)]
pub(super) struct LeaseChunkRange {
    pub(super) first: usize,
    pub(super) count: usize,
}

#[derive(Clone, Copy)]
pub(super) enum BackingMemory<'data> {
    /// No CPU-addressable backing is available through this object.
    /// Used for physical-only buffers described by frames/extents.
    None,

    /// A single contiguous read-only virtual buffer.
    /// Allows reconstructing `&[u8]` for valid leased ranges.
    SingleRead {
        ptr: usize,
        len: usize,
        _data: PhantomData<&'data [u8]>,
    },

    /// A single contiguous writable virtual buffer.
    /// Allows reconstructing `&[u8]` and `&mut [u8]` for valid leased ranges.
    SingleWrite {
        ptr: usize,
        len: usize,
        _data: PhantomData<&'data mut [u8]>,
    },

    /// Multiple read-only virtual segments.
    /// The segment pointers are represented through extents/frames, not stored here.
    SegmentedRead(PhantomData<&'data [u8]>),

    /// Multiple writable virtual segments.
    /// The segment pointers are represented through extents/frames, not stored here.
    SegmentedWrite(PhantomData<&'data mut [u8]>),
}

pub struct IoBufferBackingScratch {
    extents: Vec<IoBufferExtent>,
    frames: Vec<PhysicalFrameExtent>,
    leases: Box<[LeaseSlot]>,
    dma_records: Vec<DmaRecord>,
    overlap: Option<RadixMap>,
}

impl Default for IoBufferBackingScratch {
    fn default() -> Self {
        Self {
            extents: Vec::new(),
            frames: Vec::new(),
            leases: Vec::<LeaseSlot>::new().into_boxed_slice(),
            dma_records: Vec::new(),
            overlap: None,
        }
    }
}

impl IoBufferBackingScratch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(config: IoBufferBackingConfig) -> Result<Self, IoBufferError> {
        let mut scratch = Self::new();
        scratch.ensure_capacity(config)?;
        Ok(scratch)
    }

    pub fn clear(&mut self) {
        self.extents.clear();
        self.frames.clear();

        for slot in self.leases.iter_mut() {
            *slot = LeaseSlot::free();
        }

        for record in self.dma_records.iter_mut() {
            *record = DmaRecord::empty();
        }
    }

    pub fn ensure_capacity(&mut self, config: IoBufferBackingConfig) -> Result<(), IoBufferError> {
        validate_overlap_granularity(config.overlap_granularity)?;
        if self.leases.len() < config.lease_capacity {
            let mut leases = Vec::new();
            leases
                .try_reserve_exact(config.lease_capacity)
                .map_err(|_| IoBufferError::AllocationFailed)?;

            for _ in 0..config.lease_capacity {
                leases.push(LeaseSlot::free());
            }

            self.leases = leases.into_boxed_slice();
        }

        if self.dma_records.len() < config.dma_record_capacity {
            if self.dma_records.capacity() < config.dma_record_capacity {
                self.dma_records
                    .try_reserve_exact(config.dma_record_capacity - self.dma_records.capacity())
                    .map_err(|_| IoBufferError::AllocationFailed)?;
            }

            while self.dma_records.len() < config.dma_record_capacity {
                self.dma_records.push(DmaRecord::empty());
            }
        }

        Ok(())
    }
}

pub(super) struct LeaseSlot {
    state: AtomicU8,
    generation: AtomicU32,
    first_chunk: AtomicUsize,
    chunk_count: AtomicUsize,
    access: AtomicU8,
    dma_record: AtomicUsize,
}

impl LeaseSlot {
    fn free() -> Self {
        Self {
            state: AtomicU8::new(LEASE_FREE),
            generation: AtomicU32::new(1),
            first_chunk: AtomicUsize::new(0),
            chunk_count: AtomicUsize::new(0),
            access: AtomicU8::new(0),
            dma_record: AtomicUsize::new(NO_DMA_RECORD),
        }
    }

    pub(super) fn snapshot(&self) -> Option<LeaseSlotSnapshot> {
        if self.state.load(Ordering::Acquire) != LEASE_ACTIVE {
            return None;
        }

        let generation = self.generation.load(Ordering::Acquire);

        let snapshot = LeaseSlotSnapshot {
            generation,
            range: LeaseChunkRange {
                first: self.first_chunk.load(Ordering::Acquire),
                count: self.chunk_count.load(Ordering::Acquire),
            },
            access: self.access.load(Ordering::Acquire),
            dma_record: self.dma_record.load(Ordering::Acquire),
        };

        if self.state.load(Ordering::Acquire) != LEASE_ACTIVE
            || self.generation.load(Ordering::Acquire) != generation
        {
            return None;
        }

        Some(snapshot)
    }

    fn try_reserve(&self) -> Option<u32> {
        self.state
            .compare_exchange(
                LEASE_FREE,
                LEASE_RESERVED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;

        Some(self.generation.load(Ordering::Relaxed))
    }

    fn publish(&self, range: LeaseChunkRange, access: u8, dma_record: usize) {
        self.first_chunk.store(range.first, Ordering::Relaxed);
        self.chunk_count.store(range.count, Ordering::Relaxed);
        self.access.store(access, Ordering::Relaxed);
        self.dma_record.store(dma_record, Ordering::Relaxed);
        self.state.store(LEASE_ACTIVE, Ordering::Release);
    }

    fn cancel_reservation(&self) {
        self.state.store(LEASE_FREE, Ordering::Release);
    }

    fn begin_release(&self, generation: u32) -> Option<LeaseSlotSnapshot> {
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

        Some(snapshot)
    }

    fn finish_release(&self) {
        self.first_chunk.store(0, Ordering::Relaxed);
        self.chunk_count.store(0, Ordering::Relaxed);
        self.access.store(0, Ordering::Relaxed);
        self.dma_record.store(NO_DMA_RECORD, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.state.store(LEASE_FREE, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
pub(super) struct LeaseSlotSnapshot {
    pub(super) generation: u32,
    pub(super) range: LeaseChunkRange,
    pub(super) access: u8,
    pub(super) dma_record: usize,
}

#[derive(Clone, Copy)]
pub(super) struct LeaseSnapshot {
    pub(super) start: usize,
    pub(super) len: usize,
    pub(super) access: u8,
    pub(super) dma_record: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LeaseHandle {
    pub(super) index: usize,
    pub(super) generation: u32,
}

pub struct IoBufferBacking<'data> {
    pub(super) memory: BackingMemory<'data>,
    byte_len: usize,
    pub(super) extents: Vec<IoBufferExtent>,
    pub(super) frames: Vec<PhysicalFrameExtent>,
    leases: Box<[LeaseSlot]>,
    lease_alloc_cursor: AtomicUsize,
    dma_records: Box<[DmaRecord]>,
    dma_alloc_cursor: AtomicUsize,

    overlap: RadixMap,
    overlap_granularity: usize,
}

impl<'data> IoBufferBacking<'data> {
    pub fn new(
        desc: IoBufferBackingDesc<'data>,
        config: IoBufferBackingConfig,
    ) -> Result<Self, IoBufferError> {
        Self::from_scratch(desc, config, IoBufferBackingScratch::new())
    }
    pub fn attach_persistent_dma_mapping(
        &self,
        mapped_start: usize,
        mapped_len: usize,
        access: u8,
        layout: IoBufferDmaMappingLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<(), IoBufferError> {
        self.validate_range(mapped_start, mapped_len)?;
        validate_dma_mapping_layout(&layout)?;

        let capacity = self.dma_records.len();
        let start = self.dma_alloc_cursor.fetch_add(1, Ordering::Relaxed);
        let mut payload = DmaRecordPayload {
            mapped_start,
            mapped_len,
            access,
            layout,
            drop_ctx: DmaDropContext {
                mapped_by,
                unmap,
                cookie,
            },
        };
        for offset in 0..capacity {
            let index = start.wrapping_add(offset) % capacity;
            match self.dma_records[index].try_initialize(true, payload) {
                Ok(()) => return Ok(()),
                Err(returned) => payload = returned,
            }
        }

        Err(IoBufferError::DmaRecordCapacityExceeded { capacity })
    }
    pub fn from_scratch(
        desc: IoBufferBackingDesc<'data>,
        config: IoBufferBackingConfig,
        mut scratch: IoBufferBackingScratch,
    ) -> Result<Self, IoBufferError> {
        validate_overlap_granularity(config.overlap_granularity)?;
        scratch.clear();
        scratch.ensure_capacity(config)?;

        let (memory, byte_len) =
            build_backing_into(desc, &mut scratch.extents, &mut scratch.frames)?;
        let overlap = match scratch.overlap.take() {
            Some(overlap)
                if overlap.len() == byte_len
                    && overlap.granularity() == config.overlap_granularity =>
            {
                overlap
            }
            _ => RadixMap::try_new(byte_len, config.overlap_granularity)
                .map_err(|error| map_radix_construction_error(error))?,
        };

        let IoBufferBackingScratch {
            extents,
            frames,
            leases,
            dma_records,
            overlap: _,
        } = scratch;

        Ok(Self {
            memory,
            byte_len,
            extents,
            frames,
            leases,
            lease_alloc_cursor: AtomicUsize::new(0),
            dma_records: dma_records.into_boxed_slice(),
            dma_alloc_cursor: AtomicUsize::new(0),
            overlap,
            overlap_granularity: config.overlap_granularity,
        })
    }

    pub fn into_scratch(self) -> IoBufferBackingScratch {
        debug_assert_eq!(self.active_lease_count(), 0);

        debug_assert!({ !self.dma_records.iter().any(DmaRecord::is_active) });

        let this = ManuallyDrop::new(self);

        unsafe {
            let mut extents = ptr::read(&this.extents);
            let mut frames = ptr::read(&this.frames);
            let leases = ptr::read(&this.leases);
            let dma_records = ptr::read(&this.dma_records);
            let overlap = ptr::read(&this.overlap);

            extents.clear();
            frames.clear();

            let mut leases = leases;
            for slot in leases.iter_mut() {
                *slot = LeaseSlot::free();
            }

            let mut dma_records = dma_records.into_vec();
            for record in dma_records.iter_mut() {
                debug_assert!(!record.is_active());
                *record = DmaRecord::empty();
            }
            IoBufferBackingScratch {
                extents,
                frames,
                leases,
                dma_records,
                overlap: Some(overlap),
            }
        }
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn lease_capacity(&self) -> usize {
        self.leases.len()
    }

    pub fn active_lease_count(&self) -> usize {
        self.leases
            .iter()
            .filter(|slot| slot.state.load(Ordering::Acquire) == LEASE_ACTIVE)
            .count()
    }

    pub fn redescribe(&mut self, desc: IoBufferBackingDesc<'data>) -> Result<(), IoBufferError> {
        self.reject_active_leases()?;
        self.reject_active_dma_records()?;
        let old_byte_len = self.byte_len;

        self.memory = BackingMemory::None;
        self.byte_len = 0;
        self.extents.clear();
        self.frames.clear();

        let (memory, byte_len) = build_backing_into(desc, &mut self.extents, &mut self.frames)?;
        let overlap = if byte_len == old_byte_len {
            None
        } else {
            Some(
                RadixMap::try_new(byte_len, self.overlap_granularity)
                    .map_err(|error| map_radix_construction_error(error))?,
            )
        };

        self.memory = memory;
        self.byte_len = byte_len;
        if let Some(overlap) = overlap {
            self.overlap = overlap;
        }
        self.clear_dma_records();

        Ok(())
    }

    pub fn create_from_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'backing, FromDevice>, IoBufferError>
    where
        'data: 'backing,
    {
        self.ensure_writable_virtual_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_FROM_DEVICE)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_to_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'backing, ToDevice>, IoBufferError>
    where
        'data: 'backing,
    {
        self.ensure_virtual_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_TO_DEVICE)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_bidirectional<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'backing, Bidirectional>, IoBufferError>
    where
        'data: 'backing,
    {
        self.ensure_writable_virtual_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_BIDIRECTIONAL)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_phys_to_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'backing, ToDevice>, IoBufferError>
    where
        'data: 'backing,
    {
        self.ensure_phys_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_TO_DEVICE)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_phys_from_device<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'backing, FromDevice>, IoBufferError>
    where
        'data: 'backing,
    {
        self.ensure_phys_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_FROM_DEVICE)?;
        Ok(IoBuffer::new(self, handle))
    }

    pub fn create_phys_bidirectional<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'backing, 'backing, Bidirectional>, IoBufferError>
    where
        'data: 'backing,
    {
        self.ensure_phys_backed()?;
        let handle = self.create_lease(offset, len, ACCESS_BIDIRECTIONAL)?;
        Ok(IoBuffer::new(self, handle))
    }
    fn create_lease(
        &self,
        start: usize,
        len: usize,
        access: u8,
    ) -> Result<LeaseHandle, IoBufferError> {
        let range = self.lease_chunk_range(start, len)?;

        let capacity = self.leases.len();
        let start_index = self.lease_alloc_cursor.fetch_add(1, Ordering::Relaxed);
        let mut reserved = None;
        for offset in 0..capacity {
            let index = start_index.wrapping_add(offset) % capacity;
            if let Some(generation) = self.leases[index].try_reserve() {
                reserved = Some((index, generation));
                break;
            }
        }
        let (index, generation) =
            reserved.ok_or(IoBufferError::LeaseCapacityExceeded { capacity })?;
        let slot = &self.leases[index];

        if let Err(error) = self.overlap.try_claim_chunks(range.first, range.count) {
            slot.cancel_reservation();
            return Err(self.map_radix_error(error, range));
        }

        let dma_record = match self.try_retain_persistent_dma_record_for_range(start, len, access) {
            Ok(Some(record)) => record,
            Ok(None) => NO_DMA_RECORD,
            Err(error) => {
                unsafe { self.overlap.release_chunks(range.first, range.count) };
                slot.cancel_reservation();
                return Err(error);
            }
        };

        slot.publish(range, access, dma_record);
        Ok(LeaseHandle { index, generation })
    }
    fn try_retain_persistent_dma_record_for_range(
        &self,
        start: usize,
        len: usize,
        access: u8,
    ) -> Result<Option<usize>, IoBufferError> {
        let end = start
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;

        for (index, record) in self.dma_records.iter().enumerate() {
            if !record.try_retain_persistent()? {
                continue;
            }
            let payload = unsafe { record.payload() };

            let Some(mapped_end) = payload.mapped_start.checked_add(payload.mapped_len) else {
                if let Some(ctx) = record.release() {
                    ctx.run();
                }
                return Err(IoBufferError::LengthOverflow);
            };

            let matches = start >= payload.mapped_start
                && end <= mapped_end
                && dma_access_allows(payload.access, access);
            if matches {
                return Ok(Some(index));
            }
            if let Some(ctx) = record.release() {
                ctx.run();
            }
        }

        Ok(None)
    }
    fn persistent_dma_record_snapshot_for_range(
        &self,
        start: usize,
        len: usize,
        access: u8,
    ) -> Result<Option<(usize, usize, IoBufferDmaMappingLayout)>, IoBufferError> {
        let end = start
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;

        for record in self.dma_records.iter() {
            if !record.try_retain_persistent()? {
                continue;
            }
            let payload = unsafe { record.payload() };

            let Some(mapped_end) = payload.mapped_start.checked_add(payload.mapped_len) else {
                if let Some(ctx) = record.release() {
                    ctx.run();
                }
                return Err(IoBufferError::LengthOverflow);
            };

            let result = if start >= payload.mapped_start
                && end <= mapped_end
                && dma_access_allows(payload.access, access)
            {
                Some((payload.mapped_start, payload.mapped_len, payload.layout))
            } else {
                None
            };
            if let Some(ctx) = record.release() {
                ctx.run();
            }
            if result.is_some() {
                return Ok(result);
            }
        }

        Ok(None)
    }
    pub(super) fn dma_record_snapshot_for_lease(
        &self,
        snapshot: LeaseSnapshot,
    ) -> Result<Option<(usize, usize, IoBufferDmaMappingLayout)>, IoBufferError> {
        if snapshot.dma_record != NO_DMA_RECORD {
            let (mapped_start, mapped_len, layout) =
                self.dma_record_snapshot(snapshot.dma_record)?;

            return Ok(Some((mapped_start, mapped_len, layout)));
        }

        self.persistent_dma_record_snapshot_for_range(snapshot.start, snapshot.len, snapshot.access)
    }
    pub(super) fn split_lease(
        &self,
        handle: LeaseHandle,
        mid: usize,
    ) -> Result<LeaseHandle, IoBufferError> {
        let parent = self
            .leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        let snapshot = validate_snapshot(parent, handle, self.overlap_granularity, self.byte_len)?;
        let slot_snapshot = parent.snapshot().ok_or(IoBufferError::InvalidLease)?;

        if mid > snapshot.len {
            return Err(IoBufferError::InvalidRange);
        }
        if mid % self.overlap_granularity != 0 {
            return Err(IoBufferError::InvalidRange);
        }

        let left_count = mid / self.overlap_granularity;
        let right_range = LeaseChunkRange {
            first: slot_snapshot
                .range
                .first
                .checked_add(left_count)
                .ok_or(IoBufferError::LengthOverflow)?,
            count: slot_snapshot.range.count - left_count,
        };
        let capacity = self.leases.len();
        let start_index = self.lease_alloc_cursor.fetch_add(1, Ordering::Relaxed);
        let mut reserved = None;
        for offset in 0..capacity {
            let index = start_index.wrapping_add(offset) % capacity;
            if let Some(generation) = self.leases[index].try_reserve() {
                reserved = Some((index, generation));
                break;
            }
        }
        let (index, generation) =
            reserved.ok_or(IoBufferError::LeaseCapacityExceeded { capacity })?;
        let slot = &self.leases[index];
        if let Err(error) = unsafe {
            self.overlap.split_claim(
                slot_snapshot.range.first,
                slot_snapshot.range.count,
                left_count,
            )
        } {
            slot.cancel_reservation();
            return Err(self.map_radix_error(error, slot_snapshot.range));
        }

        if snapshot.dma_record != NO_DMA_RECORD {
            if let Err(error) = self.retain_dma_record(snapshot.dma_record) {
                slot.cancel_reservation();
                return Err(error);
            }
        }

        slot.publish(right_range, snapshot.access, snapshot.dma_record);
        parent.chunk_count.store(left_count, Ordering::Release);
        Ok(LeaseHandle { index, generation })
    }

    pub(super) fn release_lease(&self, handle: LeaseHandle) {
        let Some(slot) = self.leases.get(handle.index) else {
            return;
        };
        let Some(snapshot) = slot.begin_release(handle.generation) else {
            return;
        };
        if snapshot.dma_record != NO_DMA_RECORD {
            self.release_dma_record(snapshot.dma_record);
        }
        unsafe {
            self.overlap
                .release_chunks(snapshot.range.first, snapshot.range.count)
        };
        slot.finish_release();
    }

    pub(super) fn lease_snapshot(
        &self,
        handle: LeaseHandle,
    ) -> Result<LeaseSnapshot, IoBufferError> {
        let slot = self
            .leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        validate_snapshot(slot, handle, self.overlap_granularity, self.byte_len)
    }

    pub(super) fn set_lease_dma_record(
        &self,
        handle: LeaseHandle,
        record: usize,
    ) -> Result<(), IoBufferError> {
        let slot = self
            .leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        validate_snapshot(slot, handle, self.overlap_granularity, self.byte_len)?;

        let old = slot.dma_record.swap(record, Ordering::AcqRel);
        if old != NO_DMA_RECORD {
            self.release_dma_record(old);
        }
        Ok(())
    }

    pub(super) fn clear_lease_dma_record(&self, handle: LeaseHandle) -> Result<(), IoBufferError> {
        let slot = self
            .leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        validate_snapshot(slot, handle, self.overlap_granularity, self.byte_len)?;

        let old = slot.dma_record.swap(NO_DMA_RECORD, Ordering::AcqRel);
        if old != NO_DMA_RECORD {
            self.release_dma_record(old);
        }
        Ok(())
    }

    pub(super) fn allocate_dma_record(
        &self,
        mapped_start: usize,
        mapped_len: usize,
        layout: IoBufferDmaMappingLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<usize, IoBufferError> {
        validate_dma_mapping_layout(&layout)?;

        let capacity = self.dma_records.len();
        let start = self.dma_alloc_cursor.fetch_add(1, Ordering::Relaxed);
        let mut payload = DmaRecordPayload {
            mapped_start,
            mapped_len,
            access: ACCESS_BIDIRECTIONAL,
            layout,
            drop_ctx: DmaDropContext {
                mapped_by,
                unmap,
                cookie,
            },
        };
        for offset in 0..capacity {
            let index = start.wrapping_add(offset) % capacity;
            match self.dma_records[index].try_initialize(false, payload) {
                Ok(()) => return Ok(index),
                Err(returned) => payload = returned,
            }
        }

        Err(IoBufferError::DmaRecordCapacityExceeded { capacity })
    }

    fn retain_dma_record(&self, index: usize) -> Result<(), IoBufferError> {
        let record = self
            .dma_records
            .get(index)
            .ok_or(IoBufferError::InvalidLease)?;
        if !record.try_retain()? {
            return Err(IoBufferError::InvalidLease);
        }
        Ok(())
    }

    pub(super) fn release_dma_record(&self, index: usize) {
        let Some(record) = self.dma_records.get(index) else {
            return;
        };
        if let Some(ctx) = record.release() {
            ctx.run();
        }
    }

    fn dma_record_snapshot(
        &self,
        index: usize,
    ) -> Result<(usize, usize, IoBufferDmaMappingLayout), IoBufferError> {
        let record = self
            .dma_records
            .get(index)
            .ok_or(IoBufferError::InvalidLease)?;
        if !record.try_retain()? {
            return Err(IoBufferError::InvalidLease);
        }
        let payload = unsafe { record.payload() };
        let snapshot = (payload.mapped_start, payload.mapped_len, payload.layout);
        if let Some(ctx) = record.release() {
            ctx.run();
        }
        Ok(snapshot)
    }

    fn reject_active_leases(&self) -> Result<(), IoBufferError> {
        if self.active_lease_count() == 0 {
            Ok(())
        } else {
            Err(IoBufferError::ActiveLeases)
        }
    }

    fn reject_active_dma_records(&self) -> Result<(), IoBufferError> {
        if self.dma_records.iter().any(DmaRecord::is_active) {
            Err(IoBufferError::ActiveLeases)
        } else {
            Ok(())
        }
    }

    fn clear_dma_records(&mut self) {
        for record in self.dma_records.iter_mut() {
            debug_assert!(!record.is_active());
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

    fn lease_chunk_range(
        &self,
        start: usize,
        len: usize,
    ) -> Result<LeaseChunkRange, IoBufferError> {
        self.validate_range(start, len)?;
        let end = start
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;
        if start % self.overlap_granularity != 0
            || (len % self.overlap_granularity != 0 && end != self.byte_len)
        {
            return Err(IoBufferError::InvalidRange);
        }
        let count = if len == 0 {
            0
        } else {
            len.checked_add(self.overlap_granularity - 1)
                .ok_or(IoBufferError::LengthOverflow)?
                / self.overlap_granularity
        };
        Ok(LeaseChunkRange {
            first: start / self.overlap_granularity,
            count,
        })
    }

    fn map_radix_error(&self, error: RadixMapError, range: LeaseChunkRange) -> IoBufferError {
        match error {
            RadixMapError::Conflict => {
                let start = range
                    .first
                    .checked_mul(self.overlap_granularity)
                    .unwrap_or(usize::MAX);
                let len = range
                    .count
                    .checked_mul(self.overlap_granularity)
                    .unwrap_or(usize::MAX);
                IoBufferError::LeaseConflict { start, len }
            }
            RadixMapError::AllocationFailed => IoBufferError::AllocationFailed,
            RadixMapError::LengthOverflow => IoBufferError::LengthOverflow,
            RadixMapError::InvalidGranularity => IoBufferError::InvalidOverlapGranularity,
            RadixMapError::InvalidRange => IoBufferError::InvalidRange,
        }
    }
}

fn validate_overlap_granularity(granularity: usize) -> Result<(), IoBufferError> {
    if granularity == 0 || !granularity.is_power_of_two() {
        Err(IoBufferError::InvalidOverlapGranularity)
    } else {
        Ok(())
    }
}

fn map_radix_construction_error(error: RadixMapError) -> IoBufferError {
    match error {
        RadixMapError::AllocationFailed => IoBufferError::AllocationFailed,
        RadixMapError::LengthOverflow => IoBufferError::LengthOverflow,
        RadixMapError::InvalidGranularity => IoBufferError::InvalidOverlapGranularity,
        RadixMapError::InvalidRange | RadixMapError::Conflict => IoBufferError::InvalidRange,
    }
}
impl<'data> Drop for IoBufferBacking<'data> {
    fn drop(&mut self) {
        for record in self.dma_records.iter_mut() {
            if let Some(ctx) = record.take_exclusive() {
                ctx.run();
            }
        }
    }
}
fn dma_access_allows(mapped: u8, requested: u8) -> bool {
    mapped == ACCESS_BIDIRECTIONAL || mapped == requested
}
