const LEASE_FREE: u8 = 0;
const LEASE_ACTIVE: u8 = 1;
const LEASE_RELEASING: u8 = 2;
const ACCESS_TO_DEVICE: u8 = 1;
const ACCESS_FROM_DEVICE: u8 = 2;
const ACCESS_BIDIRECTIONAL: u8 = 3;
const NO_DMA_RECORD: usize = usize::MAX;

#[derive(Clone, Copy)]
enum BackingMemory<'data> {
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
    frames: Vec<IoBufferPageFrame>,
    leases: Box<[LeaseSlot]>,
    dma_records: Vec<DmaRecord>,
}

impl Default for IoBufferBackingScratch {
    fn default() -> Self {
        Self {
            extents: Vec::new(),
            frames: Vec::new(),
            leases: Vec::<LeaseSlot>::new().into_boxed_slice(),
            dma_records: Vec::new(),
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


struct LeaseSlot {
    state: AtomicU8,
    generation: AtomicU32,
    start: AtomicUsize,
    len: AtomicUsize,
    access: AtomicU8,
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
            dma_record: AtomicUsize::new(NO_DMA_RECORD),
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
            dma_record: self.dma_record.load(Ordering::Acquire),
        })
    }

    fn activate(
        &self,
        start: usize,
        len: usize,
        access: u8,
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
    dma_record: usize,
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

        let mut records = self.dma_records.lock();
        for record in records.iter_mut() {
            if record.active {
                continue;
            }

            record.active = true;
            record.persistent = true;
            record.ref_count = 1;
            record.mapped_start = mapped_start;
            record.mapped_len = mapped_len;
            record.access = access;
            record.layout = DmaSegmentLayout::from(layout);
            record.drop_ctx = Some(DmaDropContext {
                mapped_by,
                unmap,
                cookie,
            });
            return Ok(());
        }

        Err(IoBufferError::DmaRecordCapacityExceeded {
            capacity: records.len(),
        })
    }
    pub fn from_scratch(
        desc: IoBufferBackingDesc<'data>,
        config: IoBufferBackingConfig,
        mut scratch: IoBufferBackingScratch,
    ) -> Result<Self, IoBufferError> {
        scratch.clear();
        scratch.ensure_capacity(config)?;

        let (memory, byte_len) =
            build_backing_into(desc, &mut scratch.extents, &mut scratch.frames)?;

        let IoBufferBackingScratch {
            extents,
            frames,
            leases,
            dma_records,
        } = scratch;

        Ok(Self {
            memory,
            byte_len,
            extents,
            frames,
            leases: RwLock::new(leases),
            lease_alloc_lock: Mutex::new(()),
            dma_records: Mutex::new(dma_records),
        })
    }

    pub fn into_scratch(self) -> IoBufferBackingScratch {
        debug_assert_eq!(self.active_lease_count(), 0);

        debug_assert!({
            let records = self.dma_records.lock();
            !records.iter().any(|record| record.active)
        });

        let this = ManuallyDrop::new(self);

        unsafe {
            let mut extents = ptr::read(&this.extents);
            let mut frames = ptr::read(&this.frames);
            let leases = ptr::read(&this.leases);
            let dma_records = ptr::read(&this.dma_records);

            extents.clear();
            frames.clear();

            let mut leases = leases.into_inner();
            for slot in leases.iter_mut() {
                *slot = LeaseSlot::free();
            }

            let mut dma_records = dma_records.into_inner();
            for record in dma_records.iter_mut() {
                *record = DmaRecord::empty();
            }

            IoBufferBackingScratch {
                extents,
                frames,
                leases,
                dma_records,
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
        self.leases.read().len()
    }

    pub fn active_lease_count(&self) -> usize {
        self.leases
            .read()
            .iter()
            .filter(|slot| slot.state.load(Ordering::Acquire) == LEASE_ACTIVE)
            .count()
    }

    pub fn redescribe(&mut self, desc: IoBufferBackingDesc<'data>) -> Result<(), IoBufferError> {
        self.reject_active_leases()?;
        self.reject_active_dma_records()?;

        self.memory = BackingMemory::None;
        self.byte_len = 0;
        self.extents.clear();
        self.frames.clear();

        let (memory, byte_len) = build_backing_into(desc, &mut self.extents, &mut self.frames)?;

        self.memory = memory;
        self.byte_len = byte_len;
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
        self.validate_range(start, len)?;

        let dma_record =
            match self.try_retain_persistent_dma_record_for_range(start, len, access)? {
                Some(record) => record,
                None => NO_DMA_RECORD,
            };

        let leases = self.leases.read();
        let _alloc_guard = self.lease_alloc_lock.lock();

        for (index, slot) in leases.iter().enumerate() {
            if slot.state.load(Ordering::Acquire) != LEASE_FREE {
                continue;
            }

            match slot.activate(start, len, access, dma_record) {
                Ok(generation) => {
                    return Ok(LeaseHandle { index, generation });
                }
                Err(err) => {
                    if dma_record != NO_DMA_RECORD {
                        self.release_dma_record(dma_record);
                    }

                    return Err(err);
                }
            }
        }

        if dma_record != NO_DMA_RECORD {
            self.release_dma_record(dma_record);
        }

        Err(IoBufferError::LeaseCapacityExceeded {
            capacity: leases.len(),
        })
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

        let mut records = self.dma_records.lock();

        for (index, record) in records.iter_mut().enumerate() {
            if !record.active || !record.persistent {
                continue;
            }

            let mapped_end = record
                .mapped_start
                .checked_add(record.mapped_len)
                .ok_or(IoBufferError::LengthOverflow)?;

            if start < record.mapped_start || end > mapped_end {
                continue;
            }

            if !dma_access_allows(record.access, access) {
                continue;
            }

            record.ref_count = record
                .ref_count
                .checked_add(1)
                .ok_or(IoBufferError::LengthOverflow)?;

            return Ok(Some(index));
        }

        Ok(None)
    }
    fn persistent_dma_record_snapshot_for_range(
        &self,
        start: usize,
        len: usize,
        access: u8,
    ) -> Result<Option<(usize, usize, DmaSegmentLayout)>, IoBufferError> {
        let end = start
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;

        let records = self.dma_records.lock();

        for record in records.iter() {
            if !record.active || !record.persistent {
                continue;
            }

            let mapped_end = record
                .mapped_start
                .checked_add(record.mapped_len)
                .ok_or(IoBufferError::LengthOverflow)?;

            if start < record.mapped_start || end > mapped_end {
                continue;
            }

            if !dma_access_allows(record.access, access) {
                continue;
            }

            return Ok(Some((
                record.mapped_start,
                record.mapped_len,
                record.layout,
            )));
        }

        Ok(None)
    }
    fn dma_record_snapshot_for_lease(
        &self,
        snapshot: LeaseSnapshot,
    ) -> Result<Option<(usize, usize, DmaSegmentLayout)>, IoBufferError> {
        if snapshot.dma_record != NO_DMA_RECORD {
            let (mapped_start, mapped_len, layout) =
                self.dma_record_snapshot(snapshot.dma_record)?;

            return Ok(Some((mapped_start, mapped_len, layout)));
        }

        self.persistent_dma_record_snapshot_for_range(snapshot.start, snapshot.len, snapshot.access)
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

            match slot.activate(right_start, right_len, snapshot.access, snapshot.dma_record) {
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
        Ok(())
    }

    fn clear_lease_dma_record(&self, handle: LeaseHandle) -> Result<(), IoBufferError> {
        let leases = self.leases.read();
        let slot = leases
            .get(handle.index)
            .ok_or(IoBufferError::InvalidLease)?;
        validate_snapshot(slot, handle)?;

        let old = slot.dma_record.swap(NO_DMA_RECORD, Ordering::AcqRel);
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
            record.persistent = false;
            record.access = ACCESS_BIDIRECTIONAL;
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
            record.persistent = false;
            record.ref_count = 0;
            record.mapped_start = 0;
            record.mapped_len = 0;
            record.access = 0;
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
impl<'data> Drop for IoBufferBacking<'data> {
    fn drop(&mut self) {
        loop {
            let drop_ctx = {
                let mut records = self.dma_records.lock();
                let mut found = None;

                for record in records.iter_mut() {
                    if !record.active {
                        continue;
                    }

                    record.active = false;
                    record.persistent = false;
                    record.ref_count = 0;
                    record.mapped_start = 0;
                    record.mapped_len = 0;
                    record.access = 0;
                    record.layout = DmaSegmentLayout::None;

                    found = record.drop_ctx.take();
                    break;
                }

                found
            };

            match drop_ctx {
                Some(ctx) => ctx.run(),
                None => break,
            }
        }
    }
}
fn dma_access_allows(mapped: u8, requested: u8) -> bool {
    mapped == ACCESS_BIDIRECTIONAL || mapped == requested
}
