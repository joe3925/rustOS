use super::backing::{BackingMemory, LeaseHandle};
use super::construction::{
    checked_slice, checked_slice_mut, describe_virtual_buffer_to_frames,
    validate_dma_mapping_layout,
};
use super::descriptors::DmaDropContext;
use super::*;

pub struct IoBuffer<'backing, 'data, Access: IoBufferAccess> {
    source: IoBufferSource<'backing, 'data>,
    offset: usize,
    len: usize,
    _access: PhantomData<fn() -> Access>,
}

// Keep the backing pointer before the lease in the Backing payload. With three
// variants, repr(Rust) reordered these fields and generated overlapping stack
// copies on the create/drop hot path (nightly-2026-11-01).
#[repr(C)]
enum IoBufferSource<'backing, 'data> {
    Backing {
        backing: &'backing IoBufferBacking<'data>,
        lease: LeaseHandle,
    },
    Factory {
        anchor: &'backing IoBuffer<'backing, 'data, ToDevice>,
        mapping: FactoryDmaMapping,
    },
    Virt(VirtIoBuffer),
}

#[derive(Clone, Copy)]
enum FactoryDmaMapping {
    Inherited,
    Unmapped,
    Owned(usize),
}

pub struct IoBufferToDeviceFactory<'backing, 'data> {
    anchor: IoBuffer<'backing, 'data, ToDevice>,
}

impl<'backing, 'data> IoBufferToDeviceFactory<'backing, 'data> {
    pub fn create<'guard>(
        &'guard self,
        offset: usize,
        len: usize,
    ) -> Result<IoBuffer<'guard, 'guard, ToDevice>, IoBufferError>
    where
        'data: 'guard,
    {
        let end = offset
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;
        if end > self.anchor.len {
            return Err(IoBufferError::InvalidRange);
        }
        let offset = self
            .anchor
            .offset
            .checked_add(offset)
            .ok_or(IoBufferError::LengthOverflow)?;
        Ok(IoBuffer {
            source: IoBufferSource::Factory {
                anchor: &self.anchor,
                mapping: FactoryDmaMapping::Inherited,
            },
            offset,
            len,
            _access: PhantomData,
        })
    }
}

impl<'data> IoBufferBacking<'data> {
    pub fn create_to_device_factory<'backing>(
        &'backing self,
        offset: usize,
        len: usize,
    ) -> Result<IoBufferToDeviceFactory<'backing, 'backing>, IoBufferError>
    where
        'data: 'backing,
    {
        self.create_to_device(offset, len)?.into_to_device_factory()
    }
}

struct VirtIoBuffer {
    virt_base: usize,
    len: usize,
    details: Option<Box<VirtDetails>>,
}

struct VirtDetails {
    dma: Option<VirtDma>,
    phys: VirtPhys,
}

struct VirtPhys {
    extents: Vec<IoBufferExtent>,
    frames: Vec<PhysicalFrameExtent>,
}

struct VirtDma {
    mapped_start: usize,
    mapped_len: usize,
    layout: IoBufferDmaMappingLayout,
    drop_ctx: Option<DmaDropContext>,
}

impl Drop for VirtDma {
    fn drop(&mut self) {
        if let Some(ctx) = self.drop_ctx.take() {
            ctx.run();
        }
    }
}

impl VirtIoBuffer {
    fn ensure_phys_described(&mut self) -> Result<&mut VirtDetails, IoBufferError> {
        if self.details.is_none() {
            let mut extents = Vec::new();
            let mut frames = Vec::new();
            let first_frame = frames.len();
            let (frame_count, frame_offset) =
                describe_virtual_buffer_to_frames(self.virt_base, self.len, &mut frames)?;
            extents
                .try_reserve_exact(1)
                .map_err(|_| IoBufferError::AllocationFailed)?;
            extents.push(unsafe {
                IoBufferExtent::new(
                    Some(self.virt_base),
                    frame_offset,
                    self.len,
                    first_frame,
                    frame_count,
                )
            });
            self.details = Some(
                Box::try_new(VirtDetails {
                    phys: VirtPhys { extents, frames },
                    dma: None,
                })
                .map_err(|_| IoBufferError::AllocationFailed)?,
            );
        }
        Ok(self
            .details
            .as_deref_mut()
            .expect("virtual physical description initialized"))
    }
}

fn crop_virt_phys(phys: &VirtPhys, start: usize, len: usize) -> VirtPhys {
    let mut extents = Vec::new();
    let mut frames = Vec::new();

    for region in IoBufferRegionIter::new(&phys.extents, &phys.frames, start, len) {
        let first_frame = frames.len();
        frames.extend_from_slice(region.page_frames());
        extents.push(unsafe {
            IoBufferExtent::new(
                region.virtual_address(),
                region.frame_offset(),
                region.len(),
                first_frame,
                region.page_frames().len(),
            )
        });
    }

    VirtPhys { extents, frames }
}

fn split_virt_phys(
    phys: VirtPhys,
    start: usize,
    left_len: usize,
    right_len: usize,
) -> (Option<VirtPhys>, Option<VirtPhys>) {
    if left_len == 0 && start == 0 {
        return (
            Some(VirtPhys {
                extents: Vec::new(),
                frames: Vec::new(),
            }),
            Some(phys),
        );
    }
    if right_len == 0 && start == 0 {
        return (
            Some(phys),
            Some(VirtPhys {
                extents: Vec::new(),
                frames: Vec::new(),
            }),
        );
    }

    (
        Some(crop_virt_phys(&phys, start, left_len)),
        Some(crop_virt_phys(&phys, start + left_len, right_len)),
    )
}

impl<'backing, 'data, Access: IoBufferAccess> IoBuffer<'backing, 'data, Access> {
    pub(super) fn new(
        backing: &'backing IoBufferBacking<'data>,
        lease: LeaseHandle,
        offset: usize,
        len: usize,
    ) -> Self {
        Self {
            source: IoBufferSource::Backing { backing, lease },
            offset,
            len,
            _access: PhantomData,
        }
    }

    pub fn backing(&self) -> Option<&'backing IoBufferBacking<'data>> {
        match self.source {
            IoBufferSource::Backing { backing, .. } => Some(backing),
            IoBufferSource::Factory { anchor, .. } => anchor.backing(),
            IoBufferSource::Virt(_) => None,
        }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn split_at(self, mid: usize) -> Result<(Self, Self), (Self, IoBufferError)> {
        if mid > self.len {
            return Err((self, IoBufferError::InvalidRange));
        }
        if let IoBufferSource::Virt(virt) = &self.source {
            if virt
                .details
                .as_ref()
                .is_some_and(|details| details.dma.is_some())
            {
                return Err((self, IoBufferError::InvalidBackingKind));
            }
            if virt.virt_base.checked_add(mid).is_none() {
                return Err((self, IoBufferError::LengthOverflow));
            }
        }
        let this = ManuallyDrop::new(self);
        match &this.source {
            IoBufferSource::Backing { backing, lease } => match backing.split_lease(*lease, mid) {
                Ok(right) => {
                    let left = LeaseHandle {
                        index: lease.index,
                        generation: lease.generation,
                        range: super::backing::LeaseChunkRange {
                            first: lease.range.first,
                            count: right.range.first - lease.range.first,
                        },
                    };
                    Ok((
                        Self::new(backing, left, this.offset, mid),
                        Self::new(backing, right, this.offset + mid, this.len - mid),
                    ))
                }
                Err(err) => Err((ManuallyDrop::into_inner(this), err)),
            },
            IoBufferSource::Factory { anchor, mapping } => {
                if let FactoryDmaMapping::Owned(record) = mapping {
                    if let Err(err) = anchor.backing().unwrap().retain_dma_record(*record) {
                        return Err((ManuallyDrop::into_inner(this), err));
                    }
                }
                Ok((
                    Self {
                        source: IoBufferSource::Factory { anchor, mapping: *mapping },
                        offset: this.offset,
                        len: mid,
                        _access: PhantomData,
                    },
                    Self {
                        source: IoBufferSource::Factory { anchor, mapping: *mapping },
                        offset: this.offset + mid,
                        len: this.len - mid,
                        _access: PhantomData,
                    },
                ))
            }
            IoBufferSource::Virt(_) => {
                let source = unsafe { ptr::read(&this.source) };
                let IoBufferSource::Virt(virt) = source else {
                    unreachable!()
                };
                let right_len = this.len - mid;
                let right_base = virt.virt_base + mid;
                let left_base = virt.virt_base;
                let (left_phys, right_phys) = match virt.details {
                    Some(details) => split_virt_phys(details.phys, 0, mid, right_len),
                    None => (None, None),
                };
                Ok((
                    Self::from_virt_parts(left_base, mid, left_phys),
                    Self::from_virt_parts(right_base, right_len, right_phys),
                ))
            }
        }
    }

    fn from_virt_parts(virt_base: usize, len: usize, phys: Option<VirtPhys>) -> Self {
        Self {
            source: IoBufferSource::Virt(VirtIoBuffer {
                virt_base,
                len,
                details: phys.map(|phys| Box::new(VirtDetails { phys, dma: None })),
            }),
            offset: 0,
            len,
            _access: PhantomData,
        }
    }

    /// Ensures that the buffer has the physical description required for device I/O.
    /// Backing-based buffers are physically described when their backing is created.
    pub fn ensure_phys_described(&mut self) -> Result<(), IoBufferError> {
        match &mut self.source {
            IoBufferSource::Backing { .. } | IoBufferSource::Factory { .. } => Ok(()),
            IoBufferSource::Virt(virt) => virt.ensure_phys_described().map(|_| ()),
        }
    }

    /// Returns a side-effect-free DMA view of an already physically described buffer.
    pub fn dma_buffer_view(&self) -> Result<DmaBufferView<'_>, IoBufferError> {
        if let Some(backing) = self.backing() {
            return Ok(DmaBufferView::from_iobuffer_parts(
                self.len,
                &backing.extents,
                &backing.frames,
                self.offset,
                self.len,
            ));
        }
        match &self.source {
            IoBufferSource::Backing { .. } | IoBufferSource::Factory { .. } => unreachable!(),
            IoBufferSource::Virt(virt) => {
                let phys = &virt
                    .details
                    .as_ref()
                    .ok_or(IoBufferError::PhysicalDescriptionMissing)?
                    .phys;
                Ok(DmaBufferView::from_iobuffer_parts(
                    virt.len,
                    &phys.extents,
                    &phys.frames,
                    0,
                    virt.len,
                ))
            }
        }
    }
    pub fn regions(&self) -> IoBufferRegionIter<'_> {
        if let Some(backing) = self.backing() {
            return IoBufferRegionIter::new(
                &backing.extents,
                &backing.frames,
                self.offset,
                self.len,
            );
        }
        match &self.source {
            IoBufferSource::Backing { .. } | IoBufferSource::Factory { .. } => unreachable!(),
            IoBufferSource::Virt(virt) => match &virt.details {
                Some(details) => IoBufferRegionIter::new(
                    &details.phys.extents,
                    &details.phys.frames,
                    self.offset,
                    self.len,
                ),
                None => IoBufferRegionIter::new(&[], &[], 0, 0),
            },
        }
    }
}

impl<'backing, 'data> IoBuffer<'backing, 'data, ToDevice> {
    pub fn into_to_device_factory(
        self,
    ) -> Result<IoBufferToDeviceFactory<'backing, 'data>, IoBufferError> {
        if !matches!(self.source, IoBufferSource::Backing { .. }) {
            return Err(IoBufferError::InvalidBackingKind);
        }
        Ok(IoBufferToDeviceFactory { anchor: self })
    }

    /// The caller must keep the virtual range valid for the lifetime of the request.
    pub unsafe fn from_virt_to_device(virt_base: usize, len: usize) -> Self {
        Self::from_virt_parts(virt_base, len, None)
    }
}

impl<'backing, 'data> IoBuffer<'backing, 'data, FromDevice> {
    /// The caller must keep the virtual range valid for the lifetime of the request.
    pub unsafe fn from_virt_from_device(virt_base: usize, len: usize) -> Self {
        Self::from_virt_parts(virt_base, len, None)
    }
}

impl<'backing, 'data> IoBuffer<'backing, 'data, Bidirectional> {
    /// The caller must keep the virtual range valid for the lifetime of the request.
    pub unsafe fn from_virt_bidirectional(virt_base: usize, len: usize) -> Self {
        Self::from_virt_parts(virt_base, len, None)
    }
}

impl<'backing, 'data, Access: IoBufferAccess> IoBuffer<'backing, 'data, Access> {
    pub fn try_as_slice(&self) -> Option<&[u8]> {
        if let Some(backing) = self.backing() {
            return match backing.memory {
                BackingMemory::SingleRead { ptr, len, .. }
                | BackingMemory::SingleWrite { ptr, len, .. } => {
                    checked_slice(ptr as *const u8, len, self.offset, self.len)
                }
                _ => None,
            };
        }
        match &self.source {
            IoBufferSource::Virt(virt) => {
                checked_slice(virt.virt_base as *const u8, virt.len, self.offset, self.len)
            }
            IoBufferSource::Backing { .. } | IoBufferSource::Factory { .. } => unreachable!(),
        }
    }

    /// Returns whether every byte in this lease has a kernel CPU address.
    ///
    /// This is independent of DMA mapping. Physical-only buffers may still be
    /// suitable for direct device I/O even when this returns `false`.
    pub fn is_cpu_accessible(&self) -> bool {
        self.regions().all(|region| {
            region.virtual_address().is_some()
                || region
                    .page_frames()
                    .iter()
                    .all(|frame| frame.cpu_address().as_u64() != 0)
        })
    }

    /// Copies a logical range from this buffer into a contiguous CPU buffer.
    pub fn copy_to_slice(&self, offset: usize, dst: &mut [u8]) -> Result<(), IoBufferError> {
        let end = offset
            .checked_add(dst.len())
            .ok_or(IoBufferError::LengthOverflow)?;
        if end > self.len() {
            return Err(IoBufferError::InvalidRange);
        }

        if let Some(source) = self.try_as_slice() {
            dst.copy_from_slice(&source[offset..end]);
            return Ok(());
        }

        let mut skip = offset;
        let mut copied = 0usize;
        for region in self.regions() {
            if copied == dst.len() {
                break;
            }
            if skip >= region.len() {
                skip -= region.len();
                continue;
            }

            let take = min(region.len() - skip, dst.len() - copied);
            if let Some(addr) = region.virtual_address() {
                unsafe {
                    ptr::copy_nonoverlapping(
                        (addr + skip) as *const u8,
                        dst.as_mut_ptr().add(copied),
                        take,
                    );
                }
            } else if region
                .page_frames()
                .iter()
                .any(|frame| frame.cpu_address().as_u64() == 0)
                || !copy_from_io_buffer_frames(
                    region.page_frames(),
                    region.frame_offset() + skip,
                    unsafe { dst.as_mut_ptr().add(copied) },
                    take,
                )
            {
                return Err(IoBufferError::InvalidBackingKind);
            }

            copied += take;
            skip = 0;
        }

        if copied == dst.len() {
            Ok(())
        } else {
            Err(IoBufferError::InvalidBackingKind)
        }
    }
}

impl<'backing, 'data, Access: WritableIoBufferAccess> IoBuffer<'backing, 'data, Access> {
    pub fn try_as_mut_slice(&mut self) -> Option<&mut [u8]> {
        match &self.source {
            IoBufferSource::Factory { .. } => None,
            IoBufferSource::Virt(virt) => {
                checked_slice_mut(virt.virt_base as *mut u8, virt.len, self.offset, self.len)
            }
            IoBufferSource::Backing { backing, .. } => match backing.memory {
                BackingMemory::SingleWrite { ptr, len, .. } => {
                    checked_slice_mut(ptr as *mut u8, len, self.offset, self.len)
                }
                _ => None,
            },
        }
    }

    /// Copies a contiguous CPU buffer into a logical range of this buffer.
    pub fn copy_from_slice(&mut self, offset: usize, src: &[u8]) -> Result<(), IoBufferError> {
        let end = offset
            .checked_add(src.len())
            .ok_or(IoBufferError::LengthOverflow)?;
        if end > self.len() {
            return Err(IoBufferError::InvalidRange);
        }

        if let Some(destination) = self.try_as_mut_slice() {
            destination[offset..end].copy_from_slice(src);
            return Ok(());
        }

        let mut skip = offset;
        let mut copied = 0usize;
        for region in self.regions() {
            if copied == src.len() {
                break;
            }
            if skip >= region.len() {
                skip -= region.len();
                continue;
            }

            let take = min(region.len() - skip, src.len() - copied);
            if let Some(addr) = region.virtual_address() {
                unsafe {
                    ptr::copy_nonoverlapping(
                        src.as_ptr().add(copied),
                        (addr + skip) as *mut u8,
                        take,
                    );
                }
            } else if region
                .page_frames()
                .iter()
                .any(|frame| frame.cpu_address().as_u64() == 0)
                || !copy_to_io_buffer_frames(
                    region.page_frames(),
                    region.frame_offset() + skip,
                    unsafe { src.as_ptr().add(copied) },
                    take,
                )
            {
                return Err(IoBufferError::InvalidBackingKind);
            }

            copied += take;
            skip = 0;
        }

        if copied == src.len() {
            Ok(())
        } else {
            Err(IoBufferError::InvalidBackingKind)
        }
    }
}

impl<'backing, 'data, Access: IoBufferAccess> IoBuffer<'backing, 'data, Access> {
    pub fn apply_dma_mapping(
        self,
        layout: IoBufferDmaMappingLayout,
        mapped_by: Arc<DeviceObject>,
        unmap: DmaUnmapFn,
        cookie: usize,
    ) -> Result<Self, (Self, IoBufferError)> {
        let mut self_ = self;
        if let IoBufferSource::Factory { anchor, mapping } = &mut self_.source {
            let backing = anchor.backing().unwrap();
            let record = match backing.allocate_dma_record(
                self_.offset,
                self_.len,
                layout,
                mapped_by,
                unmap,
                cookie,
            ) {
                Ok(record) => record,
                Err(err) => return Err((self_, err)),
            };
            if let FactoryDmaMapping::Owned(previous) = *mapping {
                backing.release_dma_record(previous);
            }
            *mapping = FactoryDmaMapping::Owned(record);
            return Ok(self_);
        }
        if let IoBufferSource::Virt(virt) = &mut self_.source {
            if virt
                .details
                .as_ref()
                .is_some_and(|details| details.dma.is_some())
            {
                return Err((self_, IoBufferError::InvalidBackingKind));
            }
            let details = match virt.ensure_phys_described() {
                Ok(details) => details,
                Err(err) => return Err((self_, err)),
            };
            if let Err(err) = validate_dma_mapping_layout(&layout) {
                return Err((self_, err));
            }
            details.dma = Some(VirtDma {
                mapped_start: self_.offset,
                mapped_len: self_.len,
                layout: layout.into(),
                drop_ctx: Some(DmaDropContext {
                    mapped_by,
                    unmap,
                    cookie,
                }),
            });
            return Ok(self_);
        }
        let this = ManuallyDrop::new(self_);
        let IoBufferSource::Backing { backing, lease } = &this.source else {
            unreachable!()
        };
        let backing = *backing;
        let lease = *lease;
        match backing.lease_snapshot(lease) {
            Ok(_) => {}
            Err(err) => return Err((ManuallyDrop::into_inner(this), err)),
        }

        let record = match backing.allocate_dma_record(
            this.offset,
            this.len,
            layout,
            mapped_by,
            unmap,
            cookie,
        ) {
            Ok(record) => record,
            Err(err) => return Err((ManuallyDrop::into_inner(this), err)),
        };

        match backing.set_lease_dma_record(lease, record) {
            Ok(()) => Ok(ManuallyDrop::into_inner(this)),
            Err(err) => {
                backing.release_dma_record(record);
                Err((ManuallyDrop::into_inner(this), err))
            }
        }
    }

    pub fn remove_dma_mapping(self) -> Result<Self, (Self, IoBufferError)> {
        let mut self_ = self;
        if let IoBufferSource::Factory { anchor, mapping } = &mut self_.source {
            match *mapping {
                FactoryDmaMapping::Inherited if !anchor.is_dma_mapped() => {
                    return Err((self_, IoBufferError::DmaMappingNotFound));
                }
                FactoryDmaMapping::Unmapped => {
                    return Err((self_, IoBufferError::DmaMappingNotFound));
                }
                FactoryDmaMapping::Owned(record) => {
                    anchor.backing().unwrap().release_dma_record(record);
                }
                FactoryDmaMapping::Inherited => {}
            }
            *mapping = FactoryDmaMapping::Unmapped;
            return Ok(self_);
        }
        if let IoBufferSource::Virt(virt) = &mut self_.source {
            let Some(dma) = virt.details.as_mut().and_then(|details| details.dma.take()) else {
                return Err((self_, IoBufferError::DmaMappingNotFound));
            };
            drop(dma);
            return Ok(self_);
        }
        let this = ManuallyDrop::new(self_);
        let IoBufferSource::Backing { backing, lease } = &this.source else {
            unreachable!()
        };
        let backing = *backing;
        let lease = *lease;

        match backing.clear_lease_dma_record(lease) {
            Ok(()) => Ok(ManuallyDrop::into_inner(this)),
            Err(err) => Err((ManuallyDrop::into_inner(this), err)),
        }
    }

    fn dma_mapping_snapshot(
        &self,
    ) -> Result<Option<(usize, usize, IoBufferDmaMappingLayout)>, IoBufferError> {
        match &self.source {
            IoBufferSource::Backing { backing, lease } => backing
                .lease_snapshot(*lease)
                .and_then(|snapshot| backing.dma_record_snapshot_for_lease(snapshot)),
            IoBufferSource::Factory { anchor, mapping } => match mapping {
                FactoryDmaMapping::Inherited => anchor.dma_mapping_snapshot(),
                FactoryDmaMapping::Unmapped => Ok(None),
                FactoryDmaMapping::Owned(record) => {
                    anchor.backing().unwrap().dma_record_snapshot(*record).map(Some)
                }
            },
            IoBufferSource::Virt(virt) => Ok(virt.details.as_ref()
                .and_then(|details| details.dma.as_ref())
                .map(|dma| (dma.mapped_start, dma.mapped_len, dma.layout))),
        }
    }

    pub fn is_dma_mapped(&self) -> bool {
        self.dma_mapping_snapshot()
            .is_ok_and(|mapping| mapping.is_some())
    }

    pub fn dma_segments(&self) -> IoBufferDmaSegmentIter<'_> {
        if let Some(backing) = self.backing() {
            let Ok(Some((mapped_start, mapped_len, layout))) = self.dma_mapping_snapshot() else {
                return IoBufferDmaSegmentIter::empty(&backing.extents, &backing.frames);
            };
            return IoBufferDmaSegmentIter::new(
                layout,
                mapped_start,
                mapped_len,
                self.offset,
                self.len,
                &backing.extents,
                &backing.frames,
            );
        }
        match &self.source {
            IoBufferSource::Backing { .. } | IoBufferSource::Factory { .. } => unreachable!(),
            IoBufferSource::Virt(virt) => {
                let Some(details) = &virt.details else {
                    return IoBufferDmaSegmentIter::empty(&[], &[]);
                };
                let phys = &details.phys;
                match &details.dma {
                    Some(dma) => IoBufferDmaSegmentIter::new(
                        dma.layout,
                        dma.mapped_start,
                        dma.mapped_len,
                        self.offset,
                        self.len,
                        &phys.extents,
                        &phys.frames,
                    ),
                    None => IoBufferDmaSegmentIter::empty(&phys.extents, &phys.frames),
                }
            }
        }
    }
}

impl<'backing, 'data, Access: IoBufferAccess> Drop for IoBuffer<'backing, 'data, Access> {
    fn drop(&mut self) {
        if let IoBufferSource::Backing { backing, lease } = &self.source {
            backing.release_lease(*lease);
        } else if let IoBufferSource::Factory {
            anchor, mapping: FactoryDmaMapping::Owned(record),
        } = &self.source {
            anchor.backing().unwrap().release_dma_record(*record);
        }
    }
}

impl<'backing, 'data, Access: IoBufferAccess> fmt::Debug for IoBuffer<'backing, 'data, Access> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (source, phys_described) = match &self.source {
            IoBufferSource::Backing { .. } => ("Backing", true),
            IoBufferSource::Factory { .. } => ("Factory", true),
            IoBufferSource::Virt(virt) => ("Virt", virt.details.is_some()),
        };
        f.debug_struct("IoBuffer")
            .field("source", &source)
            .field("access", &core::any::type_name::<Access>())
            .field("offset", &self.offset())
            .field("len", &self.len())
            .field("phys_described", &phys_described)
            .field("dma_mapped", &self.is_dma_mapped())
            .finish()
    }
}

fn copy_from_io_buffer_frames(
    frames: &[PhysicalFrameExtent],
    buffer_offset: usize,
    dst: *mut u8,
    len: usize,
) -> bool {
    visit_frame_chunks(frames, buffer_offset, len, |address, done, count| unsafe {
        ptr::copy_nonoverlapping(address as *const u8, dst.add(done), count);
    })
}

fn copy_to_io_buffer_frames(
    frames: &[PhysicalFrameExtent],
    buffer_offset: usize,
    src: *const u8,
    len: usize,
) -> bool {
    visit_frame_chunks(frames, buffer_offset, len, |address, done, count| unsafe {
        ptr::copy_nonoverlapping(src.add(done), address as *mut u8, count);
    })
}

fn visit_frame_chunks(
    frames: &[PhysicalFrameExtent],
    buffer_offset: usize,
    len: usize,
    mut visit: impl FnMut(u64, usize, usize),
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
        visit(
            frame.cpu_address().as_u64() + current_offset as u64,
            done,
            n,
        );
        done += n;
        remaining -= n;
        current_offset = 0;
    }

    remaining == 0
}
