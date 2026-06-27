pub struct IoBuffer<'backing, 'data, Access: IoBufferAccess> {
    source: IoBufferSource<'backing, 'data>,
    offset: usize,
    len: usize,
    _access: PhantomData<fn() -> Access>,
}

enum IoBufferSource<'backing, 'data> {
    Backing {
        backing: &'backing IoBufferBacking<'data>,
        lease: LeaseHandle,
    },
    Virt(VirtIoBuffer),
}

struct VirtIoBuffer {
    virt_base: usize,
    len: usize,
    phys: Option<VirtPhys>,
    dma: Option<VirtDma>,
}

struct VirtPhys {
    extents: Vec<IoBufferExtent>,
    frames: Vec<IoBufferPageFrame>,
}

struct VirtDma {
    mapped_start: usize,
    mapped_len: usize,
    layout: DmaSegmentLayout,
    drop_ctx: Option<DmaDropContext>,
}

impl VirtIoBuffer {
    fn ensure_phys_described(&mut self) -> Result<&VirtPhys, IoBufferError> {
        if self.phys.is_none() {
            let mut extents = Vec::new();
            let mut frames = Vec::new();
            let first_frame = frames.len();
            let (frame_count, frame_offset) =
                describe_virtual_buffer_to_frames(self.virt_base, self.len, &mut frames)?;
            extents
                .try_reserve_exact(1)
                .map_err(|_| IoBufferError::AllocationFailed)?;
            extents.push(IoBufferExtent::new(
                Some(self.virt_base),
                frame_offset,
                self.len,
                first_frame,
                frame_count,
            ));
            self.phys = Some(VirtPhys { extents, frames });
        }
        Ok(self
            .phys
            .as_ref()
            .expect("virtual physical description initialized"))
    }
}

fn crop_virt_phys(phys: &VirtPhys, start: usize, len: usize) -> VirtPhys {
    let mut extents = Vec::new();
    let mut frames = Vec::new();

    for region in IoBufferRegionIter::new(&phys.extents, &phys.frames, start, len) {
        let first_frame = frames.len();
        frames.extend_from_slice(region.page_frames());
        extents.push(IoBufferExtent::new(
            region.virtual_address(),
            region.frame_offset(),
            region.len(),
            first_frame,
            region.page_frames().len(),
        ));
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
    fn new(backing: &'backing IoBufferBacking<'data>, lease: LeaseHandle) -> Self {
        let snapshot = backing
            .lease_snapshot(lease)
            .expect("new IoBuffer requires an active lease");
        Self {
            source: IoBufferSource::Backing { backing, lease },
            offset: snapshot.start,
            len: snapshot.len,
            _access: PhantomData,
        }
    }

    pub fn backing(&self) -> Option<&'backing IoBufferBacking<'data>> {
        match self.source {
            IoBufferSource::Backing { backing, .. } => Some(backing),
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
        if matches!(&self.source, IoBufferSource::Virt(virt) if virt.dma.is_some()) {
            return Err((self, IoBufferError::InvalidBackingKind));
        }
        if let IoBufferSource::Virt(virt) = &self.source {
            let Some(right_offset) = self.offset.checked_add(mid) else {
                return Err((self, IoBufferError::LengthOverflow));
            };
            if virt.virt_base.checked_add(right_offset).is_none()
                || virt.virt_base.checked_add(self.offset).is_none()
            {
                return Err((self, IoBufferError::LengthOverflow));
            }
        }
        let this = ManuallyDrop::new(self);
        match &this.source {
            IoBufferSource::Backing { backing, lease } => match backing.split_lease(*lease, mid) {
                Ok(right) => Ok((Self::new(backing, *lease), Self::new(backing, right))),
                Err(err) => Err((ManuallyDrop::into_inner(this), err)),
            },
            IoBufferSource::Virt(_) => {
                let source = unsafe { ptr::read(&this.source) };
                let IoBufferSource::Virt(mut virt) = source else {
                    unreachable!()
                };
                let right_len = this.len - mid;
                let right_base = virt.virt_base + this.offset + mid;
                let left_base = virt.virt_base + this.offset;
                let (left_phys, right_phys) = match virt.phys.take() {
                    Some(phys) => split_virt_phys(phys, this.offset, mid, right_len),
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
                phys,
                dma: None,
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
            IoBufferSource::Backing { .. } => Ok(()),
            IoBufferSource::Virt(virt) => virt.ensure_phys_described().map(|_| ()),
        }
    }

    /// Returns a side-effect-free DMA view of an already physically described buffer.
    pub fn dma_buffer_view(&self) -> Result<DmaBufferView<'_>, IoBufferError> {
        match &self.source {
            IoBufferSource::Backing { backing, .. } => Ok(DmaBufferView::from_iobuffer_parts(
                self.len,
                &backing.extents,
                &backing.frames,
                self.offset,
                self.len,
            )),
            IoBufferSource::Virt(virt) => {
                let phys = virt
                    .phys
                    .as_ref()
                    .ok_or(IoBufferError::PhysicalDescriptionMissing)?;
                Ok(DmaBufferView::from_iobuffer_parts(
                    self.len,
                    &phys.extents,
                    &phys.frames,
                    self.offset,
                    self.len,
                ))
            }
        }
    }
    pub fn regions(&self) -> IoBufferRegionIter<'_> {
        match &self.source {
            IoBufferSource::Backing { backing, .. } => {
                IoBufferRegionIter::new(&backing.extents, &backing.frames, self.offset, self.len)
            }
            IoBufferSource::Virt(virt) => match &virt.phys {
                Some(phys) => {
                    IoBufferRegionIter::new(&phys.extents, &phys.frames, self.offset, self.len)
                }
                None => IoBufferRegionIter::new(&[], &[], 0, 0),
            },
        }
    }
}

impl<'backing, 'data> IoBuffer<'backing, 'data, ToDevice> {
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
        if let IoBufferSource::Virt(virt) = &self.source {
            return checked_slice(virt.virt_base as *const u8, virt.len, self.offset, self.len);
        }
        let IoBufferSource::Backing { backing, .. } = self.source else {
            unreachable!()
        };
        match backing.memory {
            BackingMemory::SingleRead { ptr, len, .. } => {
                checked_slice(ptr as *const u8, len, self.offset, self.len)
            }
            BackingMemory::SingleWrite { ptr, len, .. } => {
                checked_slice(ptr as *const u8, len, self.offset, self.len)
            }
            _ => None,
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

        if let IoBufferSource::Virt(virt) = &self.source {
            let source = virt
                .virt_base
                .checked_add(self.offset)
                .and_then(|addr| addr.checked_add(offset))
                .ok_or(IoBufferError::LengthOverflow)?;
            unsafe { ptr::copy_nonoverlapping(source as *const u8, dst.as_mut_ptr(), dst.len()) };
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
        if let IoBufferSource::Virt(virt) = &self.source {
            return checked_slice_mut(virt.virt_base as *mut u8, virt.len, self.offset, self.len);
        }
        let IoBufferSource::Backing { backing, .. } = self.source else {
            unreachable!()
        };
        match backing.memory {
            BackingMemory::SingleWrite { ptr, len, .. } => {
                checked_slice_mut(ptr as *mut u8, len, self.offset, self.len)
            }
            _ => None,
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

        if let IoBufferSource::Virt(virt) = &self.source {
            let destination = virt
                .virt_base
                .checked_add(self.offset)
                .and_then(|addr| addr.checked_add(offset))
                .ok_or(IoBufferError::LengthOverflow)?;
            unsafe { ptr::copy_nonoverlapping(src.as_ptr(), destination as *mut u8, src.len()) };
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
        if let IoBufferSource::Virt(virt) = &mut self_.source {
            if virt.dma.is_some() {
                return Err((self_, IoBufferError::InvalidBackingKind));
            }
            if let Err(err) = virt
                .ensure_phys_described()
                .and_then(|_| validate_dma_mapping_layout(&layout))
            {
                return Err((self_, err));
            }
            virt.dma = Some(VirtDma {
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

    pub fn remove_dma_mapping(self) -> Result<Self, (Self, IoBufferError)> {
        let mut self_ = self;
        if let IoBufferSource::Virt(virt) = &mut self_.source {
            let Some(mut dma) = virt.dma.take() else {
                return Err((self_, IoBufferError::DmaMappingNotFound));
            };
            if let Some(ctx) = dma.drop_ctx.take() {
                ctx.run();
            }
            return Ok(self_);
        }
        let this = ManuallyDrop::new(self_);
        let IoBufferSource::Backing { backing, lease } = &this.source else {
            unreachable!()
        };
        let backing = *backing;
        let lease = *lease;

        match backing.clear_lease_dma_record(lease) {
            Ok(()) => Ok(IoBuffer::new(backing, lease)),
            Err(err) => Err((ManuallyDrop::into_inner(this), err)),
        }
    }

    pub fn is_dma_mapped(&self) -> bool {
        match &self.source {
            IoBufferSource::Backing { backing, lease } => backing
                .lease_snapshot(*lease)
                .and_then(|snapshot| backing.dma_record_snapshot_for_lease(snapshot))
                .map(|record| record.is_some())
                .unwrap_or(false),
            IoBufferSource::Virt(virt) => virt.dma.is_some(),
        }
    }

    pub fn dma_segments(&self) -> IoBufferDmaSegmentIter<'_> {
        match &self.source {
            IoBufferSource::Backing { backing, lease } => {
                let Ok(snapshot) = backing.lease_snapshot(*lease) else {
                    return IoBufferDmaSegmentIter::empty(&backing.extents, &backing.frames);
                };
                let Ok(Some((mapped_start, mapped_len, layout))) =
                    backing.dma_record_snapshot_for_lease(snapshot)
                else {
                    return IoBufferDmaSegmentIter::empty(&backing.extents, &backing.frames);
                };
                IoBufferDmaSegmentIter::new(
                    layout,
                    mapped_start,
                    mapped_len,
                    self.offset,
                    self.len,
                    &backing.extents,
                    &backing.frames,
                )
            }
            IoBufferSource::Virt(virt) => match (&virt.phys, &virt.dma) {
                (Some(phys), Some(dma)) => IoBufferDmaSegmentIter::new(
                    dma.layout,
                    dma.mapped_start,
                    dma.mapped_len,
                    self.offset,
                    self.len,
                    &phys.extents,
                    &phys.frames,
                ),
                (Some(phys), None) => IoBufferDmaSegmentIter::empty(&phys.extents, &phys.frames),
                _ => IoBufferDmaSegmentIter::empty(&[], &[]),
            },
        }
    }

}

impl<'backing, 'data, Access: IoBufferAccess> Drop for IoBuffer<'backing, 'data, Access> {
    fn drop(&mut self) {
        match &mut self.source {
            IoBufferSource::Backing { backing, lease } => backing.release_lease(*lease),
            IoBufferSource::Virt(virt) => {
                if let Some(mut dma) = virt.dma.take() {
                    if let Some(ctx) = dma.drop_ctx.take() {
                        ctx.run();
                    }
                }
            }
        }
    }
}

impl<'backing, 'data, Access: IoBufferAccess> fmt::Debug for IoBuffer<'backing, 'data, Access> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (source, phys_described) = match &self.source {
            IoBufferSource::Backing { .. } => ("Backing", true),
            IoBufferSource::Virt(virt) => ("Virt", virt.phys.is_some()),
        };
        f.debug_struct("IoBuffer")
            .field("source", &source)
            .field("access", &core::any::type_name::<Access>())
            .field("offset", &self.offset)
            .field("len", &self.len)
            .field("phys_described", &phys_described)
            .field("dma_mapped", &self.is_dma_mapped())
            .finish()
    }
}

fn copy_from_io_buffer_frames(
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

fn copy_to_io_buffer_frames(
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
