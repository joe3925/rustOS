use alloc::sync::Arc;
use core::cmp::min;
use core::marker::PhantomData;
use kernel_types::device::DeviceObject;
pub use kernel_types::dma;
use kernel_types::dma::IoBufferBacking;
use kernel_types::dma::{
    DmaBufferView, DmaMapError, DmaMappedBuffer, DmaMappingStrategy, IoBuffer, IoBufferAccess,
    IoBufferDmaSegment, IoBufferError, IoBufferPageFrame,
};
use kernel_types::status::DriverStatus;

pub fn dma_base_page_size() -> usize {
    unsafe { kernel_sys::kernel_dma_base_page_size() as usize }
}

pub fn register_pci_pdo(
    pdo: &Arc<DeviceObject>,
    identity: dma::DmaPciDeviceIdentity,
) -> DriverStatus {
    unsafe { kernel_sys::kernel_dma_register_pci_pdo(pdo, identity) }
}

pub fn register_platform_pdo(
    pdo: &Arc<DeviceObject>,
    identity: dma::DeviceMmuPlatformDeviceIdentity,
) -> DriverStatus {
    unsafe { kernel_sys::kernel_dma_register_platform_pdo(pdo, identity) }
}

pub fn open_device_handle(
    device: &Arc<DeviceObject>,
) -> Result<dma::DmaDeviceHandle, DriverStatus> {
    unsafe { kernel_sys::kernel_dma_open_device_handle(device) }
}

pub fn query_device_state(device: &Arc<DeviceObject>) -> Option<dma::DmaDeviceState> {
    unsafe { kernel_sys::kernel_dma_query_device_state(device) }
}

pub fn map_buffer<'backing, 'data, A>(
    device: &Arc<DeviceObject>,
    mut buffer: IoBuffer<'backing, 'data, A>,
    strategy: DmaMappingStrategy,
) -> Result<IoBuffer<'backing, 'data, A>, (IoBuffer<'backing, 'data, A>, DmaMapError)>
where
    A: IoBufferAccess,
{
    if let Err(err) = buffer.ensure_phys_described() {
        return Err((buffer, map_io_buffer_error(err)));
    }

    let view = match describe_dma_buffer(&buffer) {
        Ok(view) => view,
        Err(err) => return Err((buffer, err)),
    };

    let mapped = match unsafe { kernel_sys::kernel_dma_map_buffer(device, &view, strategy) } {
        Ok(mapped) => mapped,
        Err(err) => {
            drop(view);
            return Err((buffer, err));
        }
    };

    drop(view);

    match buffer.apply_dma_mapping(
        mapped.layout,
        mapped.mapped_by.clone(),
        mapped.unmap,
        mapped.cookie,
    ) {
        Ok(buffer) => Ok(buffer),
        Err((buffer, err)) => {
            unmap_kernel_mapping(mapped);
            Err((buffer, map_io_buffer_error(err)))
        }
    }
}

pub fn try_unmap_buffer<'backing, 'data, A>(
    buffer: IoBuffer<'backing, 'data, A>,
) -> Result<IoBuffer<'backing, 'data, A>, (IoBuffer<'backing, 'data, A>, IoBufferError)>
where
    A: IoBufferAccess,
{
    buffer.remove_dma_mapping()
}

pub fn unmap_buffer<'backing, 'data, A>(
    buffer: IoBuffer<'backing, 'data, A>,
) -> IoBuffer<'backing, 'data, A>
where
    A: IoBufferAccess,
{
    match try_unmap_buffer(buffer) {
        Ok(buffer) => buffer,
        Err((_buffer, _err)) => panic!("IoBuffer is not DMA mapped"),
    }
}

pub fn map_buffer_ref<'map, 'backing, 'data, A>(
    device: &Arc<DeviceObject>,
    buffer: &'map mut IoBuffer<'backing, 'data, A>,
    strategy: DmaMappingStrategy,
) -> Result<BorrowedDmaMapping<'map>, DmaMapError>
where
    A: IoBufferAccess,
{
    let byte_len = buffer.len();
    buffer
        .ensure_phys_described()
        .map_err(map_io_buffer_error)?;
    let view = describe_dma_buffer(buffer)?;
    let mapped = unsafe { kernel_sys::kernel_dma_map_buffer(device, &view, strategy) }?;

    Ok(BorrowedDmaMapping {
        layout: mapped.layout,
        mapped_by: mapped.mapped_by,
        unmap: mapped.unmap,
        cookie: mapped.cookie,
        byte_len,
        view,
        _buffer: PhantomData,
    })
}

fn describe_dma_buffer<'map, 'backing, 'data, A>(
    buffer: &'map IoBuffer<'backing, 'data, A>,
) -> Result<DmaBufferView<'map>, DmaMapError>
where
    A: IoBufferAccess,
{
    let buffer_len = buffer.len();
    if buffer_len == 0 {
        return Err(DmaMapError::InvalidSize);
    }

    let view = buffer
        .dma_buffer_view()
        .map_err(|_| DmaMapError::InvalidSize)?;

    let mut described_len = 0usize;
    let mut region_count = 0usize;

    for region in view.regions() {
        if region.is_empty() {
            continue;
        }

        if region.page_frames().is_empty() {
            return Err(DmaMapError::InvalidSize);
        }

        described_len = described_len
            .checked_add(region.len())
            .ok_or(DmaMapError::InvalidSize)?;

        region_count += 1;
    }

    if region_count == 0 || described_len != buffer_len {
        return Err(DmaMapError::InvalidSize);
    }

    Ok(view)
}

fn unmap_kernel_mapping(mapped: DmaMappedBuffer) {
    (mapped.unmap)(&mapped.mapped_by, mapped.cookie);
}

fn map_io_buffer_error(err: IoBufferError) -> DmaMapError {
    match err {
        IoBufferError::PageCapacityExceeded { required, .. } => {
            DmaMapError::PageCapacityExceeded { required }
        }
        IoBufferError::SegmentCapacityExceeded { required, .. } => {
            DmaMapError::SegmentCapacityExceeded { required }
        }
        _ => DmaMapError::InvalidSize,
    }
}

pub struct BorrowedDmaMapping<'map> {
    layout: dma::IoBufferDmaMappingLayout,
    mapped_by: Arc<DeviceObject>,
    unmap: dma::DmaUnmapFn,
    cookie: usize,
    byte_len: usize,
    view: DmaBufferView<'map>,
    _buffer: PhantomData<&'map ()>,
}

impl<'map> BorrowedDmaMapping<'map> {
    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn layout(&self) -> dma::IoBufferDmaMappingLayout {
        self.layout
    }

    pub fn dma_segments(&self) -> BorrowedDmaSegmentIter<'_, 'map> {
        BorrowedDmaSegmentIter::new(self.layout, self.byte_len, &self.view)
    }

    pub fn segment_count(&self) -> usize {
        self.dma_segments().count()
    }

    pub fn first_segment(&self) -> Option<IoBufferDmaSegment> {
        self.dma_segments().next()
    }
}

impl<'map> Drop for BorrowedDmaMapping<'map> {
    fn drop(&mut self) {
        (self.unmap)(&self.mapped_by, self.cookie);
    }
}

pub struct BorrowedDmaSegmentIter<'view, 'frames> {
    layout: dma::IoBufferDmaMappingLayout,
    regions: kernel_types::dma::DmaBufferRegionIter<'frames, 'view>,
    byte_len: usize,
    index: usize,
    remaining: usize,
    initialized: bool,
    page_offset: usize,
    page_size: usize,
    iova_cursor: u64,
    region_page_index: usize,
    region_page_count: usize,
    region_remaining: usize,
    identity_frames: &'frames [IoBufferPageFrame],
    identity_frame_index: usize,
    identity_frame_offset: usize,
    identity_remaining: usize,
}

impl<'view, 'frames> BorrowedDmaSegmentIter<'view, 'frames> {
    fn new(
        layout: dma::IoBufferDmaMappingLayout,
        byte_len: usize,
        view: &'view DmaBufferView<'frames>,
    ) -> Self {
        Self {
            layout,
            regions: view.regions(),
            byte_len,
            index: 0,
            remaining: byte_len,
            initialized: false,
            page_offset: 0,
            page_size: 0,
            iova_cursor: 0,
            region_page_index: 0,
            region_page_count: 0,
            region_remaining: 0,
            identity_frames: &[],
            identity_frame_index: 0,
            identity_frame_offset: 0,
            identity_remaining: 0,
        }
    }

    fn next_uncropped(&mut self) -> Option<IoBufferDmaSegment> {
        match self.layout {
            dma::IoBufferDmaMappingLayout::None => None,
            dma::IoBufferDmaMappingLayout::Contiguous { dma_addr, byte_len } => {
                if self.index != 0 {
                    return None;
                }

                self.index = 1;

                Some(IoBufferDmaSegment {
                    dma_addr,
                    byte_len: byte_len.try_into().ok()?,
                    reserved: 0,
                })
            }
            dma::IoBufferDmaMappingLayout::PageChunks {
                iova_base,
                page_offset,
                byte_len,
                page_size,
            } => {
                if !self.initialized {
                    self.page_offset = page_offset;
                    self.page_size = page_size;
                    self.iova_cursor = iova_base;
                    self.region_remaining = byte_len;
                    self.initialized = true;
                }

                next_page_chunk_segment(
                    self.iova_cursor,
                    self.page_offset,
                    self.page_size,
                    &mut self.index,
                    &mut self.region_remaining,
                )
            }
            dma::IoBufferDmaMappingLayout::ScatterGather {
                iova_base,
                page_size,
            } => {
                if !self.initialized {
                    self.iova_cursor = iova_base;
                    self.page_size = page_size;
                    self.initialized = true;
                }

                self.next_scatter_gather_segment()
            }
            dma::IoBufferDmaMappingLayout::FixedChunks {
                dma_addr,
                chunk_len,
                count,
            } => {
                if self.index >= count {
                    return None;
                }

                let dma_addr = dma_addr.checked_add(self.index as u64 * chunk_len as u64)?;
                self.index += 1;

                Some(IoBufferDmaSegment {
                    dma_addr,
                    byte_len: chunk_len,
                    reserved: 0,
                })
            }
            dma::IoBufferDmaMappingLayout::IdentityExtents => self.next_identity_segment(),
        }
    }

    fn next_scatter_gather_segment(&mut self) -> Option<IoBufferDmaSegment> {
        if self.page_size == 0 {
            return None;
        }

        loop {
            if self.region_remaining != 0 {
                let segment = next_page_chunk_segment(
                    self.iova_cursor,
                    self.page_offset,
                    self.page_size,
                    &mut self.region_page_index,
                    &mut self.region_remaining,
                );

                if self.region_remaining == 0 {
                    let advance = self.region_page_count.checked_mul(self.page_size)? as u64;
                    self.iova_cursor = self.iova_cursor.checked_add(advance)?;
                    self.region_page_index = 0;
                    self.region_page_count = 0;
                    self.page_offset = 0;
                }

                return segment;
            }

            while let Some(region) = self.regions.next() {
                if region.is_empty() {
                    continue;
                }

                if region.page_frames().is_empty() {
                    return None;
                }

                self.page_offset = region.frame_offset() % self.page_size;
                self.region_remaining = region.len();
                self.region_page_count = page_chunk_segment_count(
                    self.page_offset,
                    self.region_remaining,
                    self.page_size,
                );
                self.region_page_index = 0;
                break;
            }

            if self.region_remaining == 0 {
                return None;
            }
        }
    }

    fn next_identity_segment(&mut self) -> Option<IoBufferDmaSegment> {
        loop {
            if self.identity_remaining != 0 {
                return next_identity_segment_limited(
                    self.identity_frames,
                    &mut self.identity_frame_index,
                    &mut self.identity_frame_offset,
                    &mut self.identity_remaining,
                );
            }

            while let Some(region) = self.regions.next() {
                if region.is_empty() {
                    continue;
                }

                let frames = region.page_frames();
                if frames.is_empty() {
                    return None;
                }

                self.identity_frames = frames;
                self.identity_frame_index = 0;
                self.identity_frame_offset = region.frame_offset();
                self.identity_remaining = region.len();
                break;
            }

            if self.identity_remaining == 0 {
                return None;
            }
        }
    }
}

impl<'view, 'frames> Iterator for BorrowedDmaSegmentIter<'view, 'frames> {
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let mut segment = self.next_uncropped()?;
            let take = min(segment.byte_len as usize, self.remaining);

            segment.byte_len = take as u32;
            self.remaining -= take;

            return Some(segment);
        }

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

fn next_identity_segment_limited(
    frames: &[IoBufferPageFrame],
    frame_index: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if *remaining == 0 {
        return None;
    }

    while *frame_index < frames.len() && *frame_offset >= frames[*frame_index].len() as usize {
        *frame_offset -= frames[*frame_index].len() as usize;
        *frame_index += 1;
    }

    if *frame_index >= frames.len() {
        return None;
    }

    let first = frames[*frame_index];
    let start_offset = *frame_offset;
    let dma_addr = first.physical_address().checked_add(start_offset as u64)?;
    let first_available = first.len() as usize - start_offset;
    let mut byte_len = (*remaining).min(first_available).min(u32::MAX as usize);

    *remaining -= byte_len;

    if byte_len == first_available {
        *frame_index += 1;
        *frame_offset = 0;
    } else {
        *frame_offset += byte_len;
    }

    while *remaining > 0 && *frame_index < frames.len() {
        let next = frames[*frame_index];
        let expected = dma_addr.checked_add(byte_len as u64)?;

        if next.physical_address() != expected {
            break;
        }

        let add_len = (*remaining).min(next.len() as usize);
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

pub fn map_persistent_contiguous_backing(
    device: &Arc<DeviceObject>,
    backing: &IoBufferBacking<'_>,
) -> Result<(), DmaMapError> {
    unsafe { kernel_sys::kernel_dma_map_persistent_contiguous_backing(device, backing) }
}
