use crate::drivers::pnp::device::DevNodeExt;
use crate::memory::device_mmu::DeviceMmuAttachment;
use crate::memory::device_mmu::DeviceMmuDeviceIdentity;
use crate::memory::device_mmu::DeviceMmuDomain;
use crate::memory::device_mmu::DeviceMmuError;
use crate::memory::device_mmu::DeviceMmuMapPermissions;
use crate::memory::device_mmu::DeviceMmuSystem;
use crate::memory::device_mmu::MappingRecord;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::sync::Weak;
use kernel_types::device::DeviceObject;
use kernel_types::dma::BorrowedDmaMapping;
use kernel_types::dma::DeviceMmuPlatformDeviceIdentity;
use kernel_types::dma::DmaDeviceHandle;
use kernel_types::dma::DmaDeviceState;
use kernel_types::dma::DmaMapError;
use kernel_types::dma::DmaMapped;
use kernel_types::dma::DmaMappingStrategy;
use kernel_types::dma::DmaPciDeviceIdentity;
use kernel_types::dma::IoBuffer;
use kernel_types::dma::IoBufferDmaSegment;
use kernel_types::dma::IoBufferPageFrame;
use kernel_types::dma::PhysFramed;
use kernel_types::dma::ToDevice;
use kernel_types::dma::DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE;
use kernel_types::dma::IOBUFFER_INLINE_SEGMENT_CAPACITY;
use kernel_types::dma::IOBUFFER_MAX_PAGE_CAPACITY;
use kernel_types::dma::IOBUFFER_PAGE_SIZE;
use kernel_types::status::DriverStatus;
use spin::Mutex;
use spin::Once;
static DMA_MANAGER: Once<DmaManager> = Once::new();

pub fn init_dma_manager() {
    let _ = DMA_MANAGER.call_once(DmaManager::new);
}

pub fn register_pci_pdo(pdo: &Arc<DeviceObject>, identity: DmaPciDeviceIdentity) -> DriverStatus {
    manager().register_pci_pdo(pdo, identity)
}
pub fn register_platform_pdo(
    pdo: &Arc<DeviceObject>,
    identity: DeviceMmuPlatformDeviceIdentity,
) -> DriverStatus {
    manager().register_platform_pdo(pdo, identity)
}
pub fn open_device_handle(device: &Arc<DeviceObject>) -> Result<DmaDeviceHandle, DriverStatus> {
    manager().open_device_handle(device)
}

pub fn query_device_state(device: &Arc<DeviceObject>) -> Option<DmaDeviceState> {
    manager().query_device_state(device)
}

pub fn unregister_device(device: &Arc<DeviceObject>) -> DriverStatus {
    manager().unregister_device(device)
}

struct PreparedDmaMapping {
    records: PendingMappingRecords,
    segments: [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
    segments_len: usize,
}

pub fn map_buffer<'a>(
    device: &Arc<DeviceObject>,
    buffer: IoBuffer<'a, PhysFramed, ToDevice>,
    strategy: DmaMappingStrategy,
) -> Result<
    IoBuffer<'a, DmaMapped<PhysFramed>, ToDevice>,
    (IoBuffer<'a, PhysFramed, ToDevice>, DmaMapError),
> {
    let m = manager();

    let key = match resolve_hardware_pdo(device) {
        Ok(pdo) => device_key(&pdo),
        Err(_) => return Err((buffer, DmaMapError::NoIommu)),
    };

    let active = match m.begin_mapping(key) {
        Ok(active) => active,
        Err(err) => return Err((buffer, err)),
    };

    let prepared = match prepare_dma_mapping(&m.device_mmu, &active.domain, &buffer, strategy) {
        Ok(prepared) => prepared,
        Err(err) => return Err((buffer, err)),
    };

    if prepared.records.is_empty() {
        return Err((buffer, DmaMapError::RemappingUnavailable));
    }

    let cookie = m.alloc_cookie();

    let mapped_buffer = match buffer.apply_dma_mapping(
        &prepared.segments[..prepared.segments_len],
        active.pdo.clone(),
        unmap_trampoline,
        cookie as usize,
    ) {
        Ok(mapped_buffer) => mapped_buffer,
        Err((buffer, err)) => {
            rollback_mappings(&m.device_mmu, &active.domain, &prepared.records);

            return Err((
                buffer,
                match err {
                    kernel_types::dma::IoBufferError::SegmentCapacityExceeded {
                        required, ..
                    } => DmaMapError::SegmentCapacityExceeded { required },
                    kernel_types::dma::IoBufferError::PageCapacityExceeded { required, .. } => {
                        DmaMapError::PageCapacityExceeded { required }
                    }
                    _ => DmaMapError::InvalidSize,
                },
            ));
        }
    };

    m.insert_pending_unmap(
        cookie,
        PendingUnmap {
            device_key: key,
            domain: active.domain.clone(),
            records: prepared.records,
        },
    );

    Ok(mapped_buffer)
}

pub fn unmap_buffer<'a>(
    buffer: IoBuffer<'a, DmaMapped<PhysFramed>, ToDevice>,
) -> IoBuffer<'a, PhysFramed, ToDevice> {
    buffer.remove_dma_mapping()
}

pub fn map_buffer_ref<'map, 'buffer>(
    device: &Arc<DeviceObject>,
    buffer: &'map IoBuffer<'buffer, PhysFramed, ToDevice>,
    strategy: DmaMappingStrategy,
) -> Result<BorrowedDmaMapping<'map>, DmaMapError> {
    let m = manager();

    let key = match resolve_hardware_pdo(device) {
        Ok(pdo) => device_key(&pdo),
        Err(_) => return Err(DmaMapError::NoIommu),
    };

    let active = m.begin_mapping(key)?;

    let prepared = prepare_dma_mapping(&m.device_mmu, &active.domain, buffer, strategy)?;

    if prepared.records.is_empty() {
        return Err(DmaMapError::RemappingUnavailable);
    }

    let cookie = m.alloc_cookie();

    let mapping = match BorrowedDmaMapping::new(
        &prepared.segments[..prepared.segments_len],
        active.pdo.clone(),
        unmap_trampoline,
        cookie as usize,
    ) {
        Ok(mapping) => mapping,
        Err(kernel_types::dma::IoBufferError::SegmentCapacityExceeded { required, .. }) => {
            rollback_mappings(&m.device_mmu, &active.domain, &prepared.records);
            return Err(DmaMapError::SegmentCapacityExceeded { required });
        }
        Err(kernel_types::dma::IoBufferError::PageCapacityExceeded { required, .. }) => {
            rollback_mappings(&m.device_mmu, &active.domain, &prepared.records);
            return Err(DmaMapError::PageCapacityExceeded { required });
        }
        Err(_) => {
            rollback_mappings(&m.device_mmu, &active.domain, &prepared.records);
            return Err(DmaMapError::InvalidSize);
        }
    };

    m.insert_pending_unmap(
        cookie,
        PendingUnmap {
            device_key: key,
            domain: active.domain.clone(),
            records: prepared.records,
        },
    );

    Ok(mapping)
}

fn prepare_dma_mapping(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
    strategy: DmaMappingStrategy,
) -> Result<PreparedDmaMapping, DmaMapError> {
    validate_dma_buffer(buffer)?;

    let buffer_len = buffer.len();

    let Some(iommu_page_count) = covered_iommu_page_count_for_buffer(buffer) else {
        return Err(DmaMapError::InvalidSize);
    };

    let Ok(iommu_page_count_u32) = u32::try_from(iommu_page_count) else {
        return Err(DmaMapError::InvalidSize);
    };

    let Some(map_size) = (iommu_page_count as u64).checked_mul(IOBUFFER_PAGE_SIZE as u64) else {
        return Err(DmaMapError::InvalidSize);
    };

    let mut records = PendingMappingRecords::new();

    let mut segments = [IoBufferDmaSegment {
        dma_addr: 0,
        byte_len: 0,
        reserved: 0,
    }; IOBUFFER_INLINE_SEGMENT_CAPACITY];

    let segments_len = match strategy {
        DmaMappingStrategy::SingleContiguous => {
            if buffer_len > u32::MAX as usize {
                return Err(DmaMapError::InvalidSize);
            }

            if !buffer_supports_contiguous_iova(buffer) {
                return Err(DmaMapError::RemappingUnavailable);
            }

            let Some(iova_base) = domain.alloc_iova(map_size) else {
                return Err(DmaMapError::RemappingUnavailable);
            };

            let rec = MappingRecord {
                iova_base,
                page_count: iommu_page_count_u32,
                is_identity: false,
            };

            records.push(rec)?;

            if let Err(err) = map_buffer_frames_to_iova(device_mmu, domain, iova_base, buffer) {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            let Some(page_offset) = first_dma_page_offset(buffer) else {
                rollback_mappings(device_mmu, domain, &records);
                return Err(DmaMapError::InvalidSize);
            };

            segments[0] = IoBufferDmaSegment {
                dma_addr: iova_base + page_offset as u64,
                byte_len: buffer_len as u32,
                reserved: 0,
            };

            1
        }
        DmaMappingStrategy::ScatterGather => {
            if iommu_page_count > IOBUFFER_INLINE_SEGMENT_CAPACITY {
                return Err(DmaMapError::SegmentCapacityExceeded {
                    required: iommu_page_count,
                });
            }

            let Some(iova_base) = domain.alloc_iova(map_size) else {
                return Err(DmaMapError::RemappingUnavailable);
            };

            let rec = MappingRecord {
                iova_base,
                page_count: iommu_page_count_u32,
                is_identity: false,
            };

            records.push(rec)?;

            if let Err(err) = map_buffer_frames_to_iova(device_mmu, domain, iova_base, buffer) {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            match build_scatter_segments_from_iova(buffer, iova_base, &mut segments) {
                Ok(len) => len,
                Err(err) => {
                    rollback_mappings(device_mmu, domain, &records);
                    return Err(err);
                }
            }
        }
        DmaMappingStrategy::ContiguousChunks { chunk_size } => {
            if chunk_size == 0 {
                return Err(DmaMapError::InvalidSize);
            }

            if (chunk_size % IOBUFFER_PAGE_SIZE) != 0 {
                return Err(DmaMapError::ChunkSizeNotPageAligned { chunk_size });
            }

            if (buffer_len % chunk_size) != 0 {
                return Err(DmaMapError::UnalignedChunkSize {
                    buffer_len,
                    chunk_size,
                });
            }

            if chunk_size > u32::MAX as usize {
                return Err(DmaMapError::InvalidSize);
            }

            if !buffer_supports_contiguous_iova(buffer) {
                return Err(DmaMapError::RemappingUnavailable);
            }

            let chunk_count = buffer_len / chunk_size;

            if chunk_count > IOBUFFER_INLINE_SEGMENT_CAPACITY {
                return Err(DmaMapError::SegmentCapacityExceeded {
                    required: chunk_count,
                });
            }

            let Some(iova_base) = domain.alloc_iova(map_size) else {
                return Err(DmaMapError::RemappingUnavailable);
            };

            let rec = MappingRecord {
                iova_base,
                page_count: iommu_page_count_u32,
                is_identity: false,
            };

            records.push(rec)?;

            if let Err(err) = map_buffer_frames_to_iova(device_mmu, domain, iova_base, buffer) {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            let Some(page_offset) = first_dma_page_offset(buffer) else {
                rollback_mappings(device_mmu, domain, &records);
                return Err(DmaMapError::InvalidSize);
            };

            let dma_addr = iova_base + page_offset as u64;

            for idx in 0..chunk_count {
                segments[idx] = IoBufferDmaSegment {
                    dma_addr: dma_addr + (idx as u64 * chunk_size as u64),
                    byte_len: chunk_size as u32,
                    reserved: 0,
                };
            }

            chunk_count
        }
        DmaMappingStrategy::FullIdentity => {
            if let Err(err) = map_identity_frames(device_mmu, domain, buffer, &mut records) {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            match build_identity_segments(buffer, &mut segments) {
                Ok(len) => len,
                Err(err) => {
                    rollback_mappings(device_mmu, domain, &records);
                    return Err(err);
                }
            }
        }
    };

    if segments_len == 0 || records.is_empty() {
        rollback_mappings(device_mmu, domain, &records);
        return Err(DmaMapError::RemappingUnavailable);
    }

    if let Err(err) = device_mmu.invalidate_domain(domain) {
        rollback_mappings(device_mmu, domain, &records);
        return Err(map_device_mmu_error(err));
    }

    Ok(PreparedDmaMapping {
        records,
        segments,
        segments_len,
    })
}

extern "C" fn unmap_trampoline(_device: &Arc<DeviceObject>, cookie: usize) {
    let m = manager();

    let Some(pending) = m.remove_pending_unmap(cookie as u64) else {
        return;
    };

    for rec in pending.records.as_slice() {
        let _ = m.device_mmu.unmap_record(&pending.domain, *rec);
    }
}

fn map_device_mmu_error(err: DeviceMmuError) -> DmaMapError {
    match err {
        DeviceMmuError::NoBackingFrame => DmaMapError::RemappingUnavailable,
        DeviceMmuError::IovaSpaceExhausted => DmaMapError::RemappingUnavailable,
        DeviceMmuError::InvalidRange => DmaMapError::InvalidSize,
        DeviceMmuError::NotMapped => DmaMapError::NoIommu,
        DeviceMmuError::HardwareError => DmaMapError::NoIommu,
        DeviceMmuError::Unsupported => DmaMapError::NoIommu,
        DeviceMmuError::InvalidDevice => DmaMapError::NoIommu,
        DeviceMmuError::InvalidDomain => DmaMapError::NoIommu,
    }
}

fn validate_dma_buffer(buffer: &IoBuffer<'_, PhysFramed, ToDevice>) -> Result<(), DmaMapError> {
    if buffer.len() == 0 || buffer.page_count() == 0 || buffer.extent_count() == 0 {
        return Err(DmaMapError::InvalidSize);
    }

    if buffer.page_count() > IOBUFFER_MAX_PAGE_CAPACITY {
        return Err(DmaMapError::PageCapacityExceeded {
            required: buffer.page_count(),
        });
    }

    if !buffer_frames_cover_extents(buffer) {
        return Err(DmaMapError::InvalidSize);
    }

    if covered_iommu_page_count_for_buffer(buffer).is_none() {
        return Err(DmaMapError::InvalidSize);
    }

    Ok(())
}

fn for_each_buffer_extent<F>(
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
    mut f: F,
) -> Result<(), DmaMapError>
where
    F: FnMut(&[IoBufferPageFrame], usize, usize) -> Result<(), DmaMapError>,
{
    let frames = buffer.page_frames();

    for extent in buffer.extents() {
        if extent.byte_len == 0 {
            continue;
        }

        let Some(end_frame) = extent.first_frame.checked_add(extent.frame_count) else {
            return Err(DmaMapError::InvalidSize);
        };

        let Some(extent_frames) = frames.get(extent.first_frame..end_frame) else {
            return Err(DmaMapError::InvalidSize);
        };

        f(extent_frames, extent.frame_offset, extent.byte_len)?;
    }

    Ok(())
}

fn buffer_frames_cover_extents(buffer: &IoBuffer<'_, PhysFramed, ToDevice>) -> bool {
    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        if frames_cover_buffer(frames, frame_offset, byte_len) {
            Ok(())
        } else {
            Err(DmaMapError::InvalidSize)
        }
    })
    .is_ok()
}

fn first_dma_page_offset(buffer: &IoBuffer<'_, PhysFramed, ToDevice>) -> Option<usize> {
    for extent in buffer.extents() {
        if extent.byte_len != 0 {
            return Some(extent.frame_offset & (IOBUFFER_PAGE_SIZE - 1));
        }
    }

    None
}

fn buffer_supports_contiguous_iova(buffer: &IoBuffer<'_, PhysFramed, ToDevice>) -> bool {
    let mut logical_len = 0usize;
    let mut first_offset = None;

    for extent in buffer.extents() {
        if extent.byte_len == 0 {
            continue;
        }

        let start_offset = extent.frame_offset & (IOBUFFER_PAGE_SIZE - 1);

        match first_offset {
            Some(_) if start_offset != 0 => return false,
            None => first_offset = Some(start_offset),
            _ => {}
        }

        let Some(next_logical_len) = logical_len.checked_add(extent.byte_len) else {
            return false;
        };

        logical_len = next_logical_len;

        if logical_len < buffer.len() {
            let Some(total_offset) = first_offset.unwrap_or(0).checked_add(logical_len) else {
                return false;
            };

            if (total_offset & (IOBUFFER_PAGE_SIZE - 1)) != 0 {
                return false;
            }
        }
    }

    first_offset.is_some() && logical_len == buffer.len()
}

fn frames_cover_buffer(
    frames: &[IoBufferPageFrame],
    frame_offset: usize,
    buffer_len: usize,
) -> bool {
    if buffer_len == 0 {
        return true;
    }

    let Some(first) = frames.first() else {
        return false;
    };

    if frame_offset >= first.byte_len as usize {
        return false;
    }

    let mut available = (first.byte_len as usize).saturating_sub(frame_offset);

    for frame in &frames[1..] {
        if available >= buffer_len {
            return true;
        }

        available = available.saturating_add(frame.byte_len as usize);
    }

    available >= buffer_len
}

fn covered_iommu_page_count_for_buffer(
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
) -> Option<usize> {
    let mut total = 0usize;

    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        let Some(count) = covered_iommu_page_count(frames, frame_offset, byte_len) else {
            return Err(DmaMapError::InvalidSize);
        };

        total = total.checked_add(count).ok_or(DmaMapError::InvalidSize)?;

        Ok(())
    })
    .ok()?;

    Some(total)
}

fn covered_iommu_page_count(
    frames: &[IoBufferPageFrame],
    frame_offset: usize,
    buffer_len: usize,
) -> Option<usize> {
    let mut total = 0usize;

    for_each_covered_page_run(frames, frame_offset, buffer_len, |_, page_count| {
        total = total
            .checked_add(page_count)
            .ok_or(DmaMapError::InvalidSize)?;

        Ok(())
    })
    .ok()?;

    Some(total)
}

fn for_each_covered_page_run<F>(
    frames: &[IoBufferPageFrame],
    frame_offset: usize,
    buffer_len: usize,
    mut f: F,
) -> Result<(), DmaMapError>
where
    F: FnMut(u64, usize) -> Result<(), DmaMapError>,
{
    let mut remaining = buffer_len;
    let mut offset = frame_offset as u64;

    for frame in frames {
        if remaining == 0 {
            return Ok(());
        }

        if offset >= frame.byte_len {
            return Err(DmaMapError::InvalidSize);
        }

        let start = frame.phys_addr + offset;
        let bytes = remaining.min((frame.byte_len - offset) as usize);
        let page_base = start & !((IOBUFFER_PAGE_SIZE as u64) - 1);
        let page_end = align_up_u64(start + bytes as u64, IOBUFFER_PAGE_SIZE as u64)?;
        let page_count = ((page_end - page_base) / IOBUFFER_PAGE_SIZE as u64) as usize;

        f(page_base, page_count)?;

        remaining -= bytes;
        offset = 0;
    }

    if remaining == 0 {
        Ok(())
    } else {
        Err(DmaMapError::InvalidSize)
    }
}

fn for_each_covered_data_run<F>(
    frames: &[IoBufferPageFrame],
    frame_offset: usize,
    buffer_len: usize,
    mut f: F,
) -> Result<(), DmaMapError>
where
    F: FnMut(u64, usize) -> Result<(), DmaMapError>,
{
    let mut remaining = buffer_len;
    let mut offset = frame_offset as u64;

    for frame in frames {
        if remaining == 0 {
            return Ok(());
        }

        if offset >= frame.byte_len {
            return Err(DmaMapError::InvalidSize);
        }

        let bytes = remaining.min((frame.byte_len - offset) as usize);

        f(frame.phys_addr + offset, bytes)?;

        remaining -= bytes;
        offset = 0;
    }

    if remaining == 0 {
        Ok(())
    } else {
        Err(DmaMapError::InvalidSize)
    }
}

fn map_phys_run_to_iova(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    iova_base: u64,
    phys_base: u64,
    page_count: usize,
) -> Result<(), DmaMapError> {
    let len = page_count as u64 * IOBUFFER_PAGE_SIZE as u64;

    device_mmu
        .map_range(
            domain,
            iova_base,
            phys_base,
            len,
            DeviceMmuMapPermissions::ReadWrite,
        )
        .map_err(map_device_mmu_error)
}

fn map_buffer_frames_to_iova(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    iova_base: u64,
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
) -> Result<(), DmaMapError> {
    let mut iova_cursor = iova_base;

    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        for_each_covered_page_run(frames, frame_offset, byte_len, |phys_base, page_count| {
            map_phys_run_to_iova(device_mmu, domain, iova_cursor, phys_base, page_count)?;

            iova_cursor = iova_cursor
                .checked_add((page_count * IOBUFFER_PAGE_SIZE) as u64)
                .ok_or(DmaMapError::InvalidSize)?;

            Ok(())
        })
    })
}

fn map_identity_frames(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
    records: &mut PendingMappingRecords,
) -> Result<(), DmaMapError> {
    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        for_each_covered_page_run(frames, frame_offset, byte_len, |phys_base, page_count| {
            records.push_or_extend_identity(phys_base, page_count)?;
            map_phys_run_to_iova(device_mmu, domain, phys_base, phys_base, page_count)
        })
    })
}

fn rollback_mappings(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    records: &PendingMappingRecords,
) {
    for rec in records.as_slice() {
        let _ = device_mmu.unmap_record(domain, *rec);
    }
}

fn build_scatter_segments_from_iova(
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
    iova_base: u64,
    segments: &mut [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
) -> Result<usize, DmaMapError> {
    let mut count = 0usize;
    let mut iova_cursor = iova_base;

    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        let Some(page_count) = covered_iommu_page_count(frames, frame_offset, byte_len) else {
            return Err(DmaMapError::InvalidSize);
        };

        append_segments_from_contiguous_iova(
            iova_cursor,
            frame_offset & (IOBUFFER_PAGE_SIZE - 1),
            byte_len,
            false,
            segments,
            &mut count,
        )?;

        iova_cursor = iova_cursor
            .checked_add((page_count * IOBUFFER_PAGE_SIZE) as u64)
            .ok_or(DmaMapError::InvalidSize)?;

        Ok(())
    })?;

    Ok(count)
}

fn append_segments_from_contiguous_iova(
    iova_base: u64,
    page_offset: usize,
    buffer_len: usize,
    merge_adjacent: bool,
    segments: &mut [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
    count: &mut usize,
) -> Result<(), DmaMapError> {
    if buffer_len == 0 {
        return Ok(());
    }

    if page_offset >= IOBUFFER_PAGE_SIZE {
        return Err(DmaMapError::InvalidSize);
    }

    let page_count = page_offset
        .checked_add(buffer_len)
        .ok_or(DmaMapError::InvalidSize)?
        .div_ceil(IOBUFFER_PAGE_SIZE);

    let mut remaining = buffer_len;

    for idx in 0..page_count {
        if remaining == 0 {
            break;
        }

        let start_in_page = if idx == 0 { page_offset } else { 0 };
        let bytes = remaining.min(IOBUFFER_PAGE_SIZE - start_in_page);
        let dma_addr = iova_base + (idx * IOBUFFER_PAGE_SIZE + start_in_page) as u64;

        append_dma_segment(dma_addr, bytes, merge_adjacent, segments, count)?;
        remaining -= bytes;
    }

    if remaining != 0 {
        return Err(DmaMapError::InvalidSize);
    }

    Ok(())
}

fn build_identity_segments(
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
    segments: &mut [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
) -> Result<usize, DmaMapError> {
    let mut count = 0usize;

    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        for_each_covered_data_run(frames, frame_offset, byte_len, |dma_addr, bytes| {
            append_dma_segment(dma_addr, bytes, true, segments, &mut count)
        })
    })?;

    Ok(count)
}

fn append_dma_segment(
    dma_addr: u64,
    byte_len: usize,
    merge_adjacent: bool,
    segments: &mut [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
    count: &mut usize,
) -> Result<(), DmaMapError> {
    if byte_len == 0 {
        return Ok(());
    }

    if byte_len > u32::MAX as usize {
        return Err(DmaMapError::InvalidSize);
    }

    if merge_adjacent && *count > 0 {
        let prev = &mut segments[*count - 1];
        let prev_end = prev.dma_addr + prev.byte_len as u64;
        let merged_len = prev.byte_len as usize + byte_len;

        if prev_end == dma_addr && merged_len <= u32::MAX as usize {
            prev.byte_len = merged_len as u32;
            return Ok(());
        }
    }

    if *count >= IOBUFFER_INLINE_SEGMENT_CAPACITY {
        return Err(DmaMapError::SegmentCapacityExceeded {
            required: *count + 1,
        });
    }

    segments[*count] = IoBufferDmaSegment {
        dma_addr,
        byte_len: byte_len as u32,
        reserved: 0,
    };

    *count += 1;

    Ok(())
}

fn align_up_u64(value: u64, align: u64) -> Result<u64, DmaMapError> {
    debug_assert!(align.is_power_of_two());

    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or(DmaMapError::InvalidSize)
}

fn manager() -> &'static DmaManager {
    DMA_MANAGER
        .get()
        .expect("DMA manager used before device-MMU initialization")
}

struct DmaManager {
    device_mmu: DeviceMmuSystem,
    state: Mutex<DmaManagerState>,
}

impl DmaManager {
    fn new() -> Self {
        Self {
            device_mmu: crate::platform::discover_required_device_mmu(
                crate::machine::machine_info(),
            ),
            state: Mutex::new(DmaManagerState::new()),
        }
    }

    fn register_pci_pdo(
        &self,
        pdo: &Arc<DeviceObject>,
        identity: DmaPciDeviceIdentity,
    ) -> DriverStatus {
        if compute_pci_requester_id(identity.bus, identity.device, identity.function)
            != identity.requester_id
        {
            return DriverStatus::InvalidParameter;
        }

        if (identity.flags & DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE) == 0 {
            return DriverStatus::InvalidParameter;
        }

        let key = device_key(pdo);
        let mut state = self.state.lock();

        state.devices.insert(
            key,
            Arc::new(RegisteredDmaDevice {
                pdo: Arc::downgrade(pdo),
                identity: RegisteredDmaIdentity::Pci(identity),
                runtime: Mutex::new(RegisteredDmaRuntime::new()),
            }),
        );

        DriverStatus::Success
    }
    fn register_platform_pdo(
        &self,
        pdo: &Arc<DeviceObject>,
        identity: DeviceMmuPlatformDeviceIdentity,
    ) -> DriverStatus {
        if identity.iommu_id_count == 0 {
            return DriverStatus::InvalidParameter;
        }

        let key = device_key(pdo);
        let mut state = self.state.lock();

        state.devices.insert(
            key,
            Arc::new(RegisteredDmaDevice {
                pdo: Arc::downgrade(pdo),
                identity: RegisteredDmaIdentity::Platform(identity),
                runtime: Mutex::new(RegisteredDmaRuntime::new()),
            }),
        );

        DriverStatus::Success
    }
    fn open_device_handle(
        &self,
        device: &Arc<DeviceObject>,
    ) -> Result<DmaDeviceHandle, DriverStatus> {
        let pdo = resolve_hardware_pdo(device)?;
        let key = device_key(&pdo);
        let state = self.state.lock();

        let Some(entry) = state.devices.get(&key) else {
            return Err(DriverStatus::NoSuchDevice);
        };

        if entry.pdo.upgrade().is_some() {
            Ok(DmaDeviceHandle(key as u64))
        } else {
            Err(DriverStatus::NoSuchDevice)
        }
    }

    fn query_device_state(&self, device: &Arc<DeviceObject>) -> Option<DmaDeviceState> {
        let pdo = resolve_hardware_pdo(device).ok()?;
        let key = device_key(&pdo);
        let state = self.state.lock();
        let entry = state.devices.get(&key)?.clone();

        if entry.pdo.upgrade().is_none() {
            return None;
        }

        let runtime = entry.runtime.lock();
        let domain = runtime.domain.as_ref();

        Some(DmaDeviceState {
            registered: 1,
            activated: if domain.is_some() { 1 } else { 0 },
            iommu_vendor: self.device_mmu.public_vendor_code(),
            reserved0: 0,
            remapper_index: domain
                .map(|domain| domain.translation_unit_index())
                .unwrap_or(u32::MAX),
            active_mappings: state
                .pending_unmaps
                .values()
                .filter(|pending| pending.device_key == key)
                .count() as u32,
            reserved1: 0,
            domain_id: domain.map(|domain| domain.domain_id()).unwrap_or(0),
        })
    }

    fn unregister_device(&self, device: &Arc<DeviceObject>) -> DriverStatus {
        let Ok(pdo) = resolve_hardware_pdo(device) else {
            return DriverStatus::NoSuchDevice;
        };

        let key = device_key(&pdo);

        let removed = {
            let mut state = self.state.lock();

            let Some(entry) = state.devices.get(&key).cloned() else {
                return DriverStatus::NoSuchDevice;
            };

            {
                let mut runtime = entry.runtime.lock();

                if runtime.unregistering || runtime.in_flight_maps != 0 {
                    return DriverStatus::InvalidParameter;
                }

                if state
                    .pending_unmaps
                    .values()
                    .any(|pending| pending.device_key == key)
                {
                    return DriverStatus::InvalidParameter;
                }

                runtime.unregistering = true;
            }

            state.devices.remove(&key)
        };

        let Some(entry) = removed else {
            return DriverStatus::NoSuchDevice;
        };

        let (domain, attachment) = {
            let mut runtime = entry.runtime.lock();

            let attachment = runtime.attachment.take();
            let domain = runtime.domain.take();

            (domain, attachment)
        };

        if let Some(domain) = domain {
            if let Some(attachment) = attachment {
                self.device_mmu.detach_device(&domain, attachment);
            }

            self.device_mmu.destroy_domain(&domain);
        }

        DriverStatus::Success
    }

    fn begin_mapping(&self, key: usize) -> Result<ActiveDmaMapping, DmaMapError> {
        let registration = {
            let state = self.state.lock();
            state
                .devices
                .get(&key)
                .cloned()
                .ok_or(DmaMapError::NoIommu)?
        };

        let pdo = registration.pdo.upgrade().ok_or(DmaMapError::NoIommu)?;
        let domain = {
            let mut runtime = registration.runtime.lock();

            if runtime.unregistering {
                return Err(DmaMapError::NoIommu);
            }

            if runtime.domain.is_none() {
                let identity = registration.identity.device_mmu_identity();

                let domain = self
                    .device_mmu
                    .create_domain(identity)
                    .map_err(map_device_mmu_error)?;

                let attachment = match self.device_mmu.attach_device(&domain, identity) {
                    Ok(attachment) => attachment,
                    Err(err) => {
                        self.device_mmu.destroy_domain(&domain);
                        return Err(map_device_mmu_error(err));
                    }
                };

                runtime.domain = Some(domain);
                runtime.attachment = Some(attachment);
            }

            runtime.in_flight_maps = runtime
                .in_flight_maps
                .checked_add(1)
                .ok_or(DmaMapError::InvalidSize)?;

            runtime.domain.as_ref().unwrap().clone()
        };

        Ok(ActiveDmaMapping {
            pdo,
            domain,
            _guard: InFlightMapGuard { registration },
        })
    }

    fn alloc_cookie(&self) -> u64 {
        let mut state = self.state.lock();
        let cookie = state.next_cookie;
        state.next_cookie = state.next_cookie.wrapping_add(1);
        cookie
    }

    fn insert_pending_unmap(&self, cookie: u64, pending: PendingUnmap) {
        self.state.lock().pending_unmaps.insert(cookie, pending);
    }

    fn remove_pending_unmap(&self, cookie: u64) -> Option<PendingUnmap> {
        self.state.lock().pending_unmaps.remove(&cookie)
    }
}

struct DmaManagerState {
    devices: BTreeMap<usize, Arc<RegisteredDmaDevice>>,
    pending_unmaps: BTreeMap<u64, PendingUnmap>,
    next_cookie: u64,
}

impl DmaManagerState {
    fn new() -> Self {
        Self {
            devices: BTreeMap::new(),
            pending_unmaps: BTreeMap::new(),
            next_cookie: 1,
        }
    }
}

struct RegisteredDmaDevice {
    pdo: Weak<DeviceObject>,
    identity: RegisteredDmaIdentity,
    runtime: Mutex<RegisteredDmaRuntime>,
}

struct RegisteredDmaRuntime {
    domain: Option<Arc<DeviceMmuDomain>>,
    attachment: Option<DeviceMmuAttachment>,
    unregistering: bool,
    in_flight_maps: usize,
}

impl RegisteredDmaRuntime {
    fn new() -> Self {
        Self {
            domain: None,
            attachment: None,
            unregistering: false,
            in_flight_maps: 0,
        }
    }
}

#[derive(Clone, Copy)]
enum RegisteredDmaIdentity {
    Pci(DmaPciDeviceIdentity),
    Platform(DeviceMmuPlatformDeviceIdentity),
}

impl RegisteredDmaIdentity {
    fn device_mmu_identity(self) -> DeviceMmuDeviceIdentity {
        match self {
            Self::Pci(identity) => DeviceMmuDeviceIdentity::Pci(identity),
            Self::Platform(identity) => DeviceMmuDeviceIdentity::Platform(identity),
        }
    }
}

struct ActiveDmaMapping {
    pdo: Arc<DeviceObject>,
    domain: Arc<DeviceMmuDomain>,
    _guard: InFlightMapGuard,
}

struct InFlightMapGuard {
    registration: Arc<RegisteredDmaDevice>,
}

impl Drop for InFlightMapGuard {
    fn drop(&mut self) {
        let mut runtime = self.registration.runtime.lock();
        runtime.in_flight_maps = runtime.in_flight_maps.saturating_sub(1);
    }
}

#[derive(Clone)]
struct PendingMappingRecords {
    records: [MappingRecord; IOBUFFER_MAX_PAGE_CAPACITY],
    len: usize,
}

impl PendingMappingRecords {
    fn new() -> Self {
        Self {
            records: [EMPTY_MAPPING_RECORD; IOBUFFER_MAX_PAGE_CAPACITY],
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_slice(&self) -> &[MappingRecord] {
        &self.records[..self.len]
    }

    fn push(&mut self, rec: MappingRecord) -> Result<(), DmaMapError> {
        if self.len >= IOBUFFER_MAX_PAGE_CAPACITY {
            return Err(DmaMapError::PageCapacityExceeded {
                required: self.len + 1,
            });
        }

        self.records[self.len] = rec;
        self.len += 1;

        Ok(())
    }

    fn push_or_extend_identity(
        &mut self,
        iova_base: u64,
        page_count: usize,
    ) -> Result<(), DmaMapError> {
        let page_count_u32 = u32::try_from(page_count).map_err(|_| DmaMapError::InvalidSize)?;

        if let Some(prev) = self.records[..self.len].last_mut() {
            let prev_end = prev.iova_base + prev.page_count as u64 * IOBUFFER_PAGE_SIZE as u64;
            let combined = prev.page_count as u64 + page_count_u32 as u64;

            if prev.is_identity && prev_end == iova_base && combined <= u32::MAX as u64 {
                prev.page_count = combined as u32;
                return Ok(());
            }
        }

        self.push(MappingRecord {
            iova_base,
            page_count: page_count_u32,
            is_identity: true,
        })
    }
}

const EMPTY_MAPPING_RECORD: MappingRecord = MappingRecord {
    iova_base: 0,
    page_count: 0,
    is_identity: false,
};

struct PendingUnmap {
    device_key: usize,
    domain: Arc<DeviceMmuDomain>,
    records: PendingMappingRecords,
}

fn resolve_hardware_pdo(device: &Arc<DeviceObject>) -> Result<Arc<DeviceObject>, DriverStatus> {
    let Some(devnode_weak) = device.dev_node.get() else {
        return Err(DriverStatus::NoSuchDevice);
    };

    let Some(devnode) = devnode_weak.upgrade() else {
        return Err(DriverStatus::NoSuchDevice);
    };

    devnode.get_pdo().ok_or(DriverStatus::NoSuchDevice)
}

fn device_key(device: &Arc<DeviceObject>) -> usize {
    Arc::as_ptr(device) as usize
}

fn compute_pci_requester_id(bus: u8, device: u8, function: u8) -> u16 {
    ((bus as u16) << 8) | ((device as u16) << 3) | function as u16
}
