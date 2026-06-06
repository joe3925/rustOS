// TODO(rustos-iommu-dma): Follow-up work remaining after initial bring-up.
//
// High-priority correctness:
// - Track and validate mapping ownership more strictly (cookie/device/domain consistency,
//   stale-cookie behavior, and domain teardown ordering).
// - Add explicit detach/cleanup behavior for device unregister and domain lifetime
//   (including IOMMU-side detach where required by backend).
//
// IOMMU semantics / hardware completeness:
// - Respect ACPI reserved regions (RMRR/IVMD) and enforce mapping restrictions.
// - Add Intel/AMD fault/event reporting integration into kernel diagnostics.
// - Evaluate per-range/page-selective invalidation instead of always domain-wide invalidation.
//
// DMA policy and feature completeness:
// - Enforce per-device DMA constraints (DMA mask width, segment boundary constraints,
//   max segment count/size policies).
// - Implement bounce-buffer or remap fallback paths when direct mapping cannot satisfy
//   device constraints.
//
// API / observability:
// - Surface richer error distinctions (translation failure vs IOVA exhaustion vs HW fault).
// - Add mapping/unmapping counters and per-device/domain telemetry for debugging.
// - Decide whether to use `IommuDomain.mappings` for validation/accounting, or remove it
//   if state is fully managed by `pending_unmaps`.
//
// Test coverage:
// - Add unit/integration tests for all mapping strategies with:
//   - aligned/unaligned buffers
//   - multi-page and max-inline-page cases
//   - fragmentation-heavy identity scenarios
//   - map failure rollback correctness
//   - unregister while mappings are live
// - Add backend-specific tests for Intel VT-d and AMD-Vi invalidation behavior.
//
use crate::drivers::pnp::device::DevNodeExt;
use crate::drivers::ACPI::{ACPIImpl, ACPI_TABLES};
use acpi::sdt::{SdtHeader, Signature};
use acpi::{AcpiHandler, AcpiTable, AcpiTables, PhysicalMapping};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::size_of;
use kernel_types::device::DeviceObject;
use kernel_types::dma::{
    BorrowedDmaMapping, DmaDeviceHandle, DmaDeviceState, DmaMapError, DmaMapped,
    DmaMappingStrategy, DmaPciDeviceIdentity, IoBuffer, IoBufferDmaSegment, IoBufferPageFrame,
    PhysFramed, ToDevice,
    DMA_IOMMU_VENDOR_AMD_IVRS, DMA_IOMMU_VENDOR_INTEL_DMAR,
    DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE, IOBUFFER_INLINE_SEGMENT_CAPACITY,
    IOBUFFER_MAX_PAGE_CAPACITY, IOBUFFER_PAGE_SIZE,
};
use kernel_types::status::DriverStatus;
use raw_cpuid::CpuId;
use spin::{Mutex, Once};

use crate::memory::iommu::{self, IommuDomain, MappingRecord};

static DMA_MANAGER: Once<DmaManager> = Once::new();

enum PendingDmaSegments {
    Contiguous {
        dma_addr: u64,
        byte_len: usize,
    },
    PageChunks {
        iova_base: u64,
        page_offset: usize,
        byte_len: usize,
    },
    FixedChunks {
        dma_addr: u64,
        chunk_len: usize,
        count: usize,
    },
    Identity {
        frame_offset: usize,
        byte_len: usize,
    },
}

pub fn init_dma_manager() {
    let _ = DMA_MANAGER.call_once(DmaManager::new);
}

pub fn register_pci_pdo(pdo: &Arc<DeviceObject>, identity: DmaPciDeviceIdentity) -> DriverStatus {
    manager().register_pci_pdo(pdo, identity)
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

pub fn platform_iommu_info() -> &'static PlatformIommuInfo {
    manager().platform.as_ref()
}

// ---------------------------------------------------------------------------
// IoBuffer mapping
// ---------------------------------------------------------------------------

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

    let mut state = m.state.lock();
    let Some(entry) = state.devices.get_mut(&key) else {
        return Err((buffer, DmaMapError::NoIommu));
    };
    let Some(pdo) = entry.pdo.upgrade() else {
        return Err((buffer, DmaMapError::NoIommu));
    };

    let domain = if let Some(domain) = entry.domain.as_ref() {
        domain.clone()
    } else {
        let identity = match entry.identity {
            RegisteredDmaIdentity::Pci(id) => id,
        };
        let Some(domain) = iommu::get_or_create_domain(key, identity) else {
            return Err((buffer, DmaMapError::NoIommu));
        };
        entry.domain = Some(domain.clone());
        domain
    };

    let prepared = match prepare_dma_mapping(&domain, &buffer, strategy) {
        Ok(prepared) => prepared,
        Err(err) => return Err((buffer, err)),
    };

    if prepared.records.is_empty() {
        return Err((buffer, DmaMapError::RemappingUnavailable));
    }

    let cookie = state.next_cookie;
    let mapped_buffer = match buffer.apply_dma_mapping(
        &prepared.segments[..prepared.segments_len],
        pdo,
        unmap_trampoline,
        cookie as usize,
    ) {
        Ok(mapped_buffer) => mapped_buffer,
        Err((buffer, err)) => {
            rollback_mappings(&domain, &prepared.records);
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

    state.next_cookie = state.next_cookie.wrapping_add(1);
    state.pending_unmaps.insert(
        cookie,
        PendingUnmap {
            device_key: key,
            domain: domain.clone(),
            records: prepared.records,
        },
    );

    iommu::invalidate(&domain);
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

    let mut state = m.state.lock();
    let Some(entry) = state.devices.get_mut(&key) else {
        return Err(DmaMapError::NoIommu);
    };
    let Some(pdo) = entry.pdo.upgrade() else {
        return Err(DmaMapError::NoIommu);
    };

    let domain = if let Some(domain) = entry.domain.as_ref() {
        domain.clone()
    } else {
        let identity = match entry.identity {
            RegisteredDmaIdentity::Pci(id) => id,
        };
        let Some(domain) = iommu::get_or_create_domain(key, identity) else {
            return Err(DmaMapError::NoIommu);
        };
        entry.domain = Some(domain.clone());
        domain
    };

    let prepared = prepare_dma_mapping(&domain, buffer, strategy)?;

    if prepared.records.is_empty() {
        return Err(DmaMapError::RemappingUnavailable);
    }

    let cookie = state.next_cookie;
    let mapping = match BorrowedDmaMapping::new(
        &prepared.segments[..prepared.segments_len],
        pdo,
        unmap_trampoline,
        cookie as usize,
    ) {
        Ok(mapping) => mapping,
        Err(kernel_types::dma::IoBufferError::SegmentCapacityExceeded { required, .. }) => {
            rollback_mappings(&domain, &prepared.records);
            return Err(DmaMapError::SegmentCapacityExceeded { required });
        }
        Err(kernel_types::dma::IoBufferError::PageCapacityExceeded { required, .. }) => {
            rollback_mappings(&domain, &prepared.records);
            return Err(DmaMapError::PageCapacityExceeded { required });
        }
        Err(_) => {
            rollback_mappings(&domain, &prepared.records);
            return Err(DmaMapError::InvalidSize);
        }
    };

    state.next_cookie = state.next_cookie.wrapping_add(1);
    state.pending_unmaps.insert(
        cookie,
        PendingUnmap {
            device_key: key,
            domain: domain.clone(),
            records: prepared.records,
        },
    );

    iommu::invalidate(&domain);
    Ok(mapping)
}

fn prepare_dma_mapping(
    domain: &IommuDomain,
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

            if let Err(err) = map_buffer_frames_to_iova(domain, iova_base, buffer) {
                rollback_mappings(domain, &records);
                return Err(err);
            }

            let Some(page_offset) = first_dma_page_offset(buffer) else {
                rollback_mappings(domain, &records);
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

            if let Err(err) = map_buffer_frames_to_iova(domain, iova_base, buffer) {
                rollback_mappings(domain, &records);
                return Err(err);
            }

            match build_scatter_segments_from_iova(buffer, iova_base, &mut segments) {
                Ok(len) => len,
                Err(err) => {
                    rollback_mappings(domain, &records);
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

            if let Err(err) = map_buffer_frames_to_iova(domain, iova_base, buffer) {
                rollback_mappings(domain, &records);
                return Err(err);
            }

            let Some(page_offset) = first_dma_page_offset(buffer) else {
                rollback_mappings(domain, &records);
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
            if let Err(err) = map_identity_frames(domain, buffer, &mut records) {
                rollback_mappings(domain, &records);
                return Err(err);
            }

            match build_identity_segments(buffer, &mut segments) {
                Ok(len) => len,
                Err(err) => {
                    rollback_mappings(domain, &records);
                    return Err(err);
                }
            }
        }
    };

    if segments_len == 0 || records.is_empty() {
        rollback_mappings(domain, &records);
        return Err(DmaMapError::RemappingUnavailable);
    }

    Ok(PreparedDmaMapping {
        records,
        segments,
        segments_len,
    })
}

extern "win64" fn unmap_trampoline(_device: &Arc<DeviceObject>, cookie: usize) {
    let m = manager();
    let mut state = m.state.lock();
    let Some(pending) = state.pending_unmaps.remove(&(cookie as u64)) else {
        return;
    };
    for rec in pending.records.as_slice() {
        unmap_record(&pending.domain, *rec);
    }
}

fn map_iommu_error(err: iommu::IommuError) -> DmaMapError {
    match err {
        iommu::IommuError::NoBackingFrame | iommu::IommuError::IovaSpaceExhausted => {
            DmaMapError::RemappingUnavailable
        }
        iommu::IommuError::NotMapped
        | iommu::IommuError::HardwareError
        | iommu::IommuError::Unsupported => DmaMapError::NoIommu,
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
    domain: &IommuDomain,
    iova_base: u64,
    phys_base: u64,
    page_count: usize,
) -> Result<(), DmaMapError> {
    let mut pfns = [0u64; IOBUFFER_MAX_PAGE_CAPACITY];
    let mut mapped = 0usize;

    while mapped < page_count {
        let chunk_pages = (page_count - mapped).min(IOBUFFER_MAX_PAGE_CAPACITY);
        for (idx, pfn) in pfns[..chunk_pages].iter_mut().enumerate() {
            *pfn = (phys_base + ((mapped + idx) * IOBUFFER_PAGE_SIZE) as u64) >> 12;
        }
        iommu::map_pages(
            domain,
            iova_base + (mapped * IOBUFFER_PAGE_SIZE) as u64,
            &pfns[..chunk_pages],
        )
        .map_err(map_iommu_error)?;
        mapped += chunk_pages;
    }

    Ok(())
}

fn map_buffer_frames_to_iova(
    domain: &IommuDomain,
    iova_base: u64,
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
) -> Result<(), DmaMapError> {
    let mut iova_cursor = iova_base;

    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        for_each_covered_page_run(frames, frame_offset, byte_len, |phys_base, page_count| {
            map_phys_run_to_iova(domain, iova_cursor, phys_base, page_count)?;
            iova_cursor = iova_cursor
                .checked_add((page_count * IOBUFFER_PAGE_SIZE) as u64)
                .ok_or(DmaMapError::InvalidSize)?;
            Ok(())
        })
    })
}

fn map_identity_frames(
    domain: &IommuDomain,
    buffer: &IoBuffer<'_, PhysFramed, ToDevice>,
    records: &mut PendingMappingRecords,
) -> Result<(), DmaMapError> {
    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        for_each_covered_page_run(frames, frame_offset, byte_len, |phys_base, page_count| {
            records.push_or_extend_identity(phys_base, page_count)?;
            map_phys_run_to_iova(domain, phys_base, phys_base, page_count)
        })
    })
}

fn unmap_record(domain: &IommuDomain, rec: MappingRecord) {
    iommu::unmap_pages(domain, rec.iova_base, rec.page_count);
    if !rec.is_identity {
        domain.free_iova(
            rec.iova_base,
            rec.page_count as u64 * IOBUFFER_PAGE_SIZE as u64,
        );
    }
}

fn rollback_mappings(domain: &IommuDomain, records: &PendingMappingRecords) {
    for rec in records.as_slice() {
        unmap_record(domain, *rec);
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

fn build_segments_from_contiguous_iova(
    iova_base: u64,
    page_offset: usize,
    buffer_len: usize,
    merge_adjacent: bool,
    segments: &mut [IoBufferDmaSegment; IOBUFFER_INLINE_SEGMENT_CAPACITY],
) -> Result<usize, DmaMapError> {
    let mut count = 0usize;
    append_segments_from_contiguous_iova(
        iova_base,
        page_offset,
        buffer_len,
        merge_adjacent,
        segments,
        &mut count,
    )?;
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
        .expect("DMA manager used before early IOMMU initialization")
}

struct DmaManager {
    platform: Arc<PlatformIommuInfo>,
    state: Mutex<DmaManagerState>,
}

impl DmaManager {
    fn new() -> Self {
        let tables = ACPI_TABLES.get_tables();
        let platform = Arc::new(discover_platform_iommu(tables.as_ref()));
        Self {
            platform,
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
            RegisteredDmaDevice {
                pdo: Arc::downgrade(pdo),
                identity: RegisteredDmaIdentity::Pci(identity),
                domain: None,
            },
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
        if let Some(entry) = state.devices.get(&key) {
            if entry.pdo.upgrade().is_some() {
                return Ok(DmaDeviceHandle(key as u64));
            }
        }
        Err(DriverStatus::NoSuchDevice)
    }
}
impl DmaManager {
    fn query_device_state(&self, device: &Arc<DeviceObject>) -> Option<DmaDeviceState> {
        let pdo = resolve_hardware_pdo(device).ok()?;
        let key = device_key(&pdo);
        let state = self.state.lock();
        let entry = state.devices.get(&key)?;
        if entry.pdo.upgrade().is_none() {
            return None;
        }
        Some(DmaDeviceState {
            registered: 1,
            activated: if entry.domain.is_some() { 1 } else { 0 },
            iommu_vendor: self.platform.vendor_code(),
            reserved0: 0,
            remapper_index: entry
                .domain
                .as_ref()
                .map(|domain| domain.remapper_index)
                .unwrap_or(u32::MAX),
            active_mappings: state
                .pending_unmaps
                .values()
                .filter(|pending| pending.device_key == key)
                .count() as u32,
            reserved1: 0,
            domain_id: entry
                .domain
                .as_ref()
                .map(|domain| domain.domain_id as u64)
                .unwrap_or(0),
        })
    }

    fn unregister_device(&self, device: &Arc<DeviceObject>) -> DriverStatus {
        let Ok(pdo) = resolve_hardware_pdo(device) else {
            return DriverStatus::NoSuchDevice;
        };
        let key = device_key(&pdo);
        let mut state = self.state.lock();
        state.devices.remove(&key);
        DriverStatus::Success
    }
}

struct DmaManagerState {
    devices: BTreeMap<usize, RegisteredDmaDevice>,
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
    domain: Option<Arc<IommuDomain>>,
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
    domain: Arc<IommuDomain>,
    records: PendingMappingRecords,
}

#[derive(Clone, Copy)]
enum RegisteredDmaIdentity {
    Pci(DmaPciDeviceIdentity),
}

#[derive(Debug)]
pub enum PlatformIommuInfo {
    Intel(IntelPlatformIommuInfo),
    Amd(AmdPlatformIommuInfo),
}

impl PlatformIommuInfo {
    fn vendor_code(&self) -> u8 {
        match self {
            PlatformIommuInfo::Intel(_) => DMA_IOMMU_VENDOR_INTEL_DMAR,
            PlatformIommuInfo::Amd(_) => DMA_IOMMU_VENDOR_AMD_IVRS,
        }
    }
}

#[derive(Debug)]
pub struct IntelPlatformIommuInfo {
    pub host_address_width: u8,
    pub flags: u8,
    pub remapper_units: Vec<IntelRemapperUnit>,
    pub reserved_regions: Vec<IntelReservedRegion>,
}

#[derive(Debug)]
pub struct IntelRemapperUnit {
    pub segment: u16,
    pub register_base: u64,
    pub flags: u8,
    pub include_all: bool,
    pub proximity_domain: Option<u32>,
    pub device_scopes: Vec<IntelDeviceScope>,
}

#[derive(Debug, Clone)]
pub struct IntelReservedRegion {
    pub segment: u16,
    pub base_address: u64,
    pub limit_address: u64,
    pub allow_all: bool,
    pub device_scopes: Vec<IntelDeviceScope>,
}

#[derive(Debug, Clone)]
pub struct IntelDeviceScope {
    pub scope_type: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    pub path: Vec<IntelPciPath>,
}

#[derive(Debug, Clone, Copy)]
pub struct IntelPciPath {
    pub device: u8,
    pub function: u8,
}

#[derive(Debug)]
pub struct AmdPlatformIommuInfo {
    pub ivinfo_raw: u32,
    pub efr_supported: bool,
    pub dma_guard_opt_in: bool,
    pub guest_virtual_address_size: u8,
    pub physical_address_size: u8,
    pub virtual_address_size: u8,
    pub ht_ats_reserved: bool,
    pub remapper_units: Vec<AmdRemapperUnit>,
    pub reserved_regions: Vec<AmdReservedRegion>,
}

#[derive(Debug)]
pub struct AmdRemapperUnit {
    pub block_type: u8,
    pub flags: u8,
    pub device_id: u16,
    pub capability_offset: u16,
    pub register_base: u64,
    pub segment: u16,
    pub unit_info: u16,
    pub feature_reporting: u32,
    pub efr_image: Option<u64>,
    pub device_entries: Vec<AmdIvhdDeviceEntry>,
}

#[derive(Debug)]
pub struct AmdReservedRegion {
    pub block_type: u8,
    pub flags: u8,
    pub segment: u16,
    pub requester_id_start: Option<u16>,
    pub requester_id_end: Option<u16>,
    pub applies_to_all: bool,
    pub base_address: u64,
    pub limit_address: u64,
}

#[derive(Debug, Clone)]
pub enum AmdIvhdDeviceEntry {
    Pad4,
    All {
        settings: u8,
    },
    Select {
        requester_id: u16,
        settings: u8,
    },
    StartRange {
        requester_id: u16,
        settings: u8,
    },
    EndRange {
        requester_id: u16,
        settings: u8,
    },
    Pad8,
    AliasSelect {
        requester_id: u16,
        settings: u8,
        used_id: u16,
    },
    AliasStartRange {
        requester_id: u16,
        settings: u8,
        used_id: u16,
    },
    ExtSelect {
        requester_id: u16,
        settings: u8,
        extended_data: u32,
    },
    ExtStartRange {
        requester_id: u16,
        settings: u8,
        extended_data: u32,
    },
    Special {
        requester_id: u16,
        settings: u8,
        handle: u8,
        used_id: u16,
        variety: u8,
    },
    AcpiHid {
        requester_id: u16,
        settings: u8,
        hardware_id: u64,
        compatible_id: u64,
        uid_type: u8,
        uid_length: u8,
    },
    Unknown {
        entry_type: u8,
        raw: Vec<u8>,
    },
}
fn discover_platform_iommu(tables: &AcpiTables<ACPIImpl>) -> PlatformIommuInfo {
    match detect_boot_iommu_vendor() {
        BootIommuVendor::Intel => PlatformIommuInfo::Intel(parse_intel_dmar(tables)),
        BootIommuVendor::Amd => PlatformIommuInfo::Amd(parse_amd_ivrs(tables)),
        BootIommuVendor::Unknown => {
            if has_table::<DmarTable>(tables) {
                PlatformIommuInfo::Intel(parse_intel_dmar(tables))
            } else if has_table::<IvrsTable>(tables) {
                PlatformIommuInfo::Amd(parse_amd_ivrs(tables))
            } else {
                panic!("mandatory IOMMU policy: neither DMAR nor IVRS is present")
            }
        }
    }
}

fn parse_intel_dmar(tables: &AcpiTables<ACPIImpl>) -> IntelPlatformIommuInfo {
    let table = require_table::<DmarTable>(tables, "DMAR");
    let bytes = table_bytes(&table);
    let payload = bytes
        .get(size_of::<DmarTable>()..)
        .expect("DMAR payload is truncated");

    let host_address_width = table.width;
    let flags = table.flags;
    let mut remapper_units = Vec::new();
    let mut reserved_regions = Vec::new();
    let mut affinities = Vec::new();

    let mut offset = 0usize;
    while offset < payload.len() {
        if offset + size_of::<DmarSubtableHeader>() > payload.len() {
            panic!("DMAR subtable header is truncated");
        }

        let header = read_packed::<DmarSubtableHeader>(payload, offset);
        let length = header.length as usize;
        if length < size_of::<DmarSubtableHeader>() || offset + length > payload.len() {
            panic!("DMAR subtable length is invalid");
        }

        let subtable = &payload[offset..offset + length];
        match header.subtable_type {
            DMAR_TYPE_HARDWARE_UNIT => {
                if length < size_of::<DmarHardwareUnit>() {
                    panic!("DMAR hardware unit is too short");
                }
                let unit = read_packed::<DmarHardwareUnit>(payload, offset);
                let scopes = parse_intel_device_scopes(&subtable[size_of::<DmarHardwareUnit>()..]);
                remapper_units.push(IntelRemapperUnit {
                    segment: unit.segment,
                    register_base: unit.address,
                    flags: unit.flags,
                    include_all: (unit.flags & DMAR_INCLUDE_ALL) != 0,
                    proximity_domain: None,
                    device_scopes: scopes,
                });
            }
            DMAR_TYPE_RESERVED_MEMORY => {
                if length < size_of::<DmarReservedMemory>() {
                    panic!("DMAR reserved memory structure is too short");
                }
                let reserved = read_packed::<DmarReservedMemory>(payload, offset);
                let scopes =
                    parse_intel_device_scopes(&subtable[size_of::<DmarReservedMemory>()..]);
                if reserved.end_address < reserved.base_address {
                    panic!("DMAR reserved region has an inverted address range");
                }
                reserved_regions.push(IntelReservedRegion {
                    segment: reserved.segment,
                    base_address: reserved.base_address,
                    limit_address: reserved.end_address,
                    allow_all: (reserved.flags & DMAR_ALLOW_ALL) != 0,
                    device_scopes: scopes,
                });
            }
            DMAR_TYPE_HARDWARE_AFFINITY => {
                if length < size_of::<DmarHardwareAffinity>() {
                    panic!("DMAR hardware affinity structure is too short");
                }
                let affinity = read_packed::<DmarHardwareAffinity>(payload, offset);
                affinities.push((affinity.base_address, affinity.proximity_domain));
            }
            _ => {}
        }

        offset += length;
    }

    if remapper_units.is_empty() {
        panic!("mandatory IOMMU policy: DMAR contains no remapping hardware units");
    }

    for unit in remapper_units.iter_mut() {
        if let Some((_, proximity_domain)) = affinities
            .iter()
            .find(|(base, _)| *base == unit.register_base)
        {
            unit.proximity_domain = Some(*proximity_domain);
        }
    }

    IntelPlatformIommuInfo {
        host_address_width,
        flags,
        remapper_units,
        reserved_regions,
    }
}

fn parse_amd_ivrs(tables: &AcpiTables<ACPIImpl>) -> AmdPlatformIommuInfo {
    let table = require_table::<IvrsTable>(tables, "IVRS");
    let bytes = table_bytes(&table);
    let payload = bytes
        .get(size_of::<IvrsTable>()..)
        .expect("IVRS payload is truncated");

    let info = table.info;
    let target_ivhd_type = select_amd_ivhd_type(payload);
    let mut remapper_units = Vec::new();
    let mut reserved_regions = Vec::new();

    let mut offset = 0usize;
    while offset < payload.len() {
        if offset + size_of::<IvrsHeader>() > payload.len() {
            panic!("IVRS block header is truncated");
        }

        let header = read_packed::<IvrsHeader>(payload, offset);
        let length = header.length as usize;
        if length < size_of::<IvrsHeader>() || offset + length > payload.len() {
            panic!("IVRS block length is invalid");
        }

        let block = &payload[offset..offset + length];
        match header.block_type {
            IVRS_TYPE_HARDWARE_10 | IVRS_TYPE_HARDWARE_11 | IVRS_TYPE_HARDWARE_40 => {
                if header.block_type != target_ivhd_type {
                    offset += length;
                    continue;
                }

                if length < IVRS_HARDWARE_MIN_LENGTH {
                    panic!("IVRS hardware block is too short");
                }

                let capability_offset = read_u16(block, 6);
                let register_base = read_u64(block, 8);
                let segment = read_u16(block, 16);
                let unit_info = read_u16(block, 18);
                let feature_reporting = if length >= 24 { read_u32(block, 20) } else { 0 };
                if (feature_reporting & IVHD_ATTR_HATDIS) != 0 {
                    panic!(
                        "iommu: AMD IVRS reports host DMA translation disabled for remapper at {:#x}; if using QEMU, pass -device amd-iommu,dma-translation=on,dma-remap=on",
                        register_base
                    );
                }
                let (efr_image, device_entries_offset) =
                    if header.block_type == IVRS_TYPE_HARDWARE_10 {
                        (None, 24usize)
                    } else {
                        if length < 40 {
                            panic!("extended IVRS hardware block is too short");
                        }
                        (Some(read_u64(block, 24)), 40usize)
                    };

                let device_entries = parse_amd_device_entries(
                    block
                        .get(device_entries_offset..)
                        .expect("IVRS device entries are truncated"),
                );

                remapper_units.push(AmdRemapperUnit {
                    block_type: header.block_type,
                    flags: header.flags,
                    device_id: header.device_id,
                    capability_offset,
                    register_base,
                    segment,
                    unit_info,
                    feature_reporting,
                    efr_image,
                    device_entries,
                });
            }
            IVRS_TYPE_MEMORY_ALL | IVRS_TYPE_MEMORY_SPECIFIED | IVRS_TYPE_MEMORY_RANGE => {
                if length < size_of::<IvrsMemoryBlock>() {
                    panic!("IVRS memory definition block is too short");
                }
                let memory = read_packed::<IvrsMemoryBlock>(payload, offset);
                if memory.memory_length == 0 {
                    panic!("IVRS memory definition block has zero length");
                }
                let limit_address = memory
                    .start_address
                    .checked_add(memory.memory_length - 1)
                    .expect("IVRS memory definition range overflowed");
                let (applies_to_all, requester_id_start, requester_id_end) = match header.block_type
                {
                    IVRS_TYPE_MEMORY_ALL => (true, None, None),
                    IVRS_TYPE_MEMORY_SPECIFIED => {
                        (false, Some(header.device_id), Some(header.device_id))
                    }
                    IVRS_TYPE_MEMORY_RANGE => {
                        (false, Some(header.device_id), Some(memory.aux_data))
                    }
                    _ => unreachable!(),
                };

                reserved_regions.push(AmdReservedRegion {
                    block_type: header.block_type,
                    flags: header.flags,
                    segment: 0,
                    requester_id_start,
                    requester_id_end,
                    applies_to_all,
                    base_address: memory.start_address,
                    limit_address,
                });
            }
            _ => {}
        }

        offset += length;
    }

    if remapper_units.is_empty() {
        panic!("mandatory IOMMU policy: IVRS contains no IVHD remapper blocks");
    }

    AmdPlatformIommuInfo {
        ivinfo_raw: info,
        efr_supported: (info & 0x1) != 0,
        dma_guard_opt_in: (info & 0x2) != 0,
        guest_virtual_address_size: ((info >> 5) & 0x7) as u8,
        physical_address_size: ((info >> 8) & 0x7f) as u8,
        virtual_address_size: ((info >> 15) & 0x7f) as u8,
        ht_ats_reserved: (info & (1 << 22)) != 0,
        remapper_units,
        reserved_regions,
    }
}

// Linux selects one IVHD type for the whole IVRS walk so compatibility
// blocks describing the same physical IOMMU do not get instantiated twice.
fn select_amd_ivhd_type(payload: &[u8]) -> u8 {
    let mut offset = 0usize;
    let mut target_device_id = None;
    let mut target_ivhd_type = None;

    while offset < payload.len() {
        if offset + size_of::<IvrsHeader>() > payload.len() {
            panic!("IVRS block header is truncated");
        }

        let header = read_packed::<IvrsHeader>(payload, offset);
        let length = header.length as usize;
        if length < size_of::<IvrsHeader>() || offset + length > payload.len() {
            panic!("IVRS block length is invalid");
        }

        match header.block_type {
            IVRS_TYPE_HARDWARE_10 | IVRS_TYPE_HARDWARE_11 | IVRS_TYPE_HARDWARE_40 => {
                let device_id = *target_device_id.get_or_insert(header.device_id);
                if header.device_id == device_id {
                    target_ivhd_type = Some(match target_ivhd_type {
                        Some(existing) if existing > header.block_type => existing,
                        _ => header.block_type,
                    });
                }
            }
            _ => {}
        }

        offset += length;
    }

    target_ivhd_type.unwrap_or(IVRS_TYPE_HARDWARE_10)
}

fn parse_intel_device_scopes(bytes: &[u8]) -> Vec<IntelDeviceScope> {
    let mut scopes = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if offset + size_of::<DmarDeviceScopeHeader>() > bytes.len() {
            panic!("DMAR device scope header is truncated");
        }
        let header = read_packed::<DmarDeviceScopeHeader>(bytes, offset);
        let length = header.length as usize;
        if length < size_of::<DmarDeviceScopeHeader>() || offset + length > bytes.len() {
            panic!("DMAR device scope length is invalid");
        }

        let path_bytes = &bytes[offset + size_of::<DmarDeviceScopeHeader>()..offset + length];
        if (path_bytes.len() % size_of::<DmarPciPath>()) != 0 {
            panic!("DMAR device scope path is malformed");
        }

        let mut path = Vec::with_capacity(path_bytes.len() / size_of::<DmarPciPath>());
        let mut path_offset = 0usize;
        while path_offset < path_bytes.len() {
            let step = read_packed::<DmarPciPath>(path_bytes, path_offset);
            path.push(IntelPciPath {
                device: step.device,
                function: step.function,
            });
            path_offset += size_of::<DmarPciPath>();
        }

        scopes.push(IntelDeviceScope {
            scope_type: header.entry_type,
            enumeration_id: header.enumeration_id,
            start_bus: header.bus,
            path,
        });
        offset += length;
    }

    scopes
}

fn parse_amd_device_entries(bytes: &[u8]) -> Vec<AmdIvhdDeviceEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if offset + IVRS_DEVICE_ENTRY_MIN_LENGTH > bytes.len() {
            panic!("IVRS device entry header is truncated");
        }

        let entry_type = bytes[offset];
        let entry_length = amd_device_entry_length(entry_type);
        if offset + entry_length > bytes.len() {
            panic!("IVRS device entry overruns its IVHD block");
        }

        let requester_id = read_u16(bytes, offset + 1);
        let settings = bytes[offset + 3];
        let entry = match entry_type {
            IVRS_DEVICE_PAD4 => AmdIvhdDeviceEntry::Pad4,
            IVRS_DEVICE_ALL => AmdIvhdDeviceEntry::All { settings },
            IVRS_DEVICE_SELECT => AmdIvhdDeviceEntry::Select {
                requester_id,
                settings,
            },
            IVRS_DEVICE_START_RANGE => AmdIvhdDeviceEntry::StartRange {
                requester_id,
                settings,
            },
            IVRS_DEVICE_END_RANGE => AmdIvhdDeviceEntry::EndRange {
                requester_id,
                settings,
            },
            IVRS_DEVICE_PAD8 => AmdIvhdDeviceEntry::Pad8,
            IVRS_DEVICE_ALIAS_SELECT => AmdIvhdDeviceEntry::AliasSelect {
                requester_id,
                settings,
                used_id: read_u16(bytes, offset + 5),
            },
            IVRS_DEVICE_ALIAS_START_RANGE => AmdIvhdDeviceEntry::AliasStartRange {
                requester_id,
                settings,
                used_id: read_u16(bytes, offset + 5),
            },
            IVRS_DEVICE_EXT_SELECT => AmdIvhdDeviceEntry::ExtSelect {
                requester_id,
                settings,
                extended_data: read_u32(bytes, offset + 4),
            },
            IVRS_DEVICE_EXT_START_RANGE => AmdIvhdDeviceEntry::ExtStartRange {
                requester_id,
                settings,
                extended_data: read_u32(bytes, offset + 4),
            },
            IVRS_DEVICE_SPECIAL => AmdIvhdDeviceEntry::Special {
                requester_id,
                settings,
                handle: bytes[offset + 4],
                used_id: read_u16(bytes, offset + 5),
                variety: bytes[offset + 7],
            },
            IVRS_DEVICE_ACPI_HID => AmdIvhdDeviceEntry::AcpiHid {
                requester_id,
                settings,
                hardware_id: read_u64(bytes, offset + 4),
                compatible_id: read_u64(bytes, offset + 12),
                uid_type: bytes[offset + 20],
                uid_length: bytes[offset + 21],
            },
            _ => AmdIvhdDeviceEntry::Unknown {
                entry_type,
                raw: bytes[offset..offset + entry_length].to_vec(),
            },
        };

        entries.push(entry);
        offset += entry_length;
    }

    entries
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

fn has_table<T: AcpiTable>(tables: &AcpiTables<ACPIImpl>) -> bool {
    tables.find_table::<T>().is_ok()
}

fn require_table<T: AcpiTable>(
    tables: &AcpiTables<ACPIImpl>,
    name: &str,
) -> PhysicalMapping<ACPIImpl, T> {
    match tables.find_table::<T>() {
        Ok(table) => table,
        Err(err) => panic!(
            "mandatory IOMMU policy: ACPI {} is missing or invalid: {:?}",
            name, err
        ),
    }
}

fn table_bytes<'a, H: AcpiHandler, T>(table: &'a PhysicalMapping<H, T>) -> &'a [u8] {
    unsafe {
        core::slice::from_raw_parts(
            table.virtual_start().as_ptr().cast::<u8>(),
            table.region_length(),
        )
    }
}

fn read_packed<T: Copy>(bytes: &[u8], offset: usize) -> T {
    assert!(offset + size_of::<T>() <= bytes.len());
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<T>()) }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let slice = bytes
        .get(offset..offset + 2)
        .expect("ACPI field is truncated");
    u16::from_le_bytes([slice[0], slice[1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let slice = bytes
        .get(offset..offset + 4)
        .expect("ACPI field is truncated");
    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let slice = bytes
        .get(offset..offset + 8)
        .expect("ACPI field is truncated");
    u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ])
}

fn amd_device_entry_length(entry_type: u8) -> usize {
    match entry_type {
        IVRS_DEVICE_ACPI_HID => 32,
        _ => 4usize << (entry_type >> 6),
    }
}

fn detect_boot_iommu_vendor() -> BootIommuVendor {
    let cpuid = CpuId::new();
    let Some(vendor) = cpuid.get_vendor_info() else {
        return BootIommuVendor::Unknown;
    };

    match vendor.as_str() {
        "GenuineIntel" => BootIommuVendor::Intel,
        "AuthenticAMD" => BootIommuVendor::Amd,
        _ => BootIommuVendor::Unknown,
    }
}

enum BootIommuVendor {
    Intel,
    Amd,
    Unknown,
}
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DmarTable {
    header: SdtHeader,
    width: u8,
    flags: u8,
    reserved: [u8; 10],
}

unsafe impl AcpiTable for DmarTable {
    const SIGNATURE: Signature = Signature::DMAR;

    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DmarSubtableHeader {
    subtable_type: u16,
    length: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DmarHardwareUnit {
    header: DmarSubtableHeader,
    flags: u8,
    reserved: u8,
    segment: u16,
    address: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DmarReservedMemory {
    header: DmarSubtableHeader,
    flags: u16,
    segment: u16,
    base_address: u64,
    end_address: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DmarHardwareAffinity {
    header: DmarSubtableHeader,
    reserved: u32,
    base_address: u64,
    proximity_domain: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DmarDeviceScopeHeader {
    entry_type: u8,
    length: u8,
    reserved: u16,
    enumeration_id: u8,
    bus: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DmarPciPath {
    device: u8,
    function: u8,
}

const DMAR_TYPE_HARDWARE_UNIT: u16 = 0;
const DMAR_TYPE_RESERVED_MEMORY: u16 = 1;
const DMAR_TYPE_HARDWARE_AFFINITY: u16 = 3;
const DMAR_INCLUDE_ALL: u8 = 1;
const DMAR_ALLOW_ALL: u16 = 1;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IvrsTable {
    header: SdtHeader,
    info: u32,
    reserved: u64,
}

unsafe impl AcpiTable for IvrsTable {
    const SIGNATURE: Signature = Signature::IVRS;

    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IvrsHeader {
    block_type: u8,
    flags: u8,
    length: u16,
    device_id: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IvrsMemoryBlock {
    header: IvrsHeader,
    aux_data: u16,
    reserved: u64,
    start_address: u64,
    memory_length: u64,
}

const IVRS_HARDWARE_MIN_LENGTH: usize = 20;
const IVRS_DEVICE_ENTRY_MIN_LENGTH: usize = 4;

const IVRS_TYPE_HARDWARE_10: u8 = 0x10;
const IVRS_TYPE_HARDWARE_11: u8 = 0x11;
const IVRS_TYPE_HARDWARE_40: u8 = 0x40;
const IVRS_TYPE_MEMORY_ALL: u8 = 0x20;
const IVRS_TYPE_MEMORY_SPECIFIED: u8 = 0x21;
const IVRS_TYPE_MEMORY_RANGE: u8 = 0x22;

const IVHD_ATTR_HATDIS: u32 = 1 << 0;

const IVRS_DEVICE_PAD4: u8 = 0x00;
const IVRS_DEVICE_ALL: u8 = 0x01;
const IVRS_DEVICE_SELECT: u8 = 0x02;
const IVRS_DEVICE_START_RANGE: u8 = 0x03;
const IVRS_DEVICE_END_RANGE: u8 = 0x04;
const IVRS_DEVICE_PAD8: u8 = 0x40;
const IVRS_DEVICE_ALIAS_SELECT: u8 = 0x42;
const IVRS_DEVICE_ALIAS_START_RANGE: u8 = 0x43;
const IVRS_DEVICE_EXT_SELECT: u8 = 0x46;
const IVRS_DEVICE_EXT_START_RANGE: u8 = 0x47;
const IVRS_DEVICE_SPECIAL: u8 = 0x48;
const IVRS_DEVICE_ACPI_HID: u8 = 0xF0;

