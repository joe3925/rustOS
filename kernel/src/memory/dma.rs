use crate::drivers::pnp::device::DevNodeExt;
use crate::memory::device_mmu::DeviceMmuAttachment;
use crate::memory::device_mmu::DeviceMmuBackendInfo;
use crate::memory::device_mmu::DeviceMmuDeviceIdentity;
use crate::memory::device_mmu::DeviceMmuDomain;
use crate::memory::device_mmu::DeviceMmuError;
use crate::memory::device_mmu::DeviceMmuMapPermissions;
use crate::memory::device_mmu::DeviceMmuSystem;
use crate::memory::device_mmu::MappingRecord;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use kernel_types::device::DeviceObject;
use kernel_types::dma::DeviceMmuPlatformDeviceIdentity;
use kernel_types::dma::DmaBufferView;
use kernel_types::dma::DmaDeviceHandle;
use kernel_types::dma::DmaDeviceState;
use kernel_types::dma::DmaMapError;
use kernel_types::dma::DmaMappedBuffer;
use kernel_types::dma::DmaMappingStrategy;
use kernel_types::dma::DmaPciDeviceIdentity;
use kernel_types::dma::IoBufferBacking;
use kernel_types::dma::IoBufferDmaMappingLayout;
use kernel_types::dma::IoBufferPageFrame;
use kernel_types::dma::DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE;
use kernel_types::status::DriverStatus;
use spin::Mutex;
use spin::Once;
static DMA_MANAGER: Once<DmaManager> = Once::new();

pub fn init_dma_manager() {
    let _ = DMA_MANAGER.call_once(DmaManager::new);
}
pub fn get_info() -> DeviceMmuBackendInfo {
    manager().get_info()
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
    layout: IoBufferDmaMappingLayout,
}
pub fn map_persistent_contiguous_backing<'backing, 'data>(
    device: &Arc<DeviceObject>,
    backing: &'backing IoBufferBacking<'data>,
) -> Result<(), DmaMapError>
where
    'data: 'backing,
{
    const ACCESS_BIDIRECTIONAL: u8 = 3;

    if backing.is_empty() {
        return Err(DmaMapError::InvalidSize);
    }

    let mut buffer = backing
        .create_phys_bidirectional(0, backing.len())
        .map_err(|_| DmaMapError::InvalidSize)?;

    let view = buffer
        .dma_buffer_view()
        .map_err(|_| DmaMapError::InvalidSize)?;

    let mapped = match map_buffer(device, &view, DmaMappingStrategy::SingleContiguous) {
        Ok(mapped) => mapped,
        Err(err) => {
            drop(view);
            drop(buffer);
            return Err(err);
        }
    };

    drop(view);
    drop(buffer);

    match mapped.layout {
        IoBufferDmaMappingLayout::Contiguous { byte_len, .. } if byte_len == backing.len() => {
            match backing.attach_persistent_dma_mapping(
                0,
                backing.len(),
                ACCESS_BIDIRECTIONAL,
                mapped.layout,
                mapped.mapped_by.clone(),
                mapped.unmap,
                mapped.cookie,
            ) {
                Ok(()) => Ok(()),
                Err(_) => {
                    (mapped.unmap)(&mapped.mapped_by, mapped.cookie);
                    Err(DmaMapError::InvalidSize)
                }
            }
        }
        _ => {
            (mapped.unmap)(&mapped.mapped_by, mapped.cookie);
            Err(DmaMapError::RemappingUnavailable)
        }
    }
}
pub fn map_buffer(
    device: &Arc<DeviceObject>,
    buffer: &DmaBufferView<'_>,
    strategy: DmaMappingStrategy,
) -> Result<DmaMappedBuffer, DmaMapError> {
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

    let PreparedDmaMapping { records, layout } = prepared;
    let cookie = m.alloc_cookie();

    m.insert_pending_unmap(
        cookie,
        PendingUnmap {
            device_key: key,
            domain: active.domain.clone(),
            records,
        },
    );

    Ok(DmaMappedBuffer {
        layout,
        mapped_by: active.pdo.clone(),
        unmap: unmap_trampoline,
        cookie: cookie as usize,
    })
}

fn prepare_dma_mapping(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    buffer: &DmaBufferView<'_>,
    strategy: DmaMappingStrategy,
) -> Result<PreparedDmaMapping, DmaMapError> {
    let device_page_size_u64 = domain.device_page_size();
    let device_page_size =
        usize::try_from(device_page_size_u64).map_err(|_| DmaMapError::InvalidSize)?;

    if device_page_size == 0 || !device_page_size_u64.is_power_of_two() {
        return Err(DmaMapError::InvalidSize);
    }

    if device_page_size > u32::MAX as usize {
        return Err(DmaMapError::InvalidSize);
    }

    validate_dma_buffer(buffer, device_page_size)?;

    let buffer_len = buffer.len();

    let Some(iommu_page_count) = covered_iommu_page_count_for_buffer(buffer, device_page_size)
    else {
        return Err(DmaMapError::InvalidSize);
    };

    let Some(map_size) = (iommu_page_count as u64).checked_mul(device_page_size_u64) else {
        return Err(DmaMapError::InvalidSize);
    };

    let mut records = PendingMappingRecords::new();

    let layout = match strategy {
        DmaMappingStrategy::SingleContiguous => {
            if buffer_len > u32::MAX as usize {
                return Err(DmaMapError::InvalidSize);
            }

            if !buffer_supports_contiguous_iova(buffer, device_page_size) {
                return Err(DmaMapError::RemappingUnavailable);
            }

            let Some(iova_base) = domain.alloc_iova(map_size) else {
                return Err(DmaMapError::RemappingUnavailable);
            };

            records.push_range(iova_base, iommu_page_count, device_page_size, false)?;

            if let Err(err) =
                map_buffer_frames_to_iova(device_mmu, domain, iova_base, buffer, device_page_size)
            {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            let Some(page_offset) = first_dma_page_offset(buffer, device_page_size) else {
                rollback_mappings(device_mmu, domain, &records);
                return Err(DmaMapError::InvalidSize);
            };

            IoBufferDmaMappingLayout::Contiguous {
                dma_addr: iova_base + page_offset as u64,
                byte_len: buffer_len,
            }
        }
        DmaMappingStrategy::ScatterGather => {
            let Some(iova_base) = domain.alloc_iova(map_size) else {
                return Err(DmaMapError::RemappingUnavailable);
            };

            records.push_range(iova_base, iommu_page_count, device_page_size, false)?;

            if let Err(err) =
                map_buffer_frames_to_iova(device_mmu, domain, iova_base, buffer, device_page_size)
            {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            IoBufferDmaMappingLayout::ScatterGather {
                iova_base,
                page_size: device_page_size,
            }
        }
        DmaMappingStrategy::ContiguousChunks { chunk_size } => {
            if chunk_size == 0 {
                return Err(DmaMapError::InvalidSize);
            }

            if (chunk_size % device_page_size) != 0 {
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

            if !buffer_supports_contiguous_iova(buffer, device_page_size) {
                return Err(DmaMapError::RemappingUnavailable);
            }

            let chunk_count = buffer_len / chunk_size;

            let Some(iova_base) = domain.alloc_iova(map_size) else {
                return Err(DmaMapError::RemappingUnavailable);
            };

            records.push_range(iova_base, iommu_page_count, device_page_size, false)?;

            if let Err(err) =
                map_buffer_frames_to_iova(device_mmu, domain, iova_base, buffer, device_page_size)
            {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            let Some(page_offset) = first_dma_page_offset(buffer, device_page_size) else {
                rollback_mappings(device_mmu, domain, &records);
                return Err(DmaMapError::InvalidSize);
            };

            IoBufferDmaMappingLayout::FixedChunks {
                dma_addr: iova_base + page_offset as u64,
                chunk_len: chunk_size as u32,
                count: chunk_count,
            }
        }
        DmaMappingStrategy::FullIdentity => {
            if let Err(err) =
                map_identity_frames(device_mmu, domain, buffer, device_page_size, &mut records)
            {
                rollback_mappings(device_mmu, domain, &records);
                return Err(err);
            }

            IoBufferDmaMappingLayout::IdentityExtents
        }
    };

    if records.is_empty() {
        rollback_mappings(device_mmu, domain, &records);
        return Err(DmaMapError::RemappingUnavailable);
    }

    if let Err(err) = device_mmu.invalidate_domain(domain) {
        rollback_mappings(device_mmu, domain, &records);
        return Err(map_device_mmu_error(err));
    }

    Ok(PreparedDmaMapping { records, layout })
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

fn validate_dma_buffer(
    buffer: &DmaBufferView<'_>,
    device_page_size: usize,
) -> Result<(), DmaMapError> {
    if buffer.is_empty() {
        return Err(DmaMapError::InvalidSize);
    }

    let mut described_len = 0usize;
    let mut region_count = 0usize;

    for region in buffer.regions() {
        if region.is_empty() {
            continue;
        }

        let frames = region.page_frames();
        if frames.is_empty() {
            return Err(DmaMapError::InvalidSize);
        }

        described_len = described_len
            .checked_add(region.len())
            .ok_or(DmaMapError::InvalidSize)?;

        region_count += 1;
    }

    if region_count == 0 || described_len != buffer.len() {
        return Err(DmaMapError::InvalidSize);
    }

    if !buffer_frames_cover_extents(buffer) {
        return Err(DmaMapError::InvalidSize);
    }

    if covered_iommu_page_count_for_buffer(buffer, device_page_size).is_none() {
        return Err(DmaMapError::InvalidSize);
    }

    Ok(())
}
fn for_each_buffer_extent<F>(buffer: &DmaBufferView<'_>, mut f: F) -> Result<(), DmaMapError>
where
    F: FnMut(&[IoBufferPageFrame], usize, usize) -> Result<(), DmaMapError>,
{
    for region in buffer.regions() {
        if region.is_empty() {
            continue;
        }

        let frames = region.page_frames();
        let frame_offset = region.frame_offset();
        let byte_len = region.len();

        f(frames, frame_offset, byte_len)?;
    }

    Ok(())
}

fn buffer_frames_cover_extents(buffer: &DmaBufferView<'_>) -> bool {
    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        if frames_cover_buffer(frames, frame_offset, byte_len) {
            Ok(())
        } else {
            Err(DmaMapError::InvalidSize)
        }
    })
    .is_ok()
}

fn first_dma_page_offset(buffer: &DmaBufferView<'_>, device_page_size: usize) -> Option<usize> {
    if device_page_size == 0 {
        return None;
    }

    for region in buffer.regions() {
        if !region.is_empty() {
            return Some(region.frame_offset() % device_page_size);
        }
    }

    None
}

fn buffer_supports_contiguous_iova(buffer: &DmaBufferView<'_>, device_page_size: usize) -> bool {
    if device_page_size == 0 {
        return false;
    }

    let mut logical_len = 0usize;
    let mut first_offset = None;

    for region in buffer.regions() {
        if region.is_empty() {
            continue;
        }

        let byte_len = region.len();
        let start_offset = region.frame_offset() % device_page_size;

        match first_offset {
            Some(_) if start_offset != 0 => return false,
            None => first_offset = Some(start_offset),
            _ => {}
        }

        let Some(next_logical_len) = logical_len.checked_add(byte_len) else {
            return false;
        };

        logical_len = next_logical_len;

        if logical_len < buffer.len() {
            let Some(total_offset) = first_offset.unwrap_or(0).checked_add(logical_len) else {
                return false;
            };

            if (total_offset % device_page_size) != 0 {
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
    buffer: &DmaBufferView<'_>,
    device_page_size: usize,
) -> Option<usize> {
    let mut total = 0usize;

    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        let Some(count) =
            covered_iommu_page_count(frames, frame_offset, byte_len, device_page_size)
        else {
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
    device_page_size: usize,
) -> Option<usize> {
    let mut total = 0usize;

    for_each_covered_page_run(
        frames,
        frame_offset,
        buffer_len,
        device_page_size,
        |_, page_count| {
            total = total
                .checked_add(page_count)
                .ok_or(DmaMapError::InvalidSize)?;

            Ok(())
        },
    )
    .ok()?;

    Some(total)
}

fn for_each_covered_page_run<F>(
    frames: &[IoBufferPageFrame],
    frame_offset: usize,
    buffer_len: usize,
    device_page_size: usize,
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
        let device_page_size_u64 = device_page_size as u64;
        let page_base = align_down_u64(start, device_page_size_u64);
        let page_end = align_up_u64(start + bytes as u64, device_page_size_u64)?;
        let page_count = ((page_end - page_base) / device_page_size_u64) as usize;

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

fn map_phys_run_to_iova(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    iova_base: u64,
    phys_base: u64,
    page_count: usize,
    device_page_size: usize,
) -> Result<(), DmaMapError> {
    let len = (page_count as u64)
        .checked_mul(device_page_size as u64)
        .ok_or(DmaMapError::InvalidSize)?;

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
    buffer: &DmaBufferView<'_>,
    device_page_size: usize,
) -> Result<(), DmaMapError> {
    let mut iova_cursor = iova_base;

    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        for_each_covered_page_run(
            frames,
            frame_offset,
            byte_len,
            device_page_size,
            |phys_base, page_count| {
                map_phys_run_to_iova(
                    device_mmu,
                    domain,
                    iova_cursor,
                    phys_base,
                    page_count,
                    device_page_size,
                )?;

                let advance = page_count
                    .checked_mul(device_page_size)
                    .ok_or(DmaMapError::InvalidSize)?;
                iova_cursor = iova_cursor
                    .checked_add(advance as u64)
                    .ok_or(DmaMapError::InvalidSize)?;

                Ok(())
            },
        )
    })
}

fn map_identity_frames(
    device_mmu: &DeviceMmuSystem,
    domain: &Arc<DeviceMmuDomain>,
    buffer: &DmaBufferView<'_>,
    device_page_size: usize,
    records: &mut PendingMappingRecords,
) -> Result<(), DmaMapError> {
    for_each_buffer_extent(buffer, |frames, frame_offset, byte_len| {
        for_each_covered_page_run(
            frames,
            frame_offset,
            byte_len,
            device_page_size,
            |phys_base, page_count| {
                records.push_or_extend_identity(phys_base, page_count, device_page_size)?;
                map_phys_run_to_iova(
                    device_mmu,
                    domain,
                    phys_base,
                    phys_base,
                    page_count,
                    device_page_size,
                )
            },
        )
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

fn align_down_u64(value: u64, align: u64) -> u64 {
    debug_assert!(align != 0);
    value - (value % align)
}

fn align_up_u64(value: u64, align: u64) -> Result<u64, DmaMapError> {
    debug_assert!(align != 0);

    value
        .checked_add(align - 1)
        .map(|v| v - (v % align))
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
    fn get_info(&self) -> DeviceMmuBackendInfo {
        self.device_mmu.info()
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
                .iter()
                .filter_map(|slot| slot.as_ref())
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
                    .iter()
                    .filter_map(|slot| slot.as_ref())
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
        state.alloc_cookie()
    }

    fn insert_pending_unmap(&self, cookie: u64, pending: PendingUnmap) {
        self.state.lock().insert_pending_unmap(cookie, pending);
    }

    fn remove_pending_unmap(&self, cookie: u64) -> Option<PendingUnmap> {
        self.state.lock().remove_pending_unmap(cookie)
    }
}

struct DmaManagerState {
    devices: alloc::collections::BTreeMap<usize, Arc<RegisteredDmaDevice>>,
    pending_unmaps: Vec<Option<PendingUnmap>>,
    free_cookies: Vec<u64>,
}

impl DmaManagerState {
    fn new() -> Self {
        Self {
            devices: alloc::collections::BTreeMap::new(),
            pending_unmaps: Vec::new(),
            free_cookies: Vec::new(),
        }
    }

    fn alloc_cookie(&mut self) -> u64 {
        if let Some(cookie) = self.free_cookies.pop() {
            return cookie;
        }

        let index = self.pending_unmaps.len();
        self.pending_unmaps.push(None);
        (index as u64).saturating_add(1)
    }

    fn insert_pending_unmap(&mut self, cookie: u64, pending: PendingUnmap) {
        let Some(index) = cookie.checked_sub(1).and_then(|v| usize::try_from(v).ok()) else {
            return;
        };

        if let Some(slot) = self.pending_unmaps.get_mut(index) {
            *slot = Some(pending);
        }
    }

    fn remove_pending_unmap(&mut self, cookie: u64) -> Option<PendingUnmap> {
        let index = cookie
            .checked_sub(1)
            .and_then(|v| usize::try_from(v).ok())?;
        let pending = self.pending_unmaps.get_mut(index)?.take();
        if pending.is_some() {
            self.free_cookies.push(cookie);
        }
        pending
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

const INLINE_MAPPING_RECORD_CAPACITY: usize = 4;

const EMPTY_MAPPING_RECORD: MappingRecord = MappingRecord {
    iova_base: 0,
    page_count: 0,
    is_identity: false,
};

#[derive(Clone)]
struct PendingMappingRecords {
    inline: [MappingRecord; INLINE_MAPPING_RECORD_CAPACITY],
    heap: Option<Vec<MappingRecord>>,
    len: usize,
}

impl PendingMappingRecords {
    fn new() -> Self {
        Self {
            inline: [EMPTY_MAPPING_RECORD; INLINE_MAPPING_RECORD_CAPACITY],
            heap: None,
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_slice(&self) -> &[MappingRecord] {
        match self.heap.as_ref() {
            Some(records) => records.as_slice(),
            None => &self.inline[..self.len],
        }
    }

    fn push(&mut self, rec: MappingRecord) -> Result<(), DmaMapError> {
        if let Some(records) = self.heap.as_mut() {
            records.push(rec);
            self.len = records.len();
            return Ok(());
        }

        if self.len < INLINE_MAPPING_RECORD_CAPACITY {
            self.inline[self.len] = rec;
            self.len += 1;
            return Ok(());
        }

        let mut records = Vec::with_capacity(INLINE_MAPPING_RECORD_CAPACITY * 2);
        records.extend_from_slice(&self.inline[..self.len]);
        records.push(rec);
        self.len = records.len();
        self.heap = Some(records);

        Ok(())
    }

    fn last_mut(&mut self) -> Option<&mut MappingRecord> {
        match self.heap.as_mut() {
            Some(records) => records.last_mut(),
            None => self.inline[..self.len].last_mut(),
        }
    }

    fn push_range(
        &mut self,
        mut iova_base: u64,
        mut page_count: usize,
        device_page_size: usize,
        is_identity: bool,
    ) -> Result<(), DmaMapError> {
        while page_count != 0 {
            let count = page_count.min(u32::MAX as usize);

            self.push(MappingRecord {
                iova_base,
                page_count: count as u32,
                is_identity,
            })?;

            let advance = (count as u64)
                .checked_mul(device_page_size as u64)
                .ok_or(DmaMapError::InvalidSize)?;

            iova_base = iova_base
                .checked_add(advance)
                .ok_or(DmaMapError::InvalidSize)?;

            page_count -= count;
        }

        Ok(())
    }

    fn push_or_extend_identity(
        &mut self,
        mut iova_base: u64,
        mut page_count: usize,
        device_page_size: usize,
    ) -> Result<(), DmaMapError> {
        while page_count != 0 {
            let count = page_count.min(u32::MAX as usize);

            if let Some(prev) = self.last_mut() {
                let prev_len = (prev.page_count as u64)
                    .checked_mul(device_page_size as u64)
                    .ok_or(DmaMapError::InvalidSize)?;

                let prev_end = prev
                    .iova_base
                    .checked_add(prev_len)
                    .ok_or(DmaMapError::InvalidSize)?;

                let combined = prev.page_count as u64 + count as u64;

                if prev.is_identity && prev_end == iova_base && combined <= u32::MAX as u64 {
                    prev.page_count = combined as u32;

                    let advance = (count as u64)
                        .checked_mul(device_page_size as u64)
                        .ok_or(DmaMapError::InvalidSize)?;

                    iova_base = iova_base
                        .checked_add(advance)
                        .ok_or(DmaMapError::InvalidSize)?;

                    page_count -= count;
                    continue;
                }
            }

            self.push(MappingRecord {
                iova_base,
                page_count: count as u32,
                is_identity: true,
            })?;

            let advance = (count as u64)
                .checked_mul(device_page_size as u64)
                .ok_or(DmaMapError::InvalidSize)?;

            iova_base = iova_base
                .checked_add(advance)
                .ok_or(DmaMapError::InvalidSize)?;

            page_count -= count;
        }

        Ok(())
    }
}

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
