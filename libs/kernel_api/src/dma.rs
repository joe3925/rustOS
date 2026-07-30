use alloc::sync::Arc;

use kernel_types::device::DeviceObject;
pub use kernel_types::dma;
use kernel_types::dma::{
    DmaBufferView, DmaMapError, DmaMappedBuffer, DmaMappingStrategy, IoBuffer, IoBufferAccess,
    IoBufferBacking, IoBufferError,
};
use kernel_types::error::DriverErrorKind;

pub fn dma_base_page_size() -> usize {
    unsafe { kernel_sys::kernel_dma_base_page_size() as usize }
}

pub fn register_pci_pdo(
    pdo: &Arc<DeviceObject>,
    identity: dma::DmaPciDeviceIdentity,
) -> Result<(), DriverErrorKind> {
    unsafe { kernel_sys::kernel_dma_register_pci_pdo(pdo, identity) }
}

pub fn register_platform_pdo(
    pdo: &Arc<DeviceObject>,
    identity: dma::DeviceMmuPlatformDeviceIdentity,
) -> Result<(), DriverErrorKind> {
    unsafe { kernel_sys::kernel_dma_register_platform_pdo(pdo, identity) }
}

pub fn open_device_handle(
    device: &Arc<DeviceObject>,
) -> Result<dma::DmaDeviceHandle, DriverErrorKind> {
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

pub fn map_persistent_contiguous_backing(
    device: &Arc<DeviceObject>,
    backing: &IoBufferBacking<'_>,
) -> Result<(), DmaMapError> {
    unsafe { kernel_sys::kernel_dma_map_persistent_contiguous_backing(device, backing) }
}
