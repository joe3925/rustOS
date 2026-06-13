use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::ptr;

use kernel_types::device::DeviceObject;
pub use kernel_types::dma;
use kernel_types::dma::{
    BorrowedDmaMapping, DmaMapError, DmaMapped, DmaMappingStrategy, IoBuffer, IoBufferDirection,
    IoBufferState, MappableIoBufferState, PhysFramed, ToDevice,
};
use kernel_types::status::DriverStatus;

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

pub fn map_buffer<'a, S: MappableIoBufferState, D: IoBufferDirection>(
    device: &Arc<DeviceObject>,
    buffer: IoBuffer<'a, S, D>,
    strategy: DmaMappingStrategy,
) -> Result<IoBuffer<'a, DmaMapped<S>, D>, (IoBuffer<'a, S, D>, DmaMapError)> {
    match unsafe { kernel_sys::kernel_dma_map_buffer(device, buffer.into_inner(), strategy) } {
        Ok(mapped) => Ok(IoBuffer::from_inner(mapped)),
        Err((erased, err)) => Err((IoBuffer::from_inner(erased), err)),
    }
}

pub fn unmap_buffer<'a, S: MappableIoBufferState, D: IoBufferDirection>(
    buffer: IoBuffer<'a, DmaMapped<S>, D>,
) -> IoBuffer<'a, S, D> {
    let unmapped = unsafe { kernel_sys::kernel_dma_unmap_buffer(buffer.into_inner()) };
    IoBuffer::from_inner(unmapped)
}

pub fn map_buffer_ref<'map, 'buffer, S: MappableIoBufferState, D: IoBufferDirection>(
    device: &Arc<DeviceObject>,
    buffer: &'map IoBuffer<'buffer, S, D>,
    strategy: DmaMappingStrategy,
) -> Result<BorrowedDmaMapping<'map>, DmaMapError> {
    unsafe { kernel_sys::kernel_dma_map_buffer_ref(device, buffer.as_inner(), strategy) }
}
