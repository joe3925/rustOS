use alloc::sync::Arc;

use kernel_types::device::DeviceObject;
pub use kernel_types::dma;
use kernel_types::dma::{
    DmaMapError, DmaMapped, DmaMappingStrategy, IoBuffer, IoBufferDirection, IoBufferInner,
    MappableIoBufferState,
};
use kernel_types::status::DriverStatus;

pub fn register_pci_pdo(
    pdo: &Arc<DeviceObject>,
    identity: dma::DmaPciDeviceIdentity,
) -> DriverStatus {
    unsafe { kernel_sys::kernel_dma_register_pci_pdo(pdo, identity) }
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
    let raw_buffer: IoBufferInner<'a> = buffer.into_inner();
    match unsafe { kernel_sys::kernel_dma_map_buffer(device, raw_buffer, strategy) } {
        Ok(inner) => Ok(IoBuffer::<'a, DmaMapped<S>, D>::from_inner(inner)),
        Err((inner, err)) => Err((IoBuffer::<'a, S, D>::from_inner(inner), err)),
    }
}

pub fn unmap_buffer<'a, S: MappableIoBufferState, D: IoBufferDirection>(
    buffer: IoBuffer<'a, DmaMapped<S>, D>,
) -> IoBuffer<'a, S, D> {
    let raw_buffer: IoBufferInner<'a> = buffer.into_inner();
    IoBuffer::<'a, S, D>::from_inner(unsafe {
        kernel_sys::kernel_dma_unmap_buffer(raw_buffer)
    })
}
