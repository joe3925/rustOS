use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::ptr;

use kernel_types::device::DeviceObject;
pub use kernel_types::dma;
use kernel_types::dma::{
    BorrowedDmaMapping, DmaMapError, DmaMapped, DmaMappingStrategy, IoBuffer, IoBufferDirection,
    IoBufferState, PhysFramed, ToDevice,
};
use kernel_types::status::DriverStatus;

unsafe fn cast_io_buffer<'a, S, D, NextS, NextD>(
    buffer: IoBuffer<'a, S, D>,
) -> IoBuffer<'a, NextS, NextD>
where
    S: IoBufferState,
    D: IoBufferDirection,
    NextS: IoBufferState,
    NextD: IoBufferDirection,
{
    let buffer = ManuallyDrop::new(buffer);
    unsafe {
        ptr::read(
            (&*buffer as *const IoBuffer<'a, S, D>).cast::<IoBuffer<'a, NextS, NextD>>(),
        )
    }
}

unsafe fn cast_io_buffer_ref<'map, 'buffer, S, D, NextS, NextD>(
    buffer: &'map IoBuffer<'buffer, S, D>,
) -> &'map IoBuffer<'buffer, NextS, NextD>
where
    S: IoBufferState,
    D: IoBufferDirection,
    NextS: IoBufferState,
    NextD: IoBufferDirection,
{
    unsafe {
        &*(buffer as *const IoBuffer<'buffer, S, D> as *const IoBuffer<'buffer, NextS, NextD>)
    }
}

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

pub fn map_buffer<'a, D: IoBufferDirection>(
    device: &Arc<DeviceObject>,
    buffer: IoBuffer<'a, PhysFramed, D>,
    strategy: DmaMappingStrategy,
) -> Result<
    IoBuffer<'a, DmaMapped<PhysFramed>, D>,
    (IoBuffer<'a, PhysFramed, D>, DmaMapError),
> {
    let erased = unsafe { cast_io_buffer::<PhysFramed, D, PhysFramed, ToDevice>(buffer) };
    match unsafe { kernel_sys::kernel_dma_map_buffer(device, erased, strategy) } {
        Ok(mapped) => Ok(unsafe {
            cast_io_buffer::<DmaMapped<PhysFramed>, ToDevice, DmaMapped<PhysFramed>, D>(mapped)
        }),
        Err((erased, err)) => Err((
            unsafe { cast_io_buffer::<PhysFramed, ToDevice, PhysFramed, D>(erased) },
            err,
        )),
    }
}

pub fn unmap_buffer<'a, D: IoBufferDirection>(
    buffer: IoBuffer<'a, DmaMapped<PhysFramed>, D>,
) -> IoBuffer<'a, PhysFramed, D> {
    let erased =
        unsafe {
            cast_io_buffer::<DmaMapped<PhysFramed>, D, DmaMapped<PhysFramed>, ToDevice>(buffer)
        };
    let unmapped = unsafe { kernel_sys::kernel_dma_unmap_buffer(erased) };
    unsafe { cast_io_buffer::<PhysFramed, ToDevice, PhysFramed, D>(unmapped) }
}

pub fn map_buffer_ref<'map, 'buffer, D: IoBufferDirection>(
    device: &Arc<DeviceObject>,
    buffer: &'map IoBuffer<'buffer, PhysFramed, D>,
    strategy: DmaMappingStrategy,
) -> Result<BorrowedDmaMapping<'map>, DmaMapError> {
    let erased =
        unsafe { cast_io_buffer_ref::<PhysFramed, D, PhysFramed, ToDevice>(buffer) };
    unsafe { kernel_sys::kernel_dma_map_buffer_ref(device, erased, strategy) }
}
