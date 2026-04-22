use alloc::sync::Arc;

use kernel_types::device::DeviceObject;
pub use kernel_types::dma;
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
