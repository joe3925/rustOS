use alloc::sync::Arc;

pub use kernel_types::dma::{
    Bidirectional, Described, DmaDeviceHandle, DmaDeviceState, DmaMapped, DmaPciDeviceIdentity,
    FromDevice, Mdl, MdlDmaSegment, MdlError, MdlPageFrame, Pinned, ToDevice,
    DMA_IOMMU_VENDOR_AMD_IVRS, DMA_IOMMU_VENDOR_INTEL_DMAR, DMA_IOMMU_VENDOR_NONE,
    DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE, DMA_PCI_IDENTITY_FLAG_BUS_MASTER_ENABLED,
    MDL_INLINE_PAGE_CAPACITY, MDL_INLINE_SEGMENT_CAPACITY, MDL_PAGE_SIZE,
};
use kernel_types::device::DeviceObject;
use kernel_types::status::DriverStatus;

pub fn register_pci_pdo(
    pdo: &Arc<DeviceObject>,
    identity: DmaPciDeviceIdentity,
) -> DriverStatus {
    unsafe { kernel_sys::kernel_dma_register_pci_pdo(pdo, identity) }
}

pub fn open_device_handle(device: &Arc<DeviceObject>) -> Result<DmaDeviceHandle, DriverStatus> {
    unsafe { kernel_sys::kernel_dma_open_device_handle(device) }
}

pub fn query_device_state(device: &Arc<DeviceObject>) -> Option<DmaDeviceState> {
    unsafe { kernel_sys::kernel_dma_query_device_state(device) }
}
