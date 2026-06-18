use kernel_sys::{kernel_pci_read_config_u32, kernel_pci_write_config_u32};

pub use kernel_types::pci::{EcamSegment, PciConfigAddress};

#[inline]
pub fn pci_read_config_u32(address: PciConfigAddress) -> Option<u32> {
    let mut value = 0;
    if unsafe { kernel_pci_read_config_u32(address, &mut value) } {
        Some(value)
    } else {
        None
    }
}

#[inline]
pub fn pci_write_config_u32(address: PciConfigAddress, value: u32) -> bool {
    unsafe { kernel_pci_write_config_u32(address, value) }
}
