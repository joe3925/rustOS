use kernel_types::pci::PciConfigAddress;

use crate::platform::PciConfigPlatform;

use super::platform::Aarch64Platform;

impl PciConfigPlatform for Aarch64Platform {
    fn read_pci_config_u32(_address: PciConfigAddress) -> Option<u32> {
        todo!()
    }
    fn write_pci_config_u32(_address: PciConfigAddress, _value: u32) -> bool {
        todo!()
    }
}
