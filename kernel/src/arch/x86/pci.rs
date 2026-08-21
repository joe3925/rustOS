use kernel_types::pci::PciConfigAddress;
use spin::Mutex;
use x86_64::instructions::port::Port;

use crate::platform::PciConfigPlatform;

use super::platform::X86Platform;

const PCI_CFG1_ADDR: u16 = 0xCF8;
const PCI_CFG1_DATA: u16 = 0xCFC;
static PCI_CFG1_LOCK: Mutex<()> = Mutex::new(());

#[inline]
fn pci_cfg1_addr(address: PciConfigAddress) -> Option<u32> {
    if address.segment != 0
        || address.device >= 32
        || address.function >= 8
        || address.offset > 0xFFC
    {
        return None;
    }

    Some(
        0x8000_0000
            | ((address.bus as u32) << 16)
            | ((address.device as u32) << 11)
            | ((address.function as u32) << 8)
            | ((address.aligned_u32_offset() as u32) & !3),
    )
}

impl PciConfigPlatform for X86Platform {
    fn read_pci_config_u32(address: PciConfigAddress) -> Option<u32> {
        let cfg_addr = pci_cfg1_addr(address)?;
        let _guard = PCI_CFG1_LOCK.lock();

        unsafe {
            let mut addr = Port::<u32>::new(PCI_CFG1_ADDR);
            let mut data = Port::<u32>::new(PCI_CFG1_DATA);
            addr.write(cfg_addr);
            Some(data.read())
        }
    }

    fn write_pci_config_u32(address: PciConfigAddress, value: u32) -> bool {
        let Some(cfg_addr) = pci_cfg1_addr(address) else {
            return false;
        };
        let _guard = PCI_CFG1_LOCK.lock();

        unsafe {
            let mut addr = Port::<u32>::new(PCI_CFG1_ADDR);
            let mut data = Port::<u32>::new(PCI_CFG1_DATA);
            addr.write(cfg_addr);
            data.write(value);
        }

        true
    }
}
