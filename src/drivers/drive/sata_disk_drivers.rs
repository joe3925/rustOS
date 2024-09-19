use x86_64::instructions::port::Port;
use crate::drivers::pci::pci_bus::{PciBus, PCIBUS};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
pub(crate) struct SataController {
    pub(crate) mmio_base: u64,
}
impl SataController {
    pub fn new() -> Self {
        if let Some(base_addr) = SataController::find_sata_controller(){
            return SataController{
                mmio_base: base_addr,
            }
        }
        SataController{
            mmio_base: 0x0,
        }
    }
    pub fn find_sata_controller() -> Option<u64> {
        let mut address_port = Port::<u32>::new(CONFIG_ADDRESS);
        let mut data_port = Port::<u32>::new(CONFIG_DATA);

        unsafe {
            let pci_bus = PCIBUS.lock();

            // Iterate over all the devices in the device collection
            for device in pci_bus.device_collection.devices.iter() {
                // Check if the device is a SATA controller (class code 0x01, subclass 0x06)
                if device.class_code == 0x01 && device.subclass == 0x06 {
                    // Read the BAR0 from the device
                    let bar0 = PciBus::pci_config_read(device.bus, device.device, device.function, 0x10, &mut address_port, &mut data_port);

                    // Determine if BAR0 is a memory-mapped address (bit 0 should be 0 for MMIO)
                    if bar0 & 0x1 == 0 {
                        let mmio_base = bar0 & 0xFFFFFFF0; // Mask out the lower 4 bits
                        return Some(mmio_base as u64); // Return the MMIO base address
                    }
                }
            }
        }

        None // Return None if no SATA controller is found
    }
}