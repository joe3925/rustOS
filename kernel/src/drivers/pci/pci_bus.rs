use crate::drivers::pci::device_collection::Device;
use crate::drivers::pci::device_collection::DeviceCollection;
use crate::println;
use lazy_static::lazy_static;
use x86_64::instructions::port::Port;


lazy_static!(
    pub static ref PCIBUS: PciBus = PciBus::new();
);
const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
pub struct PciBus {
    pub device_collection: DeviceCollection,
    pub last_update: u128,
}
impl PciBus {
    pub fn new() -> Self {
        let mut pci = PciBus { device_collection: DeviceCollection::new(), last_update: 0 };
        let mut address_port = Port::new(CONFIG_ADDRESS);
        let mut data_port = Port::<u32>::new(CONFIG_DATA);

        for bus in 0..255 {
            for device in 0..32 {
                for function in 0..8 {
                    let id = PciBus::pci_config_read(bus, device, function, 0, &mut address_port, &mut data_port);
                    if id != 0xFFFFFFFF { // 0xFFFFFFFF means no device present
                        let header = PciBus::pci_config_read(bus, device, function, 0x08, &mut address_port, &mut data_port);
                        let class_code = (header >> 24) as u8;
                        let subclass = ((header >> 16) & 0xFF) as u8;
                        pci.device_collection.add_device(Device::new(bus, device, function, id, class_code, subclass));
                    }
                }
            }
        }
        pci
    }
    pub(crate) fn print_devices(&self) {
        for i in 0..self.device_collection.devices.len() {
            println!("Device found: Bus {}, Device {}, Function {}, ID {}, Class Code {}, Subclass {:#X}",
                     self.device_collection.devices[i].bus,
                     self.device_collection.devices[i].device,
                     self.device_collection.devices[i].function,
                     self.device_collection.devices[i].id,
                     self.device_collection.devices[i].class_code,
                     self.device_collection.devices[i].subclass
            );
        }
    }
    pub(crate) fn pci_config_read(bus: u8, device: u8, function: u8, offset: u8, address_port: &mut Port<u32>, data_port: &mut Port<u32>) -> u32 {
        let bus = u32::from(bus);
        let device = u32::from(device);
        let function = u32::from(function);
        let offset = u32::from(offset);

        let address = (1 << 31) // Enable bit
            | (bus << 16)
            | (device << 11)
            | (function << 8)
            | (offset & 0xFC);

        unsafe {
            address_port.write(address);
            data_port.read()
        }
    }
}