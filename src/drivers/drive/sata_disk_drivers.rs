use x86_64::instructions::port::Port;
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::idt::ExceptionVector::Page;
use x86_64::structures::paging::OffsetPageTable;
use crate::drivers::drive::generic_drive::DriveController;
use crate::drivers::pci::device_collection::Device;
use crate::drivers::pci::pci_bus::{PciBus, PCIBUS};
use crate::memory::paging::{map_mmio_region, BootInfoFrameAllocator};
use crate::println;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
pub(crate) struct AHCIController {
    pub(crate) mmio_base: u64,
}
impl AHCIController {
    pub fn new() -> Self {
        if let Some(base_addr) = AHCIController::find_sata_controller(){
            let controller = AHCIController {
                mmio_base: base_addr,
            };

            return controller
        }
        AHCIController {
            mmio_base: 0x0,
        }
    }
    pub fn init(&mut self, mapper: &mut OffsetPageTable, frame_allocator: &mut BootInfoFrameAllocator)
    {
        let mmio_virtual_addr = VirtAddr::new(0xFFFF_FF00_0000_0000);
        map_mmio_region(mapper, frame_allocator, PhysAddr::new(self.mmio_base), 8192, mmio_virtual_addr).expect("TODO: panic message");
        self.mmio_base = mmio_virtual_addr.as_u64();
    }
    pub fn find_sata_controller() -> Option<u64> {
        let mut address_port = Port::<u32>::new(CONFIG_ADDRESS);
        let mut data_port = Port::<u32>::new(CONFIG_DATA);

        unsafe {
            let pci_bus = PCIBUS.lock();

            for device in pci_bus.device_collection.devices.iter() {
                //SATA controller has class 0x01 and subclass 0x06
                if device.class_code == 0x01 && device.subclass == 0x06 {
                    // The base address is at BAR5
                    let bar5 = PciBus::pci_config_read(device.bus, device.device, device.function, 0x24, &mut address_port, &mut data_port);
                    println!("Found SATA device at {}", bar5);
                    // Determine if BAR0 is a memory-mapped address (bit 0 should be 0 for MMIO)
                    if bar5 & 0x1 == 0 {
                        let mmio_base = bar5 & 0xFFFFFFF0;
                        return Some(mmio_base as u64);
                    }
                }
            }
        }

        None // Return None if no SATA controller is found
    }
    pub fn get_total_drives(&self) -> u32{
        unsafe {
            let hba_cap = *(self.mmio_base as *const u32);
            let num_ports = (hba_cap & 0b11111) + 1; // Bits [4:0] hold the number of supported ports - 1
            println!("Number of supported ports: {}", num_ports);
            num_ports
        }
    }

}
impl DriveController for AHCIController{
    fn read(&mut self, label: &str, sector: u32, buffer: &mut [u8]) {
        todo!()
    }

    fn write(&mut self, label: &str, sector: u32, data: &[u8]) {
        todo!()
    }

    fn enumerate_drives()
    where
        Self: Sized
    {
        todo!()
    }

    fn isController(device: &Device) -> bool
    where
        Self: Sized
    {
        todo!()
    }
}