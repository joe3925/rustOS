use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use x86_64::instructions::port::Port;
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::idt::ExceptionVector::Page;
use x86_64::structures::paging::OffsetPageTable;
use crate::drivers::drive::generic_drive::{DriveController, DriveInfo, DRIVECOLLECTION};
use crate::drivers::pci::device_collection::Device;
use crate::drivers::pci::pci_bus::{PciBus, PCIBUS};
use crate::memory::paging::{map_mmio_region, BootInfoFrameAllocator};
use core::ptr::{read_volatile, write_volatile};
use crate::structs::aligned_buffer;

use crate::println;
use crate::structs::aligned_buffer::{AlignedBuffer1024, AlignedBuffer256};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
const MMIO_VIRTUAL_ADDR: VirtAddr = VirtAddr::new(0xFFFF_FF00_0000_0000);
pub(crate) struct AHCIController {
    pub(crate) mmio_base: u64,
    pub(crate) total_ports: u32,
    pub(crate) occupied_ports: Vec<u32>,
    pub(crate) ports_registers: Vec<AHCIPortRegisters>,
    pub(crate) command_list_buffers: Vec<AlignedBuffer1024>,
    pub(crate) FIS_Buffer: Vec<AlignedBuffer256>,

}
unsafe impl Send for AHCIController {}

pub(crate) struct AHCIPortRegisters {
    pub(crate) cmd: *mut u32,    // PxCMD: Command and Status
    pub(crate) is: *mut u32,     // PxIS: Interrupt Status
    pub(crate) ci: *mut u32,     // PxCI: Command Issue
}
impl AHCIController {
    pub fn new() -> Self {
        let mut controller =
            AHCIController{
                mmio_base: MMIO_VIRTUAL_ADDR.as_u64(),
                total_ports: 0,
                occupied_ports: Vec::new(),
                ports_registers: Vec::new(),
                command_list_buffers: Vec::new(),
                FIS_Buffer: Vec::new(),

            };
        controller.init();
        controller
    }
    pub fn init(&mut self) {
        self.total_ports = self.get_total_ports();
        self.occupied_ports = self.get_total_drives();

        //create the port registers
        let mut ports_registers = Vec::new();

        for i in 0..self.total_ports {
            let port_base = self.mmio_base + 0x100 + (i as u64 * 0x80);

            ports_registers.push(AHCIPortRegisters {
                cmd: (port_base + 0x18) as *mut u32, // PxCMD register at offset 0x18
                is: (port_base + 0x10) as *mut u32,  // PxIS register at offset 0x10
                ci: (port_base + 0x38) as *mut u32,  // PxCI register at offset 0x38
            });
        }


        self.ports_registers = ports_registers;
        //This will not work change to index with the values of occupied ports
        for mut port  in 0..self.occupied_ports.len() {
            let mut cmd_value = unsafe { read_volatile(self.ports_registers[self.occupied_ports[port] as usize].cmd) };
            // Step 2: Clear bit 0 and bit 8 of the command register
            cmd_value &= !(1 << 0);  // Clear bit 0
            cmd_value &= !(1 << 8);  // Clear bit 8

            unsafe {
                write_volatile(self.ports_registers[self.occupied_ports[port] as usize].cmd, cmd_value);
            }

            loop {
                let cmd_value = unsafe { read_volatile(self.ports_registers[self.occupied_ports[port] as usize].cmd) };

                if (cmd_value & (1 << 14)) == 0 && (cmd_value & (1 << 15)) == 0 {
                    break;
                }
            }
        }
        for _port in 0..self.total_ports{
            let buffer_1024 = AlignedBuffer1024::new();
            self.command_list_buffers.push(buffer_1024);

            let buffer_256 = AlignedBuffer256::new();
            self.FIS_Buffer.push(buffer_256);
        }
    }

    pub fn map(mapper: &mut OffsetPageTable, frame_allocator: &mut BootInfoFrameAllocator){
        if let Some(base_addr) = AHCIController::find_sata_controller() {
            println!("found controller at {}",base_addr);
            map_mmio_region(mapper, frame_allocator, PhysAddr::new(base_addr), 8192, MMIO_VIRTUAL_ADDR).expect("TODO: panic message");
        }
    }
    pub fn find_sata_controller() -> Option<u64> {
        let mut address_port = Port::<u32>::new(CONFIG_ADDRESS);
        let mut data_port = Port::<u32>::new(CONFIG_DATA);

        unsafe {
            let pci_bus = PCIBUS.lock();
            pci_bus.print_devices();

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
    pub fn get_total_ports(&self) -> u32{
        unsafe {
            let hba_cap = *(self.mmio_base as *const u32);
            let num_ports = (hba_cap & 0b11111) + 1; // Bits [4:0] hold the number of supported ports - 1
            println!("Number of supported ports: {}", num_ports);
            num_ports
        }
    }
    pub fn get_total_drives(&self) -> Vec<u32> {
        let mut drives = Vec::new();  // Vector to store the indices of ports with connected drives

        // Step 1: Read the PI (Ports Implemented) register to get the active ports
        let pi_register = unsafe { *((self.mmio_base + 0x0C) as *const u32) };

        // Step 2: Iterate through each port and check if it's implemented and has a connected drive
        for port_number in 0..self.total_ports {
            if (pi_register & (1 << port_number)) != 0 {
                // The port is implemented, now check the SATA Status (SSTS) register
                let port_base = self.mmio_base + 0x100 + (port_number as u64 * 0x80);  // Calculate the base address for the port
                let ssts = unsafe { *((port_base + 0x28) as *const u32) };      // Read the SATA Status (SSTS) register
                let device_detect = ssts & 0xF;                                // Check the device detection status

                // If the device detection field is 0x3, it means a drive is connected
                if device_detect == 0x3 {
                    drives.push(port_number);  // Add this port number to the vector
                }
            }
        }

        // Step 3: Return the vector containing the indices of ports with connected drives
        println!("total drives: {}", drives[0]);
        drives
    }
    pub fn identify_drive(&self, port: u32) -> Option<DriveInfo> {
        todo!()
    }


}
impl DriveController for AHCIController{
    fn read(&mut self, label: &str, sector: u32, buffer: &mut [u8]) {
        todo!()
    }

    fn write(&mut self, label: &str, sector: u32, data: &[u8]) {
        todo!()
    }

     fn enumerate_drives(){
        let controller = AHCIController::new();
        println!("Occupied ports: {:#?}, Total Ports: {:#?}",controller.occupied_ports,
                 controller.total_ports);
        let mut drive_collection = DRIVECOLLECTION.lock();
        for i in 0..controller.occupied_ports.len(){
            if let Some(drive_info) = controller.identify_drive(controller.occupied_ports[i]){
                drive_info.print();
                if let Some(label) = drive_collection.find_free_label() {
                    drive_collection.new_drive(label, drive_info, Box::new(AHCIController::new()));
                }
            }

        }
    }

    fn isController(device: &Device) -> bool{
        if (device.class_code == 0x01 && device.subclass == 0x06){
            return true
        }
        false
    }

}