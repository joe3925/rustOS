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
use crate::memory::paging::{map_mmio_region, virtual_to_phys, BootInfoFrameAllocator};
use core::ptr::{read_volatile, write_volatile};
use bootloader::BootInfo;
use crate::structs::aligned_buffer;

use crate::{println, BOOT_INFO};
use crate::structs::aligned_buffer::{AlignedBuffer1024, AlignedBuffer128, AlignedBuffer256};

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

#[repr(C)]
struct CommandHeader {
    flags: u16,
    prdtl: u16,
    prdbc: u32,
    ctba: u32,
    ctbau: u32,
    reserved: [u32; 4],
}

#[repr(C)]
struct CommandTable {
    command_fis: [u8; 64],  // Command FIS
    atapi_command: [u8; 16], // ATAPI Command (if applicable)
    reserved: [u8; 48],
    prdt_entry: [PRDTEntry; 8], // Physical Region Descriptor Table (PRDT) entries
}

#[repr(C)]
struct PRDTEntry {
    data_base_address: u32,
    data_base_address_upper: u32,
    reserved: u32,
    byte_count: u32,
}

#[repr(C)]
struct AHCICommandList {
    command_headers: [CommandHeader; 32], // AHCI supports up to 32 command slots
}

#[repr(C)]
struct AHCIPortRegisters {
    cmd: *mut u32, // Command Register
    is: *mut u32,  // Interrupt Status Register
    ci: *mut u32,  // Command Issue Register
    CLB: *mut u32, // Command List Base
    CLBU: *mut u32, // Command List Base Upper
    FB: *mut u32, // FIS Base Address
    FBU: *mut u32, // FIS Base Upper Address
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
        unsafe {
            // Initialize port registers
            self.initialize_port_registers();
            println!("init ports");
            // Disable ports before setup
            self.disable_ports();
            println!("disable ports");
            // Allocate Command List and FIS buffers
            self.allocate_buffers();
            println!("allocate buffers");

            // Set up command tables and list for each occupied port
            self.setup_command_tables();
            println!("command table");

            // Re-enable ports after setup
            self.enable_ports();
            println!("enable ports");

        }

        // The device is now initialized
    }

    /// Initialize port registers based on the total number of ports.
    unsafe fn initialize_port_registers(&mut self) {
        let mut ports_registers = Vec::with_capacity(self.total_ports as usize);

        for i in 0..self.total_ports {
            let port_base = self.mmio_base + 0x100 + (i as u64 * 0x80);

            ports_registers.push(AHCIPortRegisters {
                cmd: (port_base + 0x18) as *mut u32, // PxCMD register at offset 0x18
                is: (port_base + 0x10) as *mut u32,  // PxIS register at offset 0x10
                ci: (port_base + 0x38) as *mut u32,  // PxCI register at offset 0x38
                CLB: (port_base + 0x00) as *mut u32, // Command List Base
                CLBU: (port_base + 0x04) as *mut u32, // Command List Base Upper
                FB: (port_base + 0x08) as *mut u32, // FIS Base
                FBU: (port_base + 0x0C) as *mut u32, // FIS Base Upper
            });
        }

        self.ports_registers = ports_registers;
    }

    /// Disable ports by clearing ST (bit 0) and FRE (bit 8).
    unsafe fn disable_ports(&mut self) {
        for port_index in 0..self.occupied_ports.len() {
            // Ensure no commands are active by waiting for CI to be 0
            while read_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].ci) != 0 {}

            let mut cmd_value = read_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].cmd);
            cmd_value &= !(1 << 0);  // Clear bit 0 (ST)
            cmd_value &= !(1 << 8);  // Clear bit 8 (FRE)
            write_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].cmd, cmd_value);


            // Wait until CR (bit 15) and FRE (bit 14) are cleared
            loop {
                let cmd_value = read_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].cmd);
                println!("{}", cmd_value & (1 << 14));
                println!("{}", cmd_value & (1 << 15));

                if (cmd_value & (1 << 15)) == 0 && (cmd_value & (1 << 15)) == 0 {
                    break;
                }
            }
        }
    }

    /// Allocate memory for Command List and FIS buffers.
    unsafe fn allocate_buffers(&mut self) {
        for _ in 0..self.total_ports {
            let buffer_1024 = AlignedBuffer1024::new(); // For Command List
            self.command_list_buffers.push(buffer_1024);

            let buffer_256 = AlignedBuffer256::new(); // For FIS
            self.FIS_Buffer.push(buffer_256);
        }
    }

    /// Setup command tables and initialize Command Headers for each port.
    unsafe fn setup_command_tables(&mut self) {
        for port in self.occupied_ports.clone() {
            let mem_offset = VirtAddr::new(BOOT_INFO.unwrap().physical_memory_offset);

            // Set Command List Base (CLB) and CLBU
            let command_list_address = virtual_to_phys(mem_offset, VirtAddr::new(&self.command_list_buffers[port as usize] as *const _ as u64));
            write_volatile(self.ports_registers[port as usize].CLB, command_list_address.as_u64() as u32);
            write_volatile(self.ports_registers[port as usize].CLBU, (command_list_address.as_u64() >> 32) as u32);

            // Set FIS Base (FB) and FBU
            let fis_address = virtual_to_phys(mem_offset, VirtAddr::new(&self.FIS_Buffer[port as usize] as *const _ as u64));
            write_volatile(self.ports_registers[port as usize].FB, fis_address.as_u64() as u32);
            write_volatile(self.ports_registers[port as usize].FBU, (fis_address.as_u64() >> 32) as u32);

            // Allocate an 8KiB buffer for the Command Table (CT)
            let command_table_buffer = AlignedBuffer128::new(); // Allocating 8KiB buffer for Command Table

            // Calculate the physical address of the Command Table
            let command_table_address = virtual_to_phys(mem_offset, VirtAddr::new(&command_table_buffer as *const _ as u64));

            // Initialize Command Headers
            self.initialize_command_headers(port, command_table_address);
        }
    }

    /// Initialize command headers for each occupied port.
    unsafe fn initialize_command_headers(&mut self, port: u32, command_table_address: PhysAddr) {
        const COMMAND_HEADER_SIZE: usize = 32;
        const NUM_COMMAND_HEADERS: usize = 32;

        for cmdheader_index in 0..NUM_COMMAND_HEADERS {
            // Get a pointer to the start of the command list buffer for the current port
            let command_list_base_ptr = self.command_list_buffers[port as usize].buffer.as_mut_ptr();

            // Calculate the offset for the current Command Header
            let cmdheader_ptr = command_list_base_ptr.add(cmdheader_index * COMMAND_HEADER_SIZE) as *mut CommandHeader;

            // Dereference the pointer to get the actual Command Header
            let cmdheader = &mut *cmdheader_ptr;

            // Set CTBA to the lower 32 bits and CTBAU to the upper 32 bits
            cmdheader.ctba = command_table_address.as_u64() as u32;
            cmdheader.ctbau = (command_table_address.as_u64() >> 32) as u32;

            // Set the Physical Region Descriptor Table Length (prdtl) to 8 (default for now)
            cmdheader.prdtl = 8;
        }
    }

    /// Re-enable ports by setting ST (bit 0) and FRE (bit 8).
    unsafe fn enable_ports(&mut self) {
        for port_index in 0..self.occupied_ports.len() {
            let mut cmd_value = read_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].cmd);
            cmd_value |= (1 << 0);  // Set bit 0 (ST)
            cmd_value |= (1 << 8);  // Set bit 8 (FRE)
            write_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].cmd, cmd_value);
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