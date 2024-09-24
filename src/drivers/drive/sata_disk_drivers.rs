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
use crate::println;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
const MMIO_VIRTUAL_ADDR: VirtAddr = VirtAddr::new(0xFFFF_FF00_0000_0000);
pub(crate) struct AHCIController {
    pub(crate) mmio_base: u64,
    pub(crate) total_ports: u32,
    pub(crate) occupied_ports: Vec<u32>,
}
impl AHCIController {
    pub fn new() -> Self {
        let mut controller =
            AHCIController{
                mmio_base: MMIO_VIRTUAL_ADDR.as_u64(),
                total_ports: 0,
                occupied_ports: Vec::new(),
            };
        controller.init();
        controller
    }
    pub fn init(&mut self)
    {
        self.total_ports = self.get_total_ports();
        self.occupied_ports = self.get_total_drives();
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
        let port_base = self.mmio_base + 0x100 + (port as u64 * 0x80);  // Base address for the given port

        // Step 1: Check if a drive is connected by reading the SATA Status (SSTS) register
        let ssts = unsafe { *((port_base + 0x28) as *const u32) };  // Read the SATA Status register
        let device_detect = ssts & 0xF;  // Check the device detection status

        if device_detect != 0x3 {
            // No drive detected
            return None;
        }
        // Step 2: Read the drive's identify data
        let mut identify_buffer: [u8; 512] = [0; 512];
        self.read_identify_data(port, &mut identify_buffer);

        // Step 3: Extract relevant information from the identify data
        let model = String::from_utf8_lossy(&identify_buffer[54..94]).trim().to_string();
        let serial = String::from_utf8_lossy(&identify_buffer[20..40]).trim().to_string();
        let capacity = self.extract_capacity(&identify_buffer);  // Implement this function to extract the drive's capacity from the identify data

        // Step 4: Return the filled DriveInfo struct
        Some(DriveInfo {
            model,
            serial,
            port,
            capacity,
        })
    }

    // Function to extract drive capacity from the identify data
    fn extract_capacity(&self, identify_data: &[u8]) -> u64 {
        let lba28_sectors = u32::from_le_bytes([identify_data[60], identify_data[61], identify_data[62], identify_data[63]]);
        let lba48_sectors = u64::from_le_bytes([identify_data[100], identify_data[101], identify_data[102], identify_data[103], identify_data[104], identify_data[105], 0, 0]);

        if lba48_sectors > 0 {
            lba48_sectors * 512  // Return the capacity in bytes for LBA48 drives
        } else {
            lba28_sectors as u64 * 512  // Return the capacity in bytes for LBA28 drives
        }
    }

    fn read_identify_data(&self, port: u32, buffer: &mut [u8]) {
        // Step 1: Get the base address for the specified port
        let port_base = self.mmio_base + 0x100 + (port as u64 * 0x80);

        let ci = port_base + 0x38;  // PxCI register (Command Issue)
        let tfd = port_base + 0x20;  // PxTFD register (Task File Data)
        while unsafe { *((tfd) as *const u32) & (1 << 7) != 0 } { // PxTFD_BSY bit
        }

        // Step 3: Set up the command table and issue IDENTIFY command
        let cmd_issue = unsafe { &mut *((ci) as *mut u32) };
        let cmd_table = self.setup_command_table(port, 512);  // Setup a command table for 512-byte IDENTIFY data
        unsafe {
            let cmd_header = &mut *((port_base + 0x10) as *mut u32);  // PxCMD register
            let cmd_slot = self.find_free_command_slot(port).expect("No free command slot available");  // Find a free command slot

            // Setup the command FIS in the command table
            let cmd_fis = &mut *((cmd_table as *mut u8).offset(0) as *mut [u8; 64]);  // First 64 bytes are the FIS
            cmd_fis[0] = 0x27;  // Host to device FIS
            cmd_fis[1] = 0x80;  // Command FIS
            cmd_fis[2] = 0xEC;  // IDENTIFY command
            cmd_fis[3] = 0x00;  // Reserved

            // Clear PxCI and set the bit for the command slot we are using
            *cmd_issue = 0;
            *cmd_issue |= 1 << cmd_slot;

            *cmd_header |= 1 << 0;  // PxCMD.ST (Start)

            // Wait for completion
            while *cmd_issue & (1 << cmd_slot) != 0 {
            }

            let receive_buffer = (cmd_table + 0x80) as *const u8;  // The PRDT buffer starts at offset 0x80
            for i in 0..512 {
                buffer[i] = *(receive_buffer.offset(i as isize));
            }

            // Clear the command issue bit for the command slot
            *cmd_issue &= !(1 << cmd_slot);
        }
    }

    // Helper function to set up the command table
    fn setup_command_table(&self, port: u32, prdt_entry_count: usize) -> u64 {
        let port_base = self.mmio_base + 0x100 + (port as u64 * 0x80);
        let cmd_list_base = port_base + 0x00;
        let cmd_table_addr = unsafe { *((cmd_list_base + 0x08) as *const u64) };
        cmd_table_addr
    }

    fn find_free_command_slot(&self, port: u32) -> Option<u32> {
        let port_base = self.mmio_base + 0x100 + (port as u64 * 0x80);
        let ci = unsafe { &*((port_base + 0x38) as *const u32) };
        for slot in 0..32 {
            if (*ci & (1 << slot)) == 0 {
                return Some(slot);
            }
        }
        None
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