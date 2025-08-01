use crate::drivers::drive::generic_drive::DriveInfo;
use crate::drivers::pci::pci_bus::{PciBus, PCIBUS};
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::mmio::map_mmio_region;
use crate::memory::paging::tables::virtual_to_phys;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use x86_64::instructions::port::Port;
use x86_64::structures::paging::OffsetPageTable;
use x86_64::{PhysAddr, VirtAddr};

use crate::cpu::wait_cycle;
use crate::drivers::drive::ahci_structs::{
    AHCIPortRegisters, CommandHeader, CommandTable, FisRegH2D,
};
use crate::println;
use crate::structs::aligned_buffer::{
    AlignedBuffer1024, AlignedBuffer128, AlignedBuffer256, AlignedBuffer512,
};
use crate::util::boot_info;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
const MMIO_VIRTUAL_ADDR: VirtAddr = VirtAddr::new(0xFFFF_FF00_0000_0000);
pub(crate) struct AHCIController {
    pub(crate) mmio_base: u64,
    pub(crate) total_ports: u32,
    pub(crate) occupied_ports: Vec<u32>,
    pub(crate) ports_registers: Vec<AHCIPortRegisters>,
    pub(crate) command_list_buffers: Vec<AlignedBuffer1024>,
    pub(crate) fis_buffer: Vec<AlignedBuffer256>,
    pub(crate) command_table_virt_addr: Vec<VirtAddr>,
}
unsafe impl Send for AHCIController {}
// All dogshit chat gpt slop code

impl AHCIController {
    pub fn new() -> Self {
        let mut controller = AHCIController {
            mmio_base: MMIO_VIRTUAL_ADDR.as_u64(),
            total_ports: 0,
            occupied_ports: Vec::new(),
            ports_registers: Vec::new(),
            command_list_buffers: Vec::new(),
            fis_buffer: Vec::new(),
            command_table_virt_addr: Vec::new(),
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
                clb: (port_base + 0x00) as *mut u32, // Command List Base
                clbu: (port_base + 0x04) as *mut u32, // Command List Base Upper
                fb: (port_base + 0x08) as *mut u32,  // FIS Base
                fbu: (port_base + 0x0C) as *mut u32, // FIS Base Upper
            });
        }

        self.ports_registers = ports_registers;
    }

    /// Disable ports by clearing ST (bit 0) and FRE (bit 8).
    unsafe fn disable_ports(&mut self) {
        for port_index in 0..self.occupied_ports.len() {
            // Ensure no commands are active by waiting for CI to be 0
            while read_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].ci)
                != 0
            {}

            let mut cmd_value =
                read_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].cmd);
            cmd_value &= !(1 << 0); // Clear bit 0 (ST)
            cmd_value &= !(1 << 8); // Clear bit 8 (FRE)
            write_volatile(
                self.ports_registers[self.occupied_ports[port_index] as usize].cmd,
                cmd_value,
            );

            // Wait until CR (bit 15) and FRE (bit 14) are cleared
            loop {
                let cmd_value = read_volatile(
                    self.ports_registers[self.occupied_ports[port_index] as usize].cmd,
                );
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
            self.fis_buffer.push(buffer_256);
        }
    }

    /// Setup command tables and initialize Command Headers for each port.
    unsafe fn setup_command_tables(&mut self) {
        for port in 0..self.total_ports.clone() {
            let boot_info = boot_info();
            let mem_offset =
                VirtAddr::new((boot_info.physical_memory_offset.into_option().unwrap()));

            // Set Command List Base (clb) and clbu
            let command_list_address = virtual_to_phys(VirtAddr::new(
                &self.command_list_buffers[port as usize].buffer as *const _ as u64,
            ));
            write_volatile(
                self.ports_registers[port as usize].clb,
                command_list_address.as_u64() as u32,
            );
            write_volatile(
                self.ports_registers[port as usize].clbu,
                (command_list_address.as_u64() >> 32) as u32,
            );

            // Set FIS Base (fb) and fbu
            let fis_address = virtual_to_phys(VirtAddr::new(
                &self.fis_buffer[port as usize].buffer as *const _ as u64,
            ));
            write_volatile(
                self.ports_registers[port as usize].fb,
                fis_address.as_u64() as u32,
            );
            write_volatile(
                self.ports_registers[port as usize].fbu,
                (fis_address.as_u64() >> 32) as u32,
            );

            // Allocate an 8KiB buffer for the Command Table (CT)
            let command_table_buffer = AlignedBuffer128::new(); // Allocating 8KiB buffer for Command Table

            // Calculate the physical address of the Command Table
            self.command_table_virt_addr.push(VirtAddr::new(
                &command_table_buffer.buffer as *const _ as u64,
            ));
            let command_table_address = virtual_to_phys(VirtAddr::new(
                &command_table_buffer.buffer as *const _ as u64,
            ));

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
            let command_list_base_ptr =
                self.command_list_buffers[port as usize].buffer.as_mut_ptr();

            // Calculate the offset for the current Command Header
            let cmdheader_ptr = command_list_base_ptr.add(cmdheader_index * COMMAND_HEADER_SIZE)
                as *mut CommandHeader;

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
            let mut cmd_value =
                read_volatile(self.ports_registers[self.occupied_ports[port_index] as usize].cmd);
            cmd_value |= (1 << 0); // Set bit 0 (ST)
            cmd_value |= (1 << 8); // Set bit 8 (FRE)
            write_volatile(
                self.ports_registers[self.occupied_ports[port_index] as usize].cmd,
                cmd_value,
            );
        }
    }

    pub fn map(mapper: &mut OffsetPageTable, frame_allocator: &mut BootInfoFrameAllocator) {
        if let Some(base_addr) = AHCIController::find_sata_controller() {
            println!("found controller at {}", base_addr);
            map_mmio_region(PhysAddr::new(base_addr), 8192).expect("TODO: panic message");
        }
    }
    pub fn find_sata_controller() -> Option<u64> {
        let mut address_port = Port::<u32>::new(CONFIG_ADDRESS);
        let mut data_port = Port::<u32>::new(CONFIG_DATA);

        PCIBUS.print_devices();

        for device in PCIBUS.device_collection.devices.iter() {
            //SATA controller has class 0x01 and subclass 0x06
            if device.class_code == 0x01 && device.subclass == 0x06 {
                // The base address is at BAR5
                let bar5 = PciBus::pci_config_read(
                    device.bus,
                    device.device,
                    device.function,
                    0x24,
                    &mut address_port,
                    &mut data_port,
                );
                println!("Found SATA device at {}", bar5);
                // Determine if BAR0 is a memory-mapped address (bit 0 should be 0 for MMIO)
                if bar5 & 0x1 == 0 {
                    let mmio_base = bar5 & 0xFFFFFFF0;
                    return Some(mmio_base as u64);
                }
            }
        }

        None // Return None if no SATA controller is found
    }
    pub fn get_total_ports(&self) -> u32 {
        unsafe {
            let hba_cap = *(self.mmio_base as *const u32);
            let num_ports = (hba_cap & 0b11111) + 1; // Bits [4:0] hold the number of supported ports - 1
            println!("Number of supported ports: {}", num_ports);
            num_ports
        }
    }
    pub fn get_total_drives(&self) -> Vec<u32> {
        let mut drives = Vec::new(); // Vector to store the indices of ports with connected drives

        // Step 1: Read the PI (Ports Implemented) register to get the active ports
        let pi_register = unsafe { *((self.mmio_base + 0x0C) as *const u32) };

        // Step 2: Iterate through each port and check if it's implemented and has a connected drive
        for port_number in 0..self.total_ports {
            if (pi_register & (1 << port_number)) != 0 {
                // The port is implemented, now check the SATA Status (SSTS) register
                let port_base = self.mmio_base + 0x100 + (port_number as u64 * 0x80); // Calculate the base address for the port
                let ssts = unsafe { *((port_base + 0x28) as *const u32) }; // Read the SATA Status (SSTS) register
                let device_detect = ssts & 0xF; // Check the device detection status

                // If the device detection field is 0x3, it means a drive is connected
                if device_detect == 0x3 {
                    drives.push(port_number); // Add this port number to the vector
                }
            }
        }

        // Step 3: Return the vector containing the indices of ports with connected drives
        println!("total drives: {}", drives[0]);
        drives
    }
    pub fn identify_drive(&mut self, port: u32) -> Option<DriveInfo> {
        // Step 1: Set up the FIS for the IDENTIFY DEVICE command (0xEC)
        let fis = FisRegH2D::new(0xEC, 0, 1); // Identify device has no specific LBA, sector_count = 1

        // Step 2: Get the Command Header and Command Table for this port
        let command_list_base_ptr = self.command_list_buffers[port as usize].buffer.as_mut_ptr();
        let command_table_virt_addr = self.command_table_virt_addr[(port) as usize];
        let command_header_ptr = command_list_base_ptr as *mut CommandHeader;
        let command_header = unsafe { &mut *command_header_ptr };

        // Set the flags in the Command Header: Command FIS length (5 DWORDs) and write (0 for IDENTIFY)
        command_header.flags = (core::mem::size_of::<FisRegH2D>() / 4) as u16; // 5 DWORDs for the FIS
        command_header.prdtl = 1; // One PRD entry

        // Step 3: Set up the Command Table and add the FIS to it
        let command_table_base_ptr = command_table_virt_addr.as_u64() as *mut CommandTable;
        let command_table = unsafe { &mut *command_table_base_ptr };

        // Clear the command table
        unsafe { core::ptr::write_bytes(command_table as *mut CommandTable, 0, 1) };

        // Copy the FIS into the Command Table
        unsafe {
            core::ptr::copy_nonoverlapping(
                &fis as *const FisRegH2D as *const u8,
                command_table.command_fis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // Set up a Physical Region Descriptor (PRD) to point to the buffer for the response data
        let identify_buffer = AlignedBuffer512::new(); // Assume 512-byte aligned buffer for the IDENTIFY response
        command_table.prdt_entry[0].data_base_address = identify_buffer.buffer.as_ptr() as u32;
        command_table.prdt_entry[0].data_base_address_upper =
            (identify_buffer.buffer.as_ptr() as u64 >> 32) as u32;
        command_table.prdt_entry[0].byte_count = 512 - 1; // 512 bytes to transfer (byte_count field is size-1)

        // Step 4: Issue the command by setting the Command Issue (CI) bit for this slot
        unsafe {
            let cmd_issue = self.ports_registers[port as usize].ci;
            *cmd_issue |= 1; // Set the first slot in the Command Issue register
        }

        // Step 5: Poll for the command completion by checking the Interrupt Status (IS) and Command Issue (CI)
        loop {
            let is_register = unsafe { read_volatile(self.ports_registers[port as usize].is) };
            let ci_register = unsafe { read_volatile(self.ports_registers[port as usize].ci) };

            // Check if the command has completed (CI bit cleared)
            if (ci_register & 1) == 0 || true {
                wait_cycle(10000000000);
                break;
            }

            // Check for any errors in the Interrupt Status (IS) register
            if is_register & 0x40000000 != 0 {
                println!("Error during IDENTIFY DEVICE");
                return None;
            }
        }

        // Step 6: Retrieve the data from the buffer
        let identify_data =
            unsafe { core::slice::from_raw_parts(identify_buffer.buffer.as_ptr(), 512) };

        // Parse the IDENTIFY DEVICE response data (model name, serial number, etc.)
        let model_name = String::from_utf8_lossy(&identify_data[54..94]).to_string(); // Example: extract the model name
        let serial_number = String::from_utf8_lossy(&identify_data[20..40]).to_string(); // Example: extract the serial number
                                                                                         // Step 7: Return the parsed DriveInfo
        Some(DriveInfo {
            model: model_name,
            serial: serial_number,
            port: 1,
            capacity: 0,
        })
    }
}
/*impl DriveController for AHCIController  {
    fn read(&mut self, sector: u32, buffer: &mut [u8]) {
        todo!()
    }

    fn write(&mut self, sector: u32, data: &[u8]) {
        todo!()
    }

    fn enumerate_drives() -> Vec<Drive> {
        let mut controller = AHCIController::new();
        println!("Occupied ports: {:#?}, Total Ports: {:#?}", controller.occupied_ports,
                 controller.total_ports);
        let mut drive_list = Vec::new();
        for i in 0..controller.occupied_ports.len() {
            if let Some(drive_info) = controller.identify_drive(controller.occupied_ports[i]) {
                drive_info.print();
                drive_list.push(Drive::new("".to_string(), drive_info, Box::new(AHCIController::new())));
            }
        }
        drive_list
    }

    fn factory(&self) -> Box<(dyn DriveController + Send + Sync)> {
        todo!()
    }
    fn is_controller(device: &Device) -> bool {
        if (device.class_code == 0x01 && device.subclass == 0x06) {
            return true;
        }
        false
    }
}*/
