use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use x86_64::instructions::port::Port;
use crate::drivers::pci;
use crate::drivers::pci::pci_bus::PciBus;
use crate::println;
use bitflags::bitflags;

const PRIMARY_CMD_BASE: u16 = 0x1F0;
const PRIMARY_CTRL_BASE: u16 = 0x3F6;

const DATA_REG: u16 = PRIMARY_CMD_BASE + 0;
const ERROR_REG: u16 = PRIMARY_CMD_BASE + 1; // Same as FEATURES_REG for writing
const SECTOR_COUNT_REG: u16 = PRIMARY_CMD_BASE + 2;
const LBA_LO_REG: u16 = PRIMARY_CMD_BASE + 3;
const LBA_MID_REG: u16 = PRIMARY_CMD_BASE + 4;
const LBA_HI_REG: u16 = PRIMARY_CMD_BASE + 5;
const DRIVE_HEAD_REG: u16 = PRIMARY_CMD_BASE + 6;
const STATUS_REG: u16 = PRIMARY_CMD_BASE + 7; // Same as CMD_REG for writing
const CONTROL_REG: u16 = PRIMARY_CTRL_BASE + 2;
pub fn has_ide_controller(mut bus: PciBus) -> bool {
    bus.enumerate_pci();
    for device in &bus.device_collection.devices {
        // IDE controller class code is 0x01 and subclass code is 0x01
        if device.class_code == 0x01 && device.subclass == 0x01 {
            println!("IDE Controller found at Bus {}, Device {}, Function {}",
                     device.bus, device.device, device.function);
            return true;
        }
    }
    println!("No IDE Controller found.");
    false
}
#[derive(Debug, Clone)]
struct DriveInfo {
    drive_label: String,
    model: String,
    serial: String,
    capacity: u64,
}
impl DriveInfo {
    pub fn print(&self) {
        println!("Drive Label: {}", self.drive_label);
        println!("Model: {}", self.model);
        println!("Serial Number: {}", self.serial);
        println!("Capacity: {} bytes", self.capacity);
        println!("--------------------------------");
    }
}

pub struct IdeController {
    data_port: Port<u16>,
    error_port: Port<u8>,
    sector_count_port: Port<u8>,
    lba_lo_port: Port<u8>,
    lba_mid_port: Port<u8>,
    lba_hi_port: Port<u8>,
    drive_head_port: Port<u8>,
    command_port: Port<u8>,
    control_port: Port<u8>,
    drives: Vec<DriveInfo>,
}

impl IdeController {
    pub fn new() -> Self {
        IdeController {
            data_port: Port::new(DATA_REG),
            error_port: Port::new(ERROR_REG),
            sector_count_port: Port::new(SECTOR_COUNT_REG),
            lba_lo_port: Port::new(LBA_LO_REG),
            lba_mid_port: Port::new(LBA_MID_REG),
            lba_hi_port: Port::new(LBA_HI_REG),
            drive_head_port: Port::new(DRIVE_HEAD_REG),
            command_port: Port::new(STATUS_REG),
            control_port: Port::new(CONTROL_REG),
            drives: Vec::new()
        }
    }
    pub fn print_all_drives(&mut self) {
        for drive in &self.drives {
            drive.print();
        }
    }
    fn identify_drive(&mut self, drive: u8) -> Option<DriveInfo> {

        unsafe {
            self.drive_head_port.write(0xA0 | (drive << 4)); // Select drive (0 = master, 1 = slave)
            self.command_port.write(0xEC); // Send IDENTIFY command

            if self.status().contains(StatusFlags::ERR) {
                return None; // If error, drive does not exist
            }

            // Read IDENTIFY data
            let mut data = [0u16; 256];
            for word in data.iter_mut() {
                *word = self.data_port.read();
            }
            //For some reason these serial and model are stored as an array of 2 byte chunks https://mail.gnu.org/archive/html/qemu-devel/2015-04/msg02158.html
            let serial = String::from_utf8_lossy(
                &data[10..20]
                    .iter()
                    .flat_map(|&word| vec![(word >> 8) as u8, (word & 0xFF) as u8]) // Swap the bytes of each word
                    .collect::<Vec<u8>>(),
            )
                .to_string();

            let model = String::from_utf8_lossy(
                &data[27..47]
                    .iter()
                    .flat_map(|&word| vec![(word >> 8) as u8, (word & 0xFF) as u8]) // Swap the bytes of each word
                    .collect::<Vec<u8>>(),
            )
                .to_string();

            let capacity = ((data[60] as u64) | ((data[61] as u64) << 16)) * 512; // Assuming 512 bytes per sector

            Some(DriveInfo {
                drive_label: if drive == 0 { "C:".to_string() } else { "D:".to_string() },
                model,
                serial,
                capacity,
            })
        }
    }
    fn drive_selector_from_label(&self, label: &str) -> u8 {
        match label.to_uppercase().as_str() {
            "C:" => 0xA0,  // Master drive on primary channel
            "D:" => 0xB0,  // Slave drive on primary channel
            _ => 0xA0,     // Default to master if unspecified or unknown label
        }
    }
    fn status(&mut self) -> StatusFlags {
        unsafe { StatusFlags::from_bits_truncate(self.command_port.read()) }
    }

    fn enumerate_drives(&mut self) {
        if let Some(info) = self.identify_drive(0) {  // Master drive
            self.drives.push(info);
        }

        if let Some(info) = self.identify_drive(1) {  // Slave drive
            self.drives.push(info);
        }
    }
    pub fn init(&mut self) -> bool{
        if(!has_ide_controller(PciBus::new())){
            return false
        }
        self.enumerate_drives();
        unsafe {
            self.control_port.write(0x02); // Reset the controller
            self.control_port.write(0x00); // Clear the reset flag
            true
        }
    }

    pub fn read_sector(&mut self, label: &str, lba: u32, buffer: &mut [u8]) {
        assert_eq!(buffer.len(), 512); // Ensure the buffer can hold one sector
        unsafe {
            let drive_selector = self.drive_selector_from_label(label);
            self.drive_head_port.write(drive_selector | ((lba >> 24) & 0x0F) as u8); // Select drive and head
            self.sector_count_port.write(1); // Read one sector
            self.lba_lo_port.write((lba & 0xFF) as u8);
            self.lba_mid_port.write(((lba >> 8) & 0xFF) as u8);
            self.lba_hi_port.write(((lba >> 16) & 0xFF) as u8);
            self.command_port.write(0x20); // Send read command

            while self.command_port.read() & 0x80 != 0 {} // Wait for BSY to clear

            for chunk in buffer.chunks_mut(2) {
                let data = self.data_port.read();
                chunk[0] = (data & 0xFF) as u8;
                chunk[1] = ((data >> 8) & 0xFF) as u8;
            }
        }
        println!("Sector read successfully from {}.", label);
    }

    pub fn write_sector(&mut self, label: &str, lba: u32, buffer: &[u8]) {
        assert_eq!(buffer.len(), 512); // Ensure the buffer is one sector long
        unsafe {
            let drive_selector = self.drive_selector_from_label(label);
            self.drive_head_port.write(drive_selector | ((lba >> 24) & 0x0F) as u8); // Select drive and head
            self.sector_count_port.write(1); // Write one sector
            self.lba_lo_port.write((lba & 0xFF) as u8);
            self.lba_mid_port.write(((lba >> 8) & 0xFF) as u8);
            self.lba_hi_port.write(((lba >> 16) & 0xFF) as u8);
            self.command_port.write(0x30); // Send write command

            while self.command_port.read() & 0x80 != 0 {} // Wait for BSY to clear

            for chunk in buffer.chunks(2) {
                let data = (u16::from(chunk[1]) << 8) | u16::from(chunk[0]);
                self.data_port.write(data);
            }
        }
        println!("Sector written successfully to {}.", label);
    }
}
bitflags! {
    struct StatusFlags: u8 {
        const ERR = 0x01;
        const IDX = 0x02;
        const CORR = 0x04;
        const DRQ = 0x08;
        const SRV = 0x10;
        const DF = 0x20;
        const RDY = 0x40;
        const BSY = 0x80;
    }
}