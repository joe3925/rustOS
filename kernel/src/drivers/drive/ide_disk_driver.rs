use crate::cpu::get_cycles;
use crate::drivers::drive::generic_drive::{Drive, DriveController, DriveInfo, DriveType};
use crate::drivers::interrupt_index::send_eoi;
use crate::drivers::pci::device_collection::Device;
use crate::drivers::pci::pci_bus::PCIBUS;
use crate::{drivers, println};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::instructions::port::Port;
use x86_64::structures::idt::InterruptStackFrame;

const PRIMARY_CMD_BASE: u16 = 0x1F0;
const PRIMARY_CTRL_BASE: u16 = 0x3F6;

const DATA_REG: u16 = PRIMARY_CMD_BASE + 0;
const ERROR_REG: u16 = PRIMARY_CMD_BASE + 1; // Same as FEATURES_REG for writing
const SECTOR_COUNT_REG: u16 = PRIMARY_CMD_BASE + 2;
const LBA_LO_REG: u16 = PRIMARY_CMD_BASE + 3;
const LBA_MID_REG: u16 = PRIMARY_CMD_BASE + 4;
const LBA_HI_REG: u16 = PRIMARY_CMD_BASE + 5;
const DRIVE_HEAD_REG: u16 = PRIMARY_CMD_BASE + 6;
const STATUS_REG: u16 = PRIMARY_CTRL_BASE; // Same as CMD_REG for writing
const PRIMARY_STATUS_REG: u16 = PRIMARY_CMD_BASE + 7;
const CONTROL_REG: u16 = PRIMARY_CTRL_BASE + 2;

pub fn has_ide_controller() -> bool {
    for device in &PCIBUS.device_collection.devices {
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
// Global flag to indicate when the IRQ is received
static DRIVE_IRQ_RECEIVED: AtomicBool = AtomicBool::new(false);

pub(crate) extern "x86-interrupt" fn primary_drive_irq_handler(_stack_frame: InterruptStackFrame) {
    unsafe {
        let mut status_port = Port::new(PRIMARY_CMD_BASE + 7);
        let status: u8 = status_port.read();  // Read the status register

        while status & 0x40 == 0 { println!("Drive not ready"); }
        while status & 0x20 != 0 { println!("Drive faulted!"); }

        if status & 0x01 != 0 {
            println!("Error: Read sector failed!");
        }

        DRIVE_IRQ_RECEIVED.store(true, Ordering::SeqCst);


        // 3. Send End of Interrupt (EOI) to both PICs
        send_eoi(drivers::interrupt_index::InterruptIndex::PrimaryDrive.as_u8());
    }
}
pub(crate) extern "x86-interrupt" fn secondary_drive_irq_handler(_stack_frame: InterruptStackFrame) {
    // Set the global flag to indicate that the IRQ was received
    DRIVE_IRQ_RECEIVED.store(true, Ordering::SeqCst);
    println!("secondary: {}", get_cycles());
    // Acknowledge the IRQ (send End of Interrupt to PIC)
    send_eoi(drivers::interrupt_index::InterruptIndex::PrimaryDrive.as_u8());
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
    alternative_command_port: Port<u8>,
    control_port: Port<u8>,
    managed_port: u8,
}

impl IdeController {
    pub const fn new(managed_port: u32) -> Self {
        IdeController {
            data_port: Port::new(DATA_REG),
            error_port: Port::new(ERROR_REG),
            sector_count_port: Port::new(SECTOR_COUNT_REG),
            lba_lo_port: Port::new(LBA_LO_REG),
            lba_mid_port: Port::new(LBA_MID_REG),
            lba_hi_port: Port::new(LBA_HI_REG),
            drive_head_port: Port::new(DRIVE_HEAD_REG),
            command_port: Port::new(PRIMARY_STATUS_REG),
            alternative_command_port: Port::new(STATUS_REG),
            control_port: Port::new(CONTROL_REG),
            managed_port: managed_port as u8,
        }
    }
    unsafe fn identify_drive(drive: u8) -> Option<DriveInfo> {
        unsafe {
            let mut head_port = Port::new(DRIVE_HEAD_REG);
            let mut command_port = Port::new(PRIMARY_STATUS_REG);
            let mut data_port = Port::new(DATA_REG);
            head_port.write(0xE0 | (drive << 4)); // Select drive (0 = master, 1 = slave)
            command_port.write(0xEC); // Send IDENTIFY command
            if StatusFlags::from_bits_truncate(command_port.read()).contains(StatusFlags::ERR) {
                return None; // If error, drive does not exist
            }

            // Read IDENTIFY data
            let mut data = [0u16; 256];
            for word in data.iter_mut() {
                *word = data_port.read();
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
                port: if drive == 0 { 0xE0 } else { 0xF0 },
                model,
                serial,
                capacity,
            })
        }
    }
    fn status(&mut self) -> StatusFlags {
        unsafe { StatusFlags::from_bits_truncate(self.command_port.read()) }
    }
}

impl DriveController for IdeController {
    fn read(&mut self, lba: u32, buffer: &mut [u8]) {
        assert_eq!(buffer.len(), 512);  // Ensure buffer size is 512 bytes (one sector)

        unsafe {
            let drive_selector = self.managed_port;

            // Wait until the drive is not busy
            while self.command_port.read() & 0x80 != 0 {}  // BSY

            // Ensure drive is ready and no fault occurred
            while self.command_port.read() & 0x40 == 0 {  }
            while self.command_port.read() & 0x20 != 0 { println!("Drive faulted!"); }

            if self.command_port.read() & 0x01 != 0 {
                println!("Error: IDE command failed!");
            }

            // Send command to read from the sector
            self.drive_head_port.write(drive_selector | (((lba >> 24) & 0x0F) as u8));
            while self.command_port.read() & 0x80 != 0 {}  // BSY

            self.sector_count_port.write(1);  // Request 1 sector
            self.lba_lo_port.write((lba & 0xFF) as u8);
            self.lba_mid_port.write(((lba >> 8) & 0xFF) as u8);
            self.lba_hi_port.write(((lba >> 16) & 0xFF) as u8);
            self.command_port.write(0x20);  // Command to read

            while self.command_port.read() & 0x80 != 0 {}  // BSY
            while self.command_port.read() & 0x40 == 0 {  }
            while self.command_port.read() & 0x20 != 0 { println!("Drive faulted!"); }

            // Check if there was an error
            if self.command_port.read() & 0x01 != 0 {
                println!("Error: Read sector failed!");
            }
            if self.error_port.read() & 0x10 != 0 {
                println!("Tried to read from non existent sector");
                return;
            }

            // Transfer data in chunks of 2 bytes (16-bit data)
            for chunk in buffer.chunks_mut(2) {
                let data = self.data_port.read();  // Read 16-bit data
                chunk[0] = (data & 0xFF) as u8;    // Lower byte
                chunk[1] = ((data >> 8) & 0xFF) as u8;  // Upper byte
            }
        }
    }
    fn write(&mut self, lba: u32, buffer: &[u8]) {
        assert_eq!(buffer.len(), 512);

        unsafe {
            let drive_selector = self.managed_port;
            // Wait until the drive is not busy
            while self.alternative_command_port.read() & 0x80 != 0 {}  // BSY

            // Ensure drive is ready and no fault occurred
            while self.alternative_command_port.read() & 0x40 == 0 {}
            while self.alternative_command_port.read() & 0x20 != 0 { println!("Drive faulted!"); }

            if self.alternative_command_port.read() & 0x01 != 0 {
                println!("Error: IDE command failed!");
            }

            // Send command to write to the sector
            self.drive_head_port.write(drive_selector | (((lba >> 24) & 0x0F) as u8));
            while self.command_port.read() & 0x80 != 0 {}  // BSY
            self.sector_count_port.write(1);
            self.lba_lo_port.write((lba & 0xFF) as u8);
            self.lba_mid_port.write(((lba >> 8) & 0xFF) as u8);
            self.lba_hi_port.write(((lba >> 16) & 0xFF) as u8);
            self.command_port.write(0x30);  // Command to write

            while self.command_port.read() & 0x80 != 0 { println!("Drive busy"); }  // BSY
            while self.command_port.read() & 0x40 == 0 {}
            while self.command_port.read() & 0x20 != 0 { println!("Drive faulted!"); }

            //while !DRIVE_IRQ_RECEIVED.load(Ordering::SeqCst) {  }
            // Check if there was an error
            if self.alternative_command_port.read() & 0x01 != 0 {
                println!("Error: Read sector failed!");
            }
            //DRIVE_IRQ_RECEIVED.store(false, Ordering::SeqCst);

            if self.error_port.read() & 0x10 != 0 {
                println!("Tried to write to non existent sector");
                return;
            }
            // Transfer data in chunks of 2 bytes (16-bit data)
            for chunk in buffer.chunks(2) {
                let data = (u16::from(chunk[1]) << 8) | u16::from(chunk[0]);
                self.data_port.write(data);
            }
        }
    }
    fn enumerate_drives() -> Vec<Drive> {
        let mut drive_list: Vec<Drive> = Vec::new();
        let ide_controller = Self::new(0x0);

        // Check for the master drive
        unsafe {
            if let Some(info) = IdeController::identify_drive(0) {
                if (info.capacity != 0) {
                    drive_list.push(Drive::new(-1, info, Box::new(IdeController::new(DriveType::Master as u32))));
                }
            }
        }


        // Check for the slave drive
        unsafe {
            if let Some(info) = IdeController::identify_drive(1) {
                if (info.capacity != 0) {
                    drive_list.push(Drive::new(-1, info, Box::new(IdeController::new(DriveType::Slave as u32))));
                }
            }
        }
        drive_list
    }

    fn factory(&self) -> Box<dyn DriveController + Send + Sync> {
        Box::new(IdeController::new(self.managed_port as u32)) // Cloning with new instance
    }
    fn is_controller(device: &Device) -> bool {
        if (device.class_code == 0x01 && device.subclass == 0x01) {
            return true;
        }
        false
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