use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;
// Trait for iterating over enum variants
use crate::drivers::pci::device_collection::Device;
use crate::println;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::{format, vec};
use alloc::vec::Vec;
use spin::mutex::Mutex;
use spin::Lazy;
use strum_macros::Display;
use crate::drivers::drive::gpt::{Gpt, GptHeader, GptPartitionEntry};
use embedded_crc32c::crc32c;
use crate::drivers::drive::gpt::GptPartitionType::EfiSystemPartition;

// Macro to derive iteration
pub static DRIVECOLLECTION: Lazy<Mutex<DriveCollection>> = Lazy::new(|| {
    Mutex::new(DriveCollection::new())
});
pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
}
impl Controller {
    fn enumerate_drives() {
        //AHCIController::enumerate_drives();
        IdeController::enumerate_drives();
    }
}
#[derive(Debug, Display)]
pub enum FormatStatus {
    TooCorrupted,
    AlreadyFat32,
    DriveDoesntExist,
}
impl FormatStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            FormatStatus::TooCorrupted => "The former Fat32 filesystem is too corrupted to be formatted by this OS please try a different formatter",
            FormatStatus::AlreadyFat32 => "File already exists",
            FormatStatus::DriveDoesntExist => "The drive specified could not be found"
        }
    }
}
pub enum DriveType {
    Master = 0xE0,
    Slave = 0xF0,
    AHCI = 0x00,
}
#[derive(Debug, Clone)]
pub struct DriveInfo {
    pub model: String,
    pub serial: String,
    pub port: u32,
    pub capacity: u64,
}
impl DriveInfo {
    pub fn print(&self) {
        println!("Drive port: {}", self.port);
        println!("Model: {}", self.model);
        println!("Serial Number: {}", self.serial);
        println!("Capacity: {} bytes", self.capacity);
        println!("--------------------------------");
    }
}

// All drives must implement this trait
pub trait DriveController: Send + Sync {
    fn read(&mut self, sector: u32, buffer: &mut [u8]);
    fn write(&mut self, sector: u32, data: &[u8]);
    fn enumerate_drives() -> Vec<Drive>
    where
        Self: Sized;
    fn factory(&self) -> Box<dyn DriveController + Send + Sync>;
    fn is_controller(device: &Device) -> bool
    where
        Self: Sized;
}

pub struct Drive {
    pub info: DriveInfo,
    pub controller: Box<dyn DriveController + Send>,
    pub is_fat: bool,
    pub index: i64,
    pub gpt_data: Option<Gpt>,
}

impl Drive {
    pub fn new(index: i64, info: DriveInfo, controller: Box<dyn DriveController + Send>) -> Self {
        Drive {
            index,
            info,
            controller,
            is_fat: false,
            gpt_data: None
        }
    }
    /// Checks if the drive is using GPT by validating the header.
        pub fn is_gpt(&mut self) -> bool {
            let mut buffer = vec![0u8; 512]; // GPT header is within the first sector (LBA 1)
            self.controller.read(1, &mut buffer);

            if let Some(gpt) = GptHeader::new(&buffer) {
                true
            } else {
                false
            }
        }

        /// Formats the drive as GPT by writing a new GPT header and partition table.
        pub fn format_gpt(&mut self) -> Result<(), String> {
            let sector_size = 512; // Assuming standard 512-byte sectors

            let mut gpt_header = GptHeader {
                signature: *b"EFI PART",
                revision: 0x00010000,
                header_size: 92,
                header_crc32: 0,
                reserved: 0,
                current_lba: 1,
                backup_lba: (self.info.capacity / 512 - 1) as u64, // Last sector as backup
                first_usable_lba: 34,
                last_usable_lba: (self.info.capacity / 512 - 34) as u64,
                disk_guid: [0; 16], // Generate a proper GUID if needed
                partition_entry_lba: 2,
                num_partition_entries: 128,
                partition_entry_size: 128,
                partition_crc32: 0,
                reserved_block: [0; 420],
            };

            let mut partition_entries = vec![GptPartitionEntry {
                partition_type_guid: [0; 16],
                unique_partition_guid: [0; 16],
                first_lba: 0,
                last_lba: 0,
                attribute_flags: 0,
                partition_name: [0; 36],
            }; gpt_header.num_partition_entries as usize];

            let mut partition_buffer = vec![0u8; (gpt_header.num_partition_entries as usize) * gpt_header.partition_entry_size as usize];
            for (i, entry) in partition_entries.iter().enumerate() {
                entry.write_to_buffer(&mut partition_buffer[i * gpt_header.partition_entry_size as usize..])?;
            }
            gpt_header.partition_crc32 = crc32c(&partition_buffer);

            let mut header_buffer = vec![0u8; sector_size];
            gpt_header.write_to_buffer(&mut header_buffer)?;
            gpt_header.header_crc32 = crc32c(&header_buffer[0..gpt_header.header_size as usize]);

            self.controller.write(1, &header_buffer);

            for sector in partition_buffer.chunks_exact(sector_size){
                self.controller.write(2, &sector);
            }

            self.controller.write((self.info.capacity / 512  - 1) as u32, &header_buffer);

            self.gpt_data = Some(Gpt {
                header: gpt_header,
                entries: partition_entries,
            });
            self.add_partition((256 * 1024 * 1024), EfiSystemPartition.to_u8_16(), "EFI_PART".to_string()).expect("TODO: panic message");

            Ok(())
        }
        pub fn add_partition(&mut self, partition_size: u64, partition_type: [u8; 16], part_name: String) -> Result<(), String> {
            // Ensure GPT is initialized
            if(part_name.len() > 72){
                return Err("name too long".to_string());
            }
            let gpt = match self.gpt_data.as_mut() {
                Some(gpt) => gpt,
                None => return Err("GPT is not initialized on this drive.".to_string()),
            };

            let first_usable = gpt.header.first_usable_lba;
            let last_usable = gpt.header.last_usable_lba;
            let sector_size = 512;

            let required_sectors = (partition_size + sector_size - 1) / sector_size;

            let mut partitions = gpt.entries.clone();
            partitions.sort_by_key(|p| p.first_lba);

            let mut start_lba = first_usable;
            let mut found_space = false;

            for partition in &partitions {
                if partition.first_lba == 0 && partition.last_lba == 0 {
                    continue; // Skip unused entries
                }

                let available_sectors = partition.first_lba - start_lba;
                if available_sectors >= required_sectors {
                    found_space = true;
                    break; // We found a suitable gap
                }

                start_lba = partition.last_lba + 1;
            }

            if !found_space {
                let available_sectors = last_usable - start_lba;
                if available_sectors < required_sectors {
                    return Err("Not enough space available for the new partition.".to_string());
                }
            }

            let entry_index = gpt.entries.iter().position(|p| p.first_lba == 0 && p.last_lba == 0)
                .ok_or("No available GPT entry slots.")?;

            let new_partition = GptPartitionEntry {
                partition_type_guid: partition_type,
                unique_partition_guid: [0; 16], // Generate a GUID properly here
                first_lba: start_lba,
                last_lba: start_lba + required_sectors - 1,
                attribute_flags: 0,
                partition_name: name_to_utf16_fixed(part_name.as_str()), // UTF-16 partition name should be set
            };

            gpt.entries[entry_index] = new_partition;

            let mut partition_buffer = vec![0u8; (gpt.header.num_partition_entries as usize) * gpt.header.partition_entry_size as usize];
            for (i, entry) in gpt.entries.iter().enumerate() {
                entry.write_to_buffer(&mut partition_buffer[i * gpt.header.partition_entry_size as usize..])?;
            }
            gpt.header.partition_crc32 = crc32c(&partition_buffer);

            // Update GPT header CRC
            let mut header_buffer = vec![0u8; sector_size as usize];
            gpt.header.write_to_buffer(&mut header_buffer)?;
            gpt.header.header_crc32 = crc32c(&header_buffer[0..gpt.header.header_size as usize]);

            // Write updated GPT structures to disk
            for i in (0..partition_buffer.len()).step_by(sector_size as usize) {
                let sector = &partition_buffer[i..i + sector_size as usize];
                self.controller.write((i + 2) as u32, sector );
            }
            self.controller.write(1, &header_buffer);
            self.controller.write((self.info.capacity / 512 - 1) as u32, &header_buffer); // Backup GPT

            Ok(())
        }

}
fn name_to_utf16_fixed(name: &str) -> [u16; 36] {
    let mut buffer = [0x0000; 36]; // Fill with null terminators
    let utf16_iter = name.encode_utf16();

    for (i, c) in utf16_iter.take(36).enumerate() {
        buffer[i] = c;
    }

    buffer
}


pub struct DriveCollection {
    pub drives: Vec<Drive>,

}

impl DriveCollection {
    fn new() -> Self {
        DriveCollection {
            drives: Vec::new(),
        }
    }

    pub(crate) fn new_drive(&mut self, index: i64, info: DriveInfo, controller: Box<dyn DriveController + Send>) {
        let drive = Drive::new(index, info, controller);
        self.drives.push(drive);
    }
    pub(crate) fn enumerate_drives(&mut self) {
        let mut drives = Vec::new();
        drives.extend(<IdeController as DriveController>::enumerate_drives());
        //drives.extend(<AHCIController as DriveController>::enumerate_drives());

        for mut drive in drives {
            if (drive.index == -1) {
                drive.index = self.drives.len() as i64;
                self.drives.push(drive);
            }
        }
    }
    pub fn print_drives(&self) {
        if self.drives.is_empty() {
            println!("No drives in the collection.");
        } else {
            for (i, drive) in self.drives.iter().enumerate() {
                println!("Drive {}:", i + 1);
                println!("Index: {}", drive.index);
                drive.info.print(); // Call the print method of DriveInfo
            }
        }
    }
}
