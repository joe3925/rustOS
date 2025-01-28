use crate::drivers::drive::generic_drive::{Drive, DriveCollection, DriveController, DriveInfo, DRIVECOLLECTION};
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::println;
use alloc::boxed::Box;
use alloc::{format, vec};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::mutex::Mutex;
use spin::Lazy;

pub static PARTITIONS: Lazy<Mutex<PartitionCollection>> = Lazy::new(|| {
    Mutex::new(PartitionCollection::new())
});
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GptHeader {
    /// 0x00: Signature ("EFI PART", 8 bytes)
    pub signature: [u8; 8],
    /// 0x08: Revision number of header (4 bytes)
    pub revision: u32,
    /// 0x0C: Header size in little endian (4 bytes)
    pub header_size: u32,
    /// 0x10: CRC32 of header (4 bytes)
    pub header_crc32: u32,
    /// 0x14: Reserved; must be zero (4 bytes)
    pub reserved: u32,
    /// 0x18: Current LBA (8 bytes)
    pub current_lba: u64,
    /// 0x20: Backup LBA (8 bytes)
    pub backup_lba: u64,
    /// 0x28: First usable LBA for partitions (8 bytes)
    pub first_usable_lba: u64,
    /// 0x30: Last usable LBA (8 bytes)
    pub last_usable_lba: u64,
    /// 0x38: Disk GUID in mixed endian (16 bytes)
    pub disk_guid: [u8; 16],
    /// 0x48: Starting LBA of array of partition entries (8 bytes)
    pub partition_entry_lba: u64,
    /// 0x50: Number of partition entries in array (4 bytes)
    pub num_partition_entries: u32,
    /// 0x54: Size of a single partition entry (4 bytes)
    pub partition_entry_size: u32,
    /// 0x58: CRC32 of partition entries array (4 bytes)
    pub partition_crc32: u32,
    /// 0x5C: Reserved; must be zeroes for the rest of the block (420 bytes for 512-byte sectors)
    pub reserved_block: [u8; 420],
}

impl GptHeader {
    /// Function to validate the GPT signature
    pub fn is_valid_signature(&self) -> bool {
        &self.signature == b"EFI PART"
    }
    pub const fn new(buffer: &[u8]) -> Option<Self> {
        // Ensure the buffer is at least 92 bytes (header size)
        if buffer.len() < 92 {
            return None;
        }

        // Extract the first 92 bytes
        let header_bytes = &buffer[0..92];

        // Perform an unsafe cast to GptHeader
        let header: GptHeader = unsafe { core::ptr::read(header_bytes.as_ptr() as *const _) };

        if(header.is_valid_signature()) {
            Some(header)
        }else{
            None
        }
    }
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GptPartitionEntry {
    /// 0x00: Partition type GUID (16 bytes, mixed endian)
    pub partition_type_guid: [u8; 16],
    /// 0x10: Unique partition GUID (16 bytes, mixed endian)
    pub unique_partition_guid: [u8; 16],
    /// 0x20: First LBA (8 bytes, little endian)
    pub first_lba: u64,
    /// 0x28: Last LBA (8 bytes, little endian, inclusive)
    pub last_lba: u64,
    /// 0x30: Attribute flags (8 bytes)
    pub attribute_flags: u64,
    /// 0x38: Partition name (72 bytes, 36 UTF-16LE code units)
    pub partition_name: [u16; 36],
}

impl GptPartitionEntry {}

#[derive(Debug, Clone)]
pub struct GptDrive {
    pub label: String,
    pub info: DriveInfo,
    pub partition_table: Vec<GptPartitionEntry>, // GPT-specific data
    pub header: GptHeader,
}

impl GptDrive {
    pub fn new(label: String, info: DriveInfo, header: GptHeader) -> Self {
        GptDrive {
            label,
            info,
            partition_table: Vec::new(),
            header,
        }
    }
}
pub struct PartitionCollection {
    pub parts: Vec<Partition>,
}
impl PartitionCollection {
    fn new() -> Self {
        PartitionCollection {
            parts: Vec::new(),
        }
    }

    pub(crate) fn new_partition(&mut self, entry: GptPartitionEntry, drive_index: u64, controller: Box<dyn DriveController + Send>) -> Result<(), &'static str>  {
        if let Some(label) = self.find_free_label() {
            let drive = Partition::new(label,"TODO".to_string(), drive_index, controller, entry.first_lba, entry.last_lba);
            self.parts.push(drive);
            Ok(())
        }else{
            Err("No available label")
        }
    }
    pub(crate) fn enumerate_drives(&mut self) {
        for mut drive in DRIVECOLLECTION.lock().drives {
            let buffer = vec![0u8; 512];
            drive.controller.read(1, &mut buffer.as_slice());
            if let Some(header) = GptHeader::new(buffer.as_slice()){
                //TODO: add function to return a vec of partitions from the drive
            }
        }
    }
    pub fn find_drive(&mut self, label: String) -> Option<&mut Drive> {
        for drive in self.parts.iter_mut() { // Iterate over mutable references
            if drive.label == label {
                return Some(drive); // Return the mutable reference
            }
        }
        None
    }
    pub fn print_drives(&self) {
        if self.parts.is_empty() {
            println!("No drives in the collection.");
        } else {
            for (i, drive) in self.parts.iter().enumerate() {
                println!("Drive {}:", i + 1);
                println!("Label: {}", drive.label);
                drive.info.print(); // Call the print method of DriveInfo
            }
        }
    }
    pub fn find_free_label(&self) -> Option<String> {
        let mut used_labels = [false; 26]; // A flag array for each letter A-Z

        // Mark used labels
        for drive in &self.parts {
            if let Some(first_char) = drive.label.chars().next() {
                if first_char.is_ascii_alphabetic() {
                    let index = (first_char.to_ascii_uppercase() as u8 - b'A') as usize;
                    if index < 26 {
                        used_labels[index] = true;
                    }
                }
            }
        }

        // Find the first unused label from A: to Z:
        for i in 0..26 {
            if !used_labels[i] {
                let letter = (b'A' + i as u8) as char;
                return Some(format!("{}:", letter)); // Correctly format the label (e.g., "A:")
            }
        }

        None // No free label found
    }
}
pub struct Partition {
    parent_drive_index: u64,
    name: String,
    label: String,
    controller: PartitionController,
}
impl Partition {
    pub fn new(label: String, name: String, parent_drive_index: u64, controller: Box<dyn DriveController + Send>, start_lba: u64, end_lba: u64) -> Self {
        Partition {
            parent_drive_index,
            name
            label,
            controller: PartitionController::new(controller, start_lba, end_lba),
        }
    }
    pub fn read(&mut self, sector: u32, buffer: &mut [u8]) {
        self.controller.read(sector, buffer);
    }
    pub fn write(&mut self, sector: u32, data: &[u8]) {
        self.controller.write(sector, data);
    }
}
pub struct PartitionController {
    /// Underlying drive controller
    drive_controller: Box<dyn DriveController + Send>,
    /// Starting LBA of the partition
    start_lba: u64,
    /// Ending LBA of the partition (inclusive)
    end_lba: u64,
}

impl PartitionController {
    /// Create a new PartitionController
    pub fn new(
        drive_controller: Box<dyn DriveController + Send>,
        start_lba: u64,
        end_lba: u64,
    ) -> Self {
        PartitionController {
            drive_controller,
            start_lba,
            end_lba,
        }
    }

    /// Convert the logical sector to the actual physical sector on the underlying drive
    fn map_sector(&self, logical_sector: u32) -> u64 {
        self.start_lba + logical_sector as u64
    }

    /// Read sectors from the partition
    pub fn read(&mut self, sector: u32, buffer: &mut [u8]) -> Result<(), &'static str> {
        let physical_sector = self.map_sector(sector);

        if physical_sector > self.end_lba {
            return Err("Attempt to read beyond partition boundary");
        }

        self.drive_controller.read(physical_sector as u32, buffer);
        Ok(())
    }

    /// Write sectors to the partition
    pub fn write(&mut self, sector: u32, data: &[u8]) -> Result<(), &'static str> {
        let physical_sector = self.map_sector(sector);

        if physical_sector > self.end_lba {
            return Err("Attempt to write beyond partition boundary");
        }

        self.drive_controller.write(physical_sector as u32, data);
        Ok(())
    }
}