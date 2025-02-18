use crate::drivers::drive::generic_drive::{DriveController, FormatStatus, DRIVECOLLECTION};
use crate::file_system::fat::{FileSystem, INFO_SECTOR};
use crate::println;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use spin::mutex::Mutex;
use spin::Lazy;

pub static PARTITIONS: Lazy<Mutex<PartitionCollection>> = Lazy::new(|| {
    Mutex::new(PartitionCollection::new())
});
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptPartitionType {
    EfiSystemPartition,
    MicrosoftReserved,
    MicrosoftBasicData,
    LinuxFilesystem,
    LinuxSwap,
    LinuxRootX86_64,
    Unknown([u8; 16]), // Fallback for unrecognized GUIDs
}

impl GptPartitionType {
    /// Converts the partition type into a 16-byte GUID (stored in little-endian format)
    pub fn to_u8_16(&self) -> [u8; 16] {
        match self {
            GptPartitionType::EfiSystemPartition => [
                0xC1, 0x2A, 0x73, 0x28, 0xF8, 0x1F, 0x11, 0xD2,
                0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
            ],
            GptPartitionType::MicrosoftReserved => [
                0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D,
                0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE,
            ],
            GptPartitionType::MicrosoftBasicData => [
                0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
                0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
            ],
            GptPartitionType::LinuxFilesystem => [
                0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
            ],
            GptPartitionType::LinuxSwap => [
                0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43,
                0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F,
            ],
            GptPartitionType::LinuxRootX86_64 => [
                0xE3, 0xBC, 0x68, 0x4F, 0xCD, 0xE8, 0xB1, 0x4D,
                0x96, 0xE7, 0xFB, 0xCA, 0xF9, 0x84, 0xB7, 0x09,
            ],
            GptPartitionType::Unknown(guid) => *guid,
        }
    }

    /// Converts a `[u8; 16]` GUID to a `GptPartitionType`
    pub fn from_u8_16(guid: [u8; 16]) -> Self {
        match guid {
            [0xC1, 0x2A, 0x73, 0x28, 0xF8, 0x1F, 0x11, 0xD2, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B] => Self::EfiSystemPartition,
            [0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE] => Self::MicrosoftReserved,
            [0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7] => Self::MicrosoftBasicData,
            [0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4] => Self::LinuxFilesystem,
            [0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43, 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F] => Self::LinuxSwap,
            [0xE3, 0xBC, 0x68, 0x4F, 0xCD, 0xE8, 0xB1, 0x4D, 0x96, 0xE7, 0xFB, 0xCA, 0xF9, 0x84, 0xB7, 0x09] => Self::LinuxRootX86_64,
            _ => Self::Unknown(guid),
        }
    }
}

pub struct Gpt {
    /// The GPT header
    pub header: GptHeader,
    /// A vector of GPT partition entries
    pub entries: Vec<GptPartitionEntry>,
}

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
    pub fn new(buffer: &[u8]) -> Option<Self> {
        // Ensure the buffer is at least 92 bytes (header size)
        if buffer.len() < 92 {
            return None;
        }
        // Extract the first 92 bytes
        let header_bytes = &buffer[0..92];

        // Perform an unsafe cast to GptHeader
        let header: GptHeader = unsafe { core::ptr::read(header_bytes.as_ptr() as *const _) };

        if (header.is_valid_signature()) {
            Some(header)
        } else {
            None
        }
    }
    pub fn write_to_buffer(&self, buffer: &mut [u8]) {
        if buffer.len() < core::mem::size_of::<GptHeader>() {
            panic!("Too small buffer passed to GptHeader::write_to_buffer")
        }

        // Safety: Copy the struct into the buffer
        unsafe {
            core::ptr::write_unaligned(buffer.as_mut_ptr() as *mut GptHeader, *self);
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

impl GptPartitionEntry {
    /// Creates a new GptPartitionEntry from a 128-byte chunk.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 128 {
            return None; // Ensure the slice is exactly 128 bytes
        }

        Some(Self {
            partition_type_guid: bytes[0x00..0x10].try_into().unwrap(),
            unique_partition_guid: bytes[0x10..0x20].try_into().unwrap(),
            first_lba: u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap()),
            last_lba: u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()),
            attribute_flags: u64::from_le_bytes(bytes[0x30..0x38].try_into().unwrap()),
            partition_name: {
                let mut name = [0u16; 36];
                for (i, chunk) in bytes[0x38..0x80].chunks_exact(2).enumerate() {
                    name[i] = u16::from_le_bytes(chunk.try_into().unwrap());
                }
                name
            },
        })
    }
    pub fn write_to_buffer(&self, buffer: &mut [u8]) {
        if buffer.len() < core::mem::size_of::<GptPartitionEntry>() {
            panic!("Too small buffer passed to GptEntry write buffer");
        }

        // Copy the fields manually to ensure proper layout
        buffer[0x00..0x10].copy_from_slice(&self.partition_type_guid);
        buffer[0x10..0x20].copy_from_slice(&self.unique_partition_guid);
        buffer[0x20..0x28].copy_from_slice(&self.first_lba.to_le_bytes());
        buffer[0x28..0x30].copy_from_slice(&self.last_lba.to_le_bytes());
        buffer[0x30..0x38].copy_from_slice(&self.attribute_flags.to_le_bytes());

        // Partition name (convert u16 to little-endian bytes)
        for (i, &ch) in self.partition_name.iter().enumerate() {
            let start = 0x38 + i * 2;
            let end = start + 2;
            buffer[start..end].copy_from_slice(&ch.to_le_bytes());
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

    pub(crate) fn new_partition(&mut self, mut entry: GptPartitionEntry, drive_index: u64, controller: Box<dyn DriveController + Send + Sync>) -> Result<(), &'static str> {
        if let Some(label) = self.find_free_label() {
            let drive = Partition::new(label, String::from_utf16(&mut entry.partition_name).unwrap().to_string(), drive_index, controller, entry.first_lba, entry.last_lba);

            self.parts.push(drive);
            Ok(())
        } else {
            Err("No available label")
        }
    }
    pub(crate) fn enumerate_parts(&mut self) {
        let mut i = 0;
        for drive in DRIVECOLLECTION.lock().drives.iter_mut() {
            let mut buffer = vec![0u8; 512];
            drive.controller.read(1, &mut buffer);
            if let Some(header) = GptHeader::new(&mut buffer) {
                buffer.fill(0);

                for sector in 2..=33 {
                    drive.controller.read(sector, &mut buffer);

                    for chunk_start in (0..buffer.len()).step_by(128) {
                        let mut slice_128: &[u8] = &buffer[chunk_start..chunk_start + 128];

                        // Check if the 128-byte chunk is empty
                        if slice_128.iter().all(|&b| b == 0) {
                            continue;
                        }

                        if let Some(entry) = GptPartitionEntry::new(&mut slice_128) {
                            self.new_partition(entry, sector as u64, drive.controller.factory()).expect("TODO: panic message");
                        }
                    }
                }
            }
            i += 1;
        }
    }

    pub fn find_volume(&mut self, label: String) -> Option<&mut Partition> {
        for drive in self.parts.iter_mut() { // Iterate over mutable references
            if drive.label == label {
                return Some(drive); // Return the mutable reference
            }
        }
        None
    }
    pub fn print_parts(&self) {
        if self.parts.is_empty() {
            println!("No drives in the collection.");
        } else {
            for (i, drive) in self.parts.iter().enumerate() {
                println!("Part: ({})", drive.label);
                println!("Name: ({})", drive.name);
                println!("is fat: {}", drive.is_fat);
                println!("parent drive: {}", drive.parent_drive_index);
                println!("Capacity: {}", drive.size);
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
    pub(crate) label: String,
    pub(crate) size: u64,
    controller: PartitionController,
    pub(crate) is_fat: bool,
}
impl Partition {
    pub fn new(label: String, name: String, parent_drive_index: u64, controller: Box<dyn DriveController + Send + Sync>, start_lba: u64, end_lba: u64) -> Self {
        let mut part_controller = PartitionController::new(controller, start_lba, end_lba);
        let mut sector = vec![0u8; 512];
        part_controller.read(INFO_SECTOR, &mut sector).expect("failed to read info sector");
        let fat_present = FileSystem::is_fat_present(sector);
        Partition {
            parent_drive_index,
            name,
            label: label.clone(),
            size: ((end_lba - start_lba) * 512),
            controller: part_controller,
            is_fat: fat_present,
        }
    }
    pub fn format(&mut self) -> Result<(), FormatStatus> {
        if (self.is_fat == false) {
            let mut fs = FileSystem::new(self.label.clone(), self.size);
            return fs.format_drive();
        }
        Err(FormatStatus::AlreadyFat32)
    }
    pub fn force_format(&mut self) -> Result<(), FormatStatus> {
        FileSystem::new(self.label.clone(), self.size).format_drive()
    }
    pub fn read(&mut self, sector: u32, buffer: &mut [u8]) {
        self.controller.read(sector, buffer).expect("File read failed");
    }
    pub fn write(&mut self, sector: u32, data: &[u8]) {
        self.controller.write(sector, data).expect("File write failed");
    }
    pub fn get_start_lba(&self) -> u32 {
        self.controller.start_lba as u32
    }
}
pub struct PartitionController {
    /// Underlying drive controller
    drive_controller: Box<dyn DriveController>,
    /// Starting LBA of the partition
    start_lba: u64,
    /// Ending LBA of the partition (inclusive)
    end_lba: u64,
}

impl PartitionController {
    /// Create a new PartitionController
    pub fn new(
        drive_controller: Box<dyn DriveController + Send + Sync>,
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
pub fn scan_for_efi_signature(buffer: &[u8]) -> Option<usize> {
    let efi_sig: [u8; 8] = *b"EFI PART";

    // Iterate over the buffer using an 8-byte sliding window to find the signature
    buffer.windows(8).position(|window| window == efi_sig)
}

pub const MBR: [u8; 512] = [
    0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0x8E, 0xC0, 0x8E, 0xD8, 0xBE, 0x00, 0x7C, 0xBF, 0x00,
    0x06, 0xB9, 0x00, 0x02, 0xFC, 0xF3, 0xA4, 0x50, 0x68, 0x1C, 0x06, 0xCB, 0xFB, 0xB9, 0x04, 0x00,
    0xBD, 0xBE, 0x07, 0x80, 0x7E, 0x00, 0x00, 0x7C, 0x0B, 0x0F, 0x85, 0x0E, 0x01, 0x83, 0xC5, 0x10,
    0xE2, 0xF1, 0xCD, 0x18, 0x88, 0x56, 0x00, 0x55, 0xC6, 0x46, 0x11, 0x05, 0xC6, 0x46, 0x10, 0x00,
    0xB4, 0x41, 0xBB, 0xAA, 0x55, 0xCD, 0x13, 0x5D, 0x72, 0x0F, 0x81, 0xFB, 0x55, 0xAA, 0x75, 0x09,
    0xF7, 0xC1, 0x01, 0x00, 0x74, 0x03, 0xFE, 0x46, 0x10, 0x66, 0x60, 0x80, 0x7E, 0x10, 0x00, 0x74,
    0x26, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0xFF, 0x76, 0x08, 0x68, 0x00, 0x00, 0x68, 0x00,
    0x7C, 0x68, 0x01, 0x00, 0x68, 0x10, 0x00, 0xB4, 0x42, 0x8A, 0x56, 0x00, 0x8B, 0xF4, 0xCD, 0x13,
    0x9F, 0x83, 0xC4, 0x10, 0x9E, 0xEB, 0x14, 0xB8, 0x01, 0x02, 0xBB, 0x00, 0x7C, 0x8A, 0x56, 0x00,
    0x8A, 0x76, 0x01, 0x8A, 0x4E, 0x02, 0x8A, 0x6E, 0x03, 0xCD, 0x13, 0x66, 0x61, 0x73, 0x1C, 0xFE,
    0x4E, 0x11, 0x75, 0x0C, 0x80, 0x7E, 0x00, 0x80, 0x0F, 0x84, 0x8A, 0x00, 0xB2, 0x80, 0xEB, 0x84,
    0x55, 0x32, 0xE4, 0x8A, 0x56, 0x00, 0xCD, 0x13, 0x5D, 0xEB, 0x9E, 0x81, 0x3E, 0xFE, 0x7D, 0x55,
    0xAA, 0x75, 0x6E, 0xFF, 0x76, 0x00, 0xE8, 0x8D, 0x00, 0x75, 0x17, 0xFA, 0xB0, 0xD1, 0xE6, 0x64,
    0xE8, 0x83, 0x00, 0xB0, 0xDF, 0xE6, 0x60, 0xE8, 0x7C, 0x00, 0xB0, 0xFF, 0xE6, 0x64, 0xE8, 0x75,
    0x00, 0xFB, 0xB8, 0x00, 0xBB, 0xCD, 0x1A, 0x66, 0x23, 0xC0, 0x75, 0x3B, 0x66, 0x81, 0xFB, 0x54,
    0x43, 0x50, 0x41, 0x75, 0x32, 0x81, 0xF9, 0x02, 0x01, 0x72, 0x2C, 0x66, 0x68, 0x07, 0xBB, 0x00,
    0x00, 0x66, 0x68, 0x00, 0x02, 0x00, 0x00, 0x66, 0x68, 0x08, 0x00, 0x00, 0x00, 0x66, 0x53, 0x66,
    0x53, 0x66, 0x55, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0x68, 0x00, 0x7C, 0x00, 0x00, 0x66,
    0x61, 0x68, 0x00, 0x00, 0x07, 0xCD, 0x1A, 0x5A, 0x32, 0xF6, 0xEA, 0x00, 0x7C, 0x00, 0x00, 0xCD,
    0x18, 0xA0, 0xB7, 0x07, 0xEB, 0x08, 0xA0, 0xB6, 0x07, 0xEB, 0x03, 0xA0, 0xB5, 0x07, 0x32, 0xE4,
    0x05, 0x00, 0x07, 0x8B, 0xF0, 0xAC, 0x3C, 0x00, 0x74, 0x09, 0xBB, 0x07, 0x00, 0xB4, 0x0E, 0xCD,
    0x10, 0xEB, 0xF2, 0xF4, 0xEB, 0xFD, 0x2B, 0xC9, 0xE4, 0x64, 0xEB, 0x00, 0x24, 0x02, 0xE0, 0xF8,
    0x24, 0x02, 0xC3, 0x49, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x20, 0x70, 0x61, 0x72, 0x74, 0x69,
    0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x00, 0x45, 0x72, 0x72, 0x6F, 0x72,
    0x20, 0x6C, 0x6F, 0x61, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,
    0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x00, 0x4D, 0x69, 0x73, 0x73, 0x69, 0x6E,
    0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x6D, 0x00, 0x00, 0x00, 0x63, 0x7B, 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0xEE, 0xFE, 0x7F, 0x18, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xAA,
];