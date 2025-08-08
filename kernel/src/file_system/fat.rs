use crate::drivers::drive::generic_drive::FormatStatus;
use crate::drivers::drive::generic_drive::FormatStatus::TooCorrupted;
use crate::drivers::drive::gpt::Partition;
use crate::file_system::file::FileStatus::PathNotFound;
use crate::file_system::file::{File, FileAttribute, FileStatus};
use crate::println;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt::Debug;

//
//
//
//
//
// if it works it works
//
//
//
//
//
//
//
//

const CLUSTER_SIZE: u32 = 32; //in KiB
const CLUSTER_OFFSET: u32 = CLUSTER_SIZE * 1024;
const SECTORS_PER_CLUSTER: u32 = (CLUSTER_SIZE * 1024) / 512;
const RESERVED_SECTORS: u32 = 32;
pub const INFO_SECTOR: u32 = 1;
const NUM_FATS: u8 = 1;
const SECTOR_SIZE: u16 = 512;
#[repr(C, packed)]
pub struct BIOSParameterBlock {
    pub jmp_boot: [u8; 3],         // Jump instruction to bootstrap code
    pub oem_name: [u8; 8],         // OEM Identifier (e.g., "MSWIN4.1")
    pub bytes_per_sector: u16,     // Bytes per sector (512, 1024, 2048, or 4096)
    pub sectors_per_cluster: u8,   // Sectors per allocation unit (1,2,4,8,16,32,64,128)
    pub reserved_sectors: u16,     // Number of reserved sectors
    pub num_fats: u8,              // Number of FATs (usually 2)
    pub root_entry_count: u16,     // Always 0 for FAT32
    pub total_sectors_16: u16,     // 16-bit total sector count (0 if FAT32)
    pub media_descriptor: u8,      // Media descriptor type
    pub fat_size_16: u16,          // FAT size in sectors (0 for FAT32)
    pub sectors_per_track: u16,    // Sectors per track (for CHS addressing)
    pub num_heads: u16,            // Number of heads (for CHS addressing)
    pub hidden_sectors: u32,       // Hidden sectors before FAT32 partition
    pub total_sectors_32: u32,     // 32-bit total sector count
    pub fat_size_32: u32,          // FAT size in sectors (FAT32 only)
    pub ext_flags: u16,            // Flags (e.g., active FAT, mirroring)
    pub fs_version: u16,           // FAT32 version (usually 0x0000)
    pub root_cluster: u32,         // Root directory starting cluster (typically 2)
    pub fs_info_sector: u16,       // Sector number of FSINFO structure
    pub backup_boot_sector: u16,   // Sector number of backup boot sector
    pub reserved: [u8; 12],        // Reserved space (must be zero)
    pub drive_number: u8,          // Logical drive number (0x80 for HDD, 0x00 for FDD)
    pub reserved1: u8,             // Reserved (must be zero)
    pub boot_signature: u8,        // Boot signature (0x29 indicates BPB is present)
    pub volume_id: u32,            // Volume serial number
    pub volume_label: [u8; 11],    // Volume label (e.g., "NO NAME    ")
    pub file_system_type: [u8; 8], // Always "FAT32   "
}

impl BIOSParameterBlock {
    pub fn new(total_sectors: u32, fat_size: u32) -> Self {
        BIOSParameterBlock {
            jmp_boot: [0xEB, 0x58, 0x90],                   // Standard jump code
            oem_name: *b"MSWIN4.1",                         // Standard OEM name
            bytes_per_sector: 512,                          // Standard sector size
            sectors_per_cluster: SECTORS_PER_CLUSTER as u8, // Must be power of 2, chosen for performance
            reserved_sectors: RESERVED_SECTORS as u16,      // Typically 32 for FAT32
            num_fats: 1,
            root_entry_count: 0,             // Always 0 for FAT32
            total_sectors_16: 0,             // Use total_sectors_32 for FAT32
            media_descriptor: 0xF8,          // Fixed disk
            fat_size_16: 0,                  // FAT size is 32-bit, set to 0
            sectors_per_track: 63,           // CHS setting (not commonly used)
            num_heads: 255,                  // CHS setting
            hidden_sectors: 0,               // No hidden sectors
            total_sectors_32: total_sectors, // Total sector count
            fat_size_32: fat_size,           // FAT size in sectors
            ext_flags: 0x0000,               // FAT mirroring enabled
            fs_version: 0x0000,              // FAT32 version 0.0
            root_cluster: 2,                 // Typically starts at cluster 2
            fs_info_sector: 1,               // FSINFO sector location
            backup_boot_sector: 6,           // Backup boot sector location
            reserved: [0; 12],               // Must be zero
            drive_number: 0x80,              // Standard hard drive identifier
            reserved1: 0,                    // Reserved
            boot_signature: 0x29,            // Indicates valid BPB
            volume_id: 0x12345678,           // Random serial number (can be changed)
            volume_label: *b"NO NAME    ",   // Default volume label
            file_system_type: *b"FAT32   ",  // FAT32 identifier
        }
    }
    pub fn write_to_buffer(&self, buffer: &mut [u8]) {
        buffer[0..3].copy_from_slice(&self.jmp_boot);
        buffer[3..11].copy_from_slice(&self.oem_name);
        buffer[11..13].copy_from_slice(&self.bytes_per_sector.to_le_bytes());
        buffer[13] = self.sectors_per_cluster;
        buffer[14..16].copy_from_slice(&self.reserved_sectors.to_le_bytes());
        buffer[16] = self.num_fats;
        buffer[17..19].copy_from_slice(&self.root_entry_count.to_le_bytes());
        buffer[19..21].copy_from_slice(&self.total_sectors_16.to_le_bytes());
        buffer[21] = self.media_descriptor;
        buffer[22..24].copy_from_slice(&self.fat_size_16.to_le_bytes());
        buffer[24..26].copy_from_slice(&self.sectors_per_track.to_le_bytes());
        buffer[26..28].copy_from_slice(&self.num_heads.to_le_bytes());
        buffer[28..32].copy_from_slice(&self.hidden_sectors.to_le_bytes());
        buffer[32..36].copy_from_slice(&self.total_sectors_32.to_le_bytes());
        buffer[36..40].copy_from_slice(&self.fat_size_32.to_le_bytes());
        buffer[40..42].copy_from_slice(&self.ext_flags.to_le_bytes());
        buffer[42..44].copy_from_slice(&self.fs_version.to_le_bytes());
        buffer[44..48].copy_from_slice(&self.root_cluster.to_le_bytes());
        buffer[48..50].copy_from_slice(&self.fs_info_sector.to_le_bytes());
        buffer[50..52].copy_from_slice(&self.backup_boot_sector.to_le_bytes());
        buffer[52..64].copy_from_slice(&self.reserved);
        buffer[64] = self.drive_number;
        buffer[65] = self.reserved1;
        buffer[66] = self.boot_signature;
        buffer[67..71].copy_from_slice(&self.volume_id.to_le_bytes());
        buffer[71..82].copy_from_slice(&self.volume_label);
        buffer[82..90].copy_from_slice(&self.file_system_type);
    }
}
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileEntry {
    name: [u8; 8],             // DIR_Name (first 8 bytes - filename)
    extension: [u8; 3],        // DIR_Name (last 3 bytes - extension)
    attributes: u8,            // DIR_Attr
    nt_reserved: u8,           // DIR_NTRes
    creation_time_tenth: u8,   // DIR_CrtTimeTenth
    creation_time: u16,        // DIR_CrtTime
    creation_date: u16,        // DIR_CrtDate
    last_access_date: u16,     // DIR_LstAccDate
    first_cluster_high: u16,   // DIR_FstClusHI
    write_time: u16,           // DIR_WrtTime
    write_date: u16,           // DIR_WrtDate
    first_cluster_low: u16,    // DIR_FstClusLO
    pub(crate) file_size: u32, // DIR_FileSize
}

impl FileEntry {
    /// Parses a 32-byte buffer into a `FileEntry`
    pub fn from_buffer(buffer: &[u8]) -> Self {
        assert!(buffer.len() >= 32, "Buffer must be at least 32 bytes");

        FileEntry {
            name: buffer[0..8].try_into().unwrap(),
            extension: buffer[8..11].try_into().unwrap(),
            attributes: buffer[11],
            nt_reserved: buffer[12],
            creation_time_tenth: buffer[13],
            creation_time: u16::from_le_bytes([buffer[14], buffer[15]]),
            creation_date: u16::from_le_bytes([buffer[16], buffer[17]]),
            last_access_date: u16::from_le_bytes([buffer[18], buffer[19]]),
            first_cluster_high: u16::from_le_bytes([buffer[20], buffer[21]]),
            write_time: u16::from_le_bytes([buffer[22], buffer[23]]),
            write_date: u16::from_le_bytes([buffer[24], buffer[25]]),
            first_cluster_low: u16::from_le_bytes([buffer[26], buffer[27]]),
            file_size: u32::from_le_bytes([buffer[28], buffer[29], buffer[30], buffer[31]]),
        }
    }
    pub fn write_to_buffer(&self, buffer: &mut [u8], offset: usize) {
        let mut name_bytes = [0x20; 8];
        name_bytes.copy_from_slice(&self.name);
        buffer[offset..offset + 8].copy_from_slice(&name_bytes);

        let mut ext_bytes = [0x20; 3];
        ext_bytes.copy_from_slice(&self.extension);
        buffer[offset + 8..offset + 11].copy_from_slice(&ext_bytes);

        // Attributes
        buffer[offset + 11] = self.attributes;

        buffer[offset + 12] = self.nt_reserved;
        buffer[offset + 13] = self.creation_time_tenth;
        buffer[offset + 14..offset + 16].copy_from_slice(&self.creation_time.to_le_bytes());
        buffer[offset + 16..offset + 18].copy_from_slice(&self.creation_date.to_le_bytes());
        buffer[offset + 18..offset + 20].copy_from_slice(&self.last_access_date.to_le_bytes());
        buffer[offset + 20..offset + 22].copy_from_slice(&self.first_cluster_high.to_le_bytes());
        buffer[offset + 22..offset + 24].copy_from_slice(&self.write_time.to_le_bytes());
        buffer[offset + 24..offset + 26].copy_from_slice(&self.write_date.to_le_bytes());
        buffer[offset + 26..offset + 28].copy_from_slice(&self.first_cluster_low.to_le_bytes());
        buffer[offset + 28..offset + 32].copy_from_slice(&self.file_size.to_le_bytes());
    }

    /// Creates a blank `FileEntry` with only a name and starting cluster set
    pub fn new(name: &str, extension: &str, starting_cluster: u32) -> Self {
        let (mut name_arr, mut ext_arr) = Self::make_sfn(name, extension);
        let name_upper = name.to_uppercase();
        let ext_upper = extension.to_uppercase();

        let name_bytes = name_upper.as_bytes();
        let ext_bytes = ext_upper.as_bytes();

        name_arr[..name_bytes.len().min(8)].copy_from_slice(&name_bytes[..name_bytes.len().min(8)]);
        ext_arr[..ext_bytes.len().min(3)].copy_from_slice(&ext_bytes[..ext_bytes.len().min(3)]);

        FileEntry {
            name: name_arr,
            extension: ext_arr,
            attributes: 0x20, // Default to ATTR_ARCHIVE
            nt_reserved: 0,
            creation_time_tenth: 0,
            creation_time: 0,
            creation_date: 0,
            last_access_date: 0,
            first_cluster_high: ((starting_cluster >> 16) & 0xFFFF) as u16,
            write_time: 0,
            write_date: 0,
            first_cluster_low: (starting_cluster & 0xFFFF) as u16,
            file_size: 0, // Default size 0
        }
    }

    /// Extracts the file name as a `String`
    pub fn get_name(&self) -> String {
        let name_trimmed = self
            .name
            .iter()
            .take_while(|&&c| c != b' ')
            .copied()
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&name_trimmed).to_string()
    }

    /// Extracts the file extension as a `String`
    pub fn get_extension(&self) -> String {
        let ext_trimmed = self
            .extension
            .iter()
            .take_while(|&&c| c != b' ')
            .copied()
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&ext_trimmed).to_string()
    }
    pub fn get_cluster(&self) -> u32 {
        ((self.first_cluster_high as u32) << 16) | (self.first_cluster_low as u32)
    }
    pub fn new_long_name(name: &str, extension: &str, starting_cluster: u32) -> Vec<FileEntry> {
        let long_full = if extension.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", name, extension)
        };

        let (sfn_name, sfn_ext) = Self::make_sfn(name, extension);
        let mut sfn = FileEntry::new("", "", starting_cluster);
        sfn.name = sfn_name;
        sfn.extension = sfn_ext;
        sfn.attributes = 0x20;

        let mut sfn_bytes = [0u8; 11];
        sfn_bytes[..8].copy_from_slice(&sfn.name);
        sfn_bytes[8..].copy_from_slice(&sfn.extension);
        let chk = Self::lfn_checksum(&sfn_bytes);

        let mut utf16: Vec<u16> = long_full.encode_utf16().collect();

        // insert null terminator
        utf16.push(0x0000);

        // pad with 0xFFFF up to 39 UTF-16 entries
        if utf16.len() < 39 {
            utf16.resize(39, 0xFFFF);
        } else {
            utf16.truncate(39);
        }

        let chunks: Vec<&[u16]> = (0..3).map(|i| &utf16[i * 13..i * 13 + 13]).collect();

        let mut out = Vec::with_capacity(4);
        out.push(FileEntry::from_buffer(&Self::build_lfn_slot(
            0x40 | 3,
            chk,
            chunks[2],
        )));
        out.push(FileEntry::from_buffer(&Self::build_lfn_slot(
            2, chk, chunks[1],
        )));
        out.push(FileEntry::from_buffer(&Self::build_lfn_slot(
            1, chk, chunks[0],
        )));
        out.push(sfn);
        out
    }

    fn lfn_checksum(sfn: &[u8; 11]) -> u8 {
        let mut sum: u8 = 0;
        for b in sfn {
            sum = ((sum & 1) << 7) | (sum >> 1);
            sum = sum.wrapping_add(*b);
        }
        sum
    }

    fn build_lfn_slot(seq: u8, chksum: u8, chunk: &[u16]) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = seq;
        e[11] = 0x0F;
        e[12] = 0x00;
        e[13] = chksum;
        e[14..16].copy_from_slice(&0u16.to_le_bytes());

        let mut utf16 = [0xFFFFu16; 13];
        for (i, &u) in chunk.iter().enumerate() {
            utf16[i] = u;
        }
        if chunk.len() < 13 {
            utf16[chunk.len()] = 0x0000;
        }

        for i in 0..5 {
            e[1 + i * 2..1 + i * 2 + 2].copy_from_slice(&utf16[i].to_le_bytes());
        }
        for i in 0..6 {
            e[14 + i * 2..14 + i * 2 + 2].copy_from_slice(&utf16[5 + i].to_le_bytes());
        }
        for i in 0..2 {
            e[28 + i * 2..28 + i * 2 + 2].copy_from_slice(&utf16[11 + i].to_le_bytes());
        }

        e
    }

    fn make_sfn(name: &str, ext: &str) -> ([u8; 8], [u8; 3]) {
        fn clean(s: &str) -> String {
            s.chars()
                .map(|c| c.to_ascii_uppercase())
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect()
        }
        let mut base = clean(name);
        let mut extc = clean(ext);
        if base.len() > 8 {
            base = base.chars().take(6).collect::<String>() + "~1";
        }
        let mut name_arr = [b' '; 8];
        let mut ext_arr = [b' '; 3];
        for (i, b) in base.as_bytes().iter().take(8).enumerate() {
            name_arr[i] = *b;
        }
        for (i, b) in extc.as_bytes().iter().take(3).enumerate() {
            ext_arr[i] = *b;
        }
        (name_arr, ext_arr)
    }
}

#[repr(C, packed)]
struct InfoSector {
    signature1: [u8; 4],             // Offset: 0x00 ("RRaA" - 0x52 0x52 0x61 0x41)
    reserved1: [u8; 480],            // Offset: 0x04 - 0x1E3 (Reserved, usually 0)
    signature2: [u8; 4],             // Offset: 0x1E4 ("rrAa" - 0x72 0x72 0x61 0x41)
    free_clusters: u32,              // Offset: 0x1E8 (Last known free cluster count)
    recently_allocated_cluster: u32, // Offset: 0x1EC (Next free cluster hint)
    reserved2: [u8; 12],             // Offset: 0x1F0 - 0x1FB (Reserved, should be 0)
    signature3: u16,                 // Offset: 0x1FC (0xAA55 - Boot sector signature)
}
impl InfoSector {
    /// Reads an `InfoSector` from a 512-byte buffer
    pub fn from_buffer(buffer: &[u8]) -> Option<Self> {
        let mut info_sector = InfoSector {
            signature1: [buffer[0], buffer[1], buffer[2], buffer[3]],
            reserved1: [0; 480], // Reserved bytes
            signature2: [buffer[0x1E4], buffer[0x1E5], buffer[0x1E6], buffer[0x1E7]],
            free_clusters: u32::from_le_bytes([
                buffer[0x1E8],
                buffer[0x1E9],
                buffer[0x1EA],
                buffer[0x1EB],
            ]),
            recently_allocated_cluster: u32::from_le_bytes([
                buffer[0x1EC],
                buffer[0x1ED],
                buffer[0x1EE],
                buffer[0x1EF],
            ]),
            reserved2: [0; 12], // Reserved bytes
            signature3: u16::from_le_bytes([buffer[0x1FE], buffer[0x1FF]]),
        };

        // Copy reserved fields
        info_sector.reserved1.copy_from_slice(&buffer[0x04..0x1E4]);
        info_sector.reserved2.copy_from_slice(&buffer[0x1F0..0x1FC]);

        Some(info_sector)
    }
    pub fn default() -> Self {
        InfoSector {
            signature1: [0x52, 0x52, 0x61, 0x41], // "RRaA" (0x52, 0x52, 0x61, 0x41)
            reserved1: [0; 480],                  // Reserved bytes (set to zero)
            signature2: [0x72, 0x72, 0x41, 0x61], // "rrAa" (0x72, 0x72, 0x61, 0x41)
            free_clusters: 0xFFFFFFFF,            // Free cluster count (unknown)
            recently_allocated_cluster: 0xFFFFFFFF, // Next free cluster hint (unknown)
            reserved2: [0; 12],                   // More reserved bytes
            signature3: 0xAA55,                   // Boot sector signature
        }
    }
}

struct Dir {
    files: Vec<FileEntry>,
    next_cluster: u8,
}
pub struct FileSystem {
    info: InfoSector,
    pub(crate) label: String,
}

impl FileSystem {
    pub fn new(label: String, volume_size: u64) -> Self {
        FileSystem {
            info: InfoSector::default(),
            label,
        }
    }
    pub fn is_fat_present(sector: Vec<u8>) -> bool {
        if let Some(info) = InfoSector::from_buffer(&sector) {
            let sig3 = info.signature3;
            //println!("sig1: {:#?}, sig2: {:#?}, sig3: {:#x}", info.signature1, info.signature2, sig3);
            if (info.signature1 == [0x52, 0x52, 0x61, 0x41]
                && info.signature2 == [0x72, 0x72, 0x41, 0x61]
                && info.signature3 == 0xAA55)
            {
                return true;
            }
        }
        false
    }
    pub fn format_drive(part: &mut Partition) -> Result<(), FormatStatus> {
        let mut info_sector = InfoSector::default();
        let mut info_sec = vec![0u8; 512];
        part.read(1, &mut info_sec);
        if (Self::is_fat_present(info_sec)) {
            let clusters = Self::get_all_clusters(part, 2);

            // If the root directory has been corrupted remove what we can
            if (*clusters.last().unwrap() == 0) {
                // Prevents a fault from the corrupted root dir
                Self::update_fat(part, 2, 0xFFFFFFFF);
            }
            let res = Self::remove_dir(part, "\\".to_string());
            if res.is_err() {
                return Err(TooCorrupted);
            }
        }
        let mut boot_buffer = vec![0u8; 512];
        let part_size = part.size;
        //self.calculate_data_region_start() - RESERVED_SECTORS;
        let bpb = BIOSParameterBlock::new(
            (part_size / 512) as u32,
            Self::calculate_max_fat_size(part.size),
        );
        bpb.write_to_buffer(&mut boot_buffer);
        part.write(0, &boot_buffer);

        info_sector.free_clusters = (part_size / CLUSTER_OFFSET as u64) as u32;
        info_sector.recently_allocated_cluster = 0;
        let mut info_sec_buffer = vec![0x00; 512]; // Initialize buffer with zeros
        info_sec_buffer[0x00..0x04].copy_from_slice(&info_sector.signature1);
        info_sec_buffer[0x1E4..0x1E8].copy_from_slice(&info_sector.signature2);
        info_sec_buffer[0x1E8..0x1EC].copy_from_slice(&info_sector.free_clusters.to_le_bytes());
        info_sec_buffer[0x1EC..0x1F0]
            .copy_from_slice(&info_sector.recently_allocated_cluster.to_le_bytes());
        info_sec_buffer[0x1FE..0x200].copy_from_slice(&info_sector.signature3.to_le_bytes());
        let mut buffer = vec![0u8; 512]; // Buffer of one sector size (512 bytes)

        part.write(INFO_SECTOR, &mut info_sec_buffer);

        // Write the FAT table to the partition
        let itr = info_sector.free_clusters / 512;

        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS {
            part.write((i) as u32, &mut buffer);
        }
        let mut read_buffer = vec![0u8; 512]; // Buffer of one sector size (512 bytes)

        //validate data sectors
        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS {
            part.read((i + 1) as u32, &mut read_buffer);
            for j in 0..512 {
                if (read_buffer[j] != buffer[j]) {
                    println!("Sector {} is invalid", i);
                    break;
                }
            }
        }
        Self::update_fat(part, 0, 0xFFFFFFFF);
        Self::update_fat(part, 1, 0xFFFFFFFF);
        Self::update_fat(part, 2, 0xFFFFFFFF);
        //wipe the root dir
        match Self::write_cluster(part, 2, &mut vec![0u8; CLUSTER_OFFSET as usize]) {
            Ok(_) => {}
            Err(e) => return Err(TooCorrupted),
        }
        info_sector.recently_allocated_cluster = 0;

        Ok(())
    }

    fn update_fat(part: &mut Partition, cluster_number: u32, next_cluster: u32) {
        let fat_offset = cluster_number * 4;
        let sector_number = (fat_offset / 512) + RESERVED_SECTORS;
        let entry_offset = (fat_offset % 512) as usize;

        let mut buffer = vec![0u8; 512];
        part.read(sector_number, &mut buffer);

        buffer[entry_offset] = (next_cluster & 0xFF) as u8;
        buffer[entry_offset + 1] = ((next_cluster >> 8) & 0xFF) as u8;
        buffer[entry_offset + 2] = ((next_cluster >> 16) & 0xFF) as u8;
        buffer[entry_offset + 3] = ((next_cluster >> 24) & 0xFF) as u8;

        part.write(sector_number, &mut buffer);
    }
    pub fn create_dir(part: &mut Partition, path: &str) -> Result<(), FileStatus> {
        let files = FileSystem::file_parser(path);
        let mut current_cluster = 2;

        for dir_name in files {
            let parent_cluster = current_cluster;

            match Self::file_present(part, dir_name, FileAttribute::Directory, parent_cluster) {
                Ok(file) => {
                    current_cluster = file.get_cluster();
                }
                Err(FileStatus::PathNotFound) => {
                    let free_cluster = Self::find_free_cluster(part, 0);

                    // Create base entry
                    let mut entry = FileEntry::new(dir_name, "", free_cluster);
                    entry.attributes = FileAttribute::Directory as u8;

                    // Check if this name needs LFN
                    let needs_lfn = {
                        let upper = dir_name.to_uppercase();
                        upper.len() > 8
                            || upper.contains('.')
                            || upper
                                .chars()
                                .any(|c| !c.is_ascii_alphanumeric() && c != '_')
                    };

                    if needs_lfn {
                        Self::write_file_to_dir(
                            part,
                            &entry,
                            parent_cluster,
                            Some(dir_name.to_string()),
                        )?;
                    } else {
                        Self::write_file_to_dir(part, &entry, parent_cluster, None)?;
                    }

                    Self::update_fat(part, free_cluster, 0xFFFFFFFF);
                    Self::initialize_directory(part, free_cluster, parent_cluster)?;
                    current_cluster = free_cluster;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn initialize_directory(
        part: &mut Partition,
        new_cluster: u32,
        parent_cluster: u32,
    ) -> Result<(), FileStatus> {
        // Zero out the new directory cluster.
        let empty_buffer = vec![0u8; CLUSTER_OFFSET as usize];
        Self::write_cluster(part, new_cluster, &empty_buffer)?;

        // Create the '.' entry (self-reference)
        let mut entry = FileEntry::new(".", "", new_cluster);
        entry.attributes = FileAttribute::Directory as u8;
        Self::write_file_to_dir(part, &entry, new_cluster, None)?;

        // For the '..' entry, if the parent is the root directory,
        // set the cluster reference to 0 as required.
        let parent_cluster_ref = if parent_cluster == 2 {
            0
        } else {
            parent_cluster
        };
        let mut entry = FileEntry::new("..", "", parent_cluster_ref);
        entry.attributes = FileAttribute::Directory as u8;
        // Create the '..' entry
        Self::write_file_to_dir(part, &entry, new_cluster, None)?;

        Ok(())
    }

    pub fn read_dir(
        part: &mut Partition,
        starting_cluster: u32,
    ) -> Result<Vec<FileEntry>, FileStatus> {
        let dirs = Self::get_all_clusters(part, starting_cluster);

        let mut root_dir = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];
        let entry_size = 32;
        let mut file_entries = Vec::new();
        for j in 0..dirs.len() {
            Self::read_cluster(part, dirs[j], &mut root_dir)?;

            for i in (0..root_dir.len()).step_by(entry_size) {
                if root_dir[i] == 0x00 {
                    continue; // Empty entry, skip
                } else if root_dir[i] == 0xE5 {
                    continue; // Deleted entry, skip
                }

                let file_entry = FileEntry::from_buffer(&root_dir[i..i + entry_size]);

                file_entries.push(file_entry);
            }
        }
        Ok(file_entries)
    }
    pub fn remove_dir(part: &mut Partition, path: String) -> Result<(), FileStatus> {
        // Get the directory and its contents.
        let dir = Self::find_dir(part, &path)?;
        let files = Self::read_dir(part, dir.get_cluster())?;

        for entry in files {
            if entry.get_name() == "." || entry.get_name() == ".." {
                continue;
            }

            let child_path = if path == "\\" {
                // If the parent path is the root "\" then simply prepend it.
                format!("\\{}", entry.get_name())
            } else {
                // Otherwise, combine parent and child with a single backslash.
                format!("{}\\{}", path, entry.get_name())
            };

            if entry.attributes == u8::from(FileAttribute::Archive) {
                // For files, append the extension.
                let file_path = format!("{}.{}", child_path, entry.get_extension());
                Self::delete_file(part, &file_path)?;
            } else if entry.attributes == u8::from(FileAttribute::Directory) {
                if (entry.get_name() == ".." || entry.get_name() == ".") {
                    Self::delete_file(part, &child_path)?;
                    continue;
                }

                Self::remove_dir(part, child_path)?;
            }
        }

        // Remove the (now empty) directory.
        Self::delete_file(part, &path)?;
        Ok(())
    }
    pub(crate) fn file_parser(path: &str) -> Vec<&str> {
        path.trim_start_matches('\\').split('\\').collect()
    }
    fn find_last_dot(s: &str) -> Option<usize> {
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).rev() {
            if bytes[i] == b'.' {
                return Some(i);
            }
        }
        None
    }

    pub fn get_text_before_last_dot(s: &str) -> &str {
        if let Some(pos) = FileSystem::find_last_dot(s) {
            &s[..pos]
        } else {
            s
        }
    }
    pub fn get_text_after_last_dot(s: &str) -> &str {
        if let Some(pos) = FileSystem::find_last_dot(s) {
            &s[pos + 1..]
        } else {
            ""
        }
    }
    fn file_present(
        part: &mut Partition,
        file_name: &str,
        file_attribute: FileAttribute,
        starting_cluster: u32,
    ) -> Result<FileEntry, FileStatus> {
        let clusters = Self::get_all_clusters(part, starting_cluster);

        for &cluster in &clusters {
            let dir = Self::read_dir(part, cluster)?;

            let mut assembled: Vec<(String, u8, usize)> = Vec::new();
            let mut pending_lfn_parts: Vec<FileEntry> = Vec::new();

            for (idx, entry) in dir.iter().enumerate() {
                let attr = entry.attributes;

                if attr == 0x0F {
                    pending_lfn_parts.push(*entry);
                    continue;
                }

                if entry.name[0] == 0x00 || entry.name[0] == 0xE5 {
                    pending_lfn_parts.clear();
                    continue;
                }

                let full_name = if !pending_lfn_parts.is_empty() {
                    pending_lfn_parts.reverse();

                    let mut utf16_name = Vec::new();
                    for lfn in &pending_lfn_parts {
                        let raw: [u8; 32] = unsafe { core::mem::transmute(*lfn) };

                        for k in (1..11).step_by(2) {
                            utf16_name.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                        for k in (14..26).step_by(2) {
                            utf16_name.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                        for k in (28..32).step_by(2) {
                            utf16_name.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                    }

                    if let Some(pos) = utf16_name.iter().position(|&c| c == 0x0000) {
                        utf16_name.truncate(pos);
                    }

                    pending_lfn_parts.clear();
                    String::from_utf16_lossy(&utf16_name)
                } else {
                    let name = entry
                        .name
                        .iter()
                        .take_while(|&&c| c != 0 && c != b' ')
                        .copied()
                        .collect::<Vec<u8>>();
                    let ext = entry
                        .extension
                        .iter()
                        .take_while(|&&c| c != 0 && c != b' ')
                        .copied()
                        .collect::<Vec<u8>>();
                    let mut s = String::from_utf8_lossy(&name).to_string();
                    if !ext.is_empty() {
                        s.push('.');
                        s.push_str(&String::from_utf8_lossy(&ext));
                    }
                    s
                };

                assembled.push((full_name, attr, idx));
            }

            for (name, attr, idx) in assembled {
                if name.eq_ignore_ascii_case(file_name) && attr == file_attribute as u8 {
                    return Ok(dir[idx].clone());
                }
            }
        }

        Err(FileStatus::PathNotFound)
    }
    pub(crate) fn find_file(part: &mut Partition, path: &str) -> Result<FileEntry, FileStatus> {
        let files = Self::file_parser(path);
        let mut current_cluster = 2;
        if (path == "\\") {
            let mut root_dir = FileEntry::new("", "", 2);
            root_dir.attributes = u8::from(FileAttribute::Directory);
            return Ok(root_dir);
        }
        for i in 0..files.len() {
            let mut attribute = FileAttribute::Directory;
            if (i == files.len() - 1) {
                attribute = FileAttribute::Archive;
            }

            let current_file = Self::file_present(part, files[i], attribute, current_cluster)?;

            if (i == files.len() - 1) {
                return Ok(current_file);
            } else {
                current_cluster = current_file.get_cluster();
            }
        }
        Err(FileStatus::PathNotFound)
    }
    pub fn find_dir(part: &mut Partition, path: &str) -> Result<FileEntry, FileStatus> {
        if (path == "\\") {
            let mut root_dir = FileEntry::new("", "", 2);
            root_dir.attributes = u8::from(FileAttribute::Directory);
            return Ok(root_dir);
        }
        let files = Self::file_parser(path);
        let mut current_cluster = 2;
        for i in 0..files.len() {
            let attribute = FileAttribute::Directory;

            let current_file = Self::file_present(part, files[i], attribute, current_cluster)?;

            if i == files.len() - 1 {
                return Ok(current_file);
            } else {
                current_cluster = current_file.get_cluster();
            }
        }
        Err(PathNotFound)
    }
    pub fn create_file(
        part: &mut Partition,
        file_name: &str,
        file_extension: &str,
        path: &str,
    ) -> Result<(), FileStatus> {
        let file_path = format!("{}\\{}.{}", path, file_name, file_extension);

        if Self::find_file(part, file_path.as_str()).is_ok() {
            return Err(FileStatus::FileAlreadyExist);
        }

        // Get the directory where the file will be created
        let dir = Self::find_dir(part, File::remove_file_from_path(&file_path));
        match dir {
            Ok(dir) => {
                let free_cluster = Self::find_free_cluster(part, 0);
                if free_cluster == 0xFFFFFFFF {
                    return Err(FileStatus::UnknownFail); // No free cluster available
                }

                // Create the file entry
                Self::update_fat(part, free_cluster, 0xFFFFFFFF);
                let entry = FileEntry::new(file_name, file_extension, free_cluster);

                // Check if this file name needs a long name
                let full_name = if file_extension.is_empty() {
                    file_name.to_string()
                } else {
                    format!("{}.{}", file_name, file_extension)
                };

                let needs_lfn = {
                    let upper = full_name.to_uppercase();
                    // LFN needed if >8.3, has spaces, or invalid chars for SFN
                    let parts: Vec<&str> = upper.split('.').collect();
                    let name_ok = parts[0].len() <= 8
                        && parts[0]
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_');
                    let ext_ok = parts.len() == 1
                        || (parts[1].len() <= 3
                            && parts[1]
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_'));
                    !(name_ok && ext_ok)
                };

                if needs_lfn {
                    Self::write_file_to_dir(part, &entry, dir.get_cluster(), Some(full_name))?;
                } else {
                    Self::write_file_to_dir(part, &entry, dir.get_cluster(), None)?;
                }

                Ok(())
            }
            Err(FileStatus::PathNotFound) => Err(FileStatus::InternalError),
            Err(err) => Err(err),
        }
    }

    pub fn write_file(
        part: &mut Partition,
        file_data: &[u8],
        path: &str,
    ) -> Result<(), FileStatus> {
        // Find the file to overwrite
        let mut file_entry = Self::find_file(part, path)?;
        let cluster_size = CLUSTER_OFFSET as usize;
        let new_clusters_needed = (file_data.len() + cluster_size - 1) / cluster_size;
        let old_clusters = Self::get_all_clusters(part, file_entry.get_cluster());
        let old_clusters_needed = old_clusters.len();

        let mut buffer = vec![0u8; cluster_size];
        let mut current_cluster = file_entry.get_cluster();

        // Write data to the existing clusters
        for i in 0..new_clusters_needed {
            let data_offset = i * cluster_size;
            let bytes_to_copy = core::cmp::min(cluster_size, file_data.len() - data_offset);

            buffer[..bytes_to_copy]
                .copy_from_slice(&file_data[data_offset..data_offset + bytes_to_copy]);

            // Write the buffer to the current cluster
            Self::write_cluster(part, current_cluster, &buffer)?;

            // Check if we need more clusters
            if i < new_clusters_needed - 1 {
                if i < old_clusters_needed - 1 {
                    current_cluster = old_clusters[i + 1];
                } else {
                    let next_cluster = Self::find_free_cluster(part, current_cluster);
                    if next_cluster == 0xFFFFFFFF {
                        return Err(FileStatus::UnknownFail); // No free cluster available
                    }
                    Self::update_fat(part, current_cluster, next_cluster);
                    current_cluster = next_cluster;
                }
            } else {
                Self::update_fat(part, current_cluster, 0xFFFFFFFF); // End of chain
            }
        }

        // If there are leftover clusters, free them
        if old_clusters_needed > new_clusters_needed {
            for cluster in &old_clusters[new_clusters_needed..] {
                Self::update_fat(part, *cluster, 0x00000000); // Mark as free
            }
        }

        // Update directory entry
        file_entry.file_size = file_data.len() as u32;
        let starting_cluster = file_entry.get_cluster();

        // Determine if LFN is needed
        let full_name = {
            let name = file_entry.get_name();
            let ext = file_entry.get_extension();
            if ext.is_empty() {
                name
            } else {
                format!("{}.{}", name, ext)
            }
        };

        let needs_lfn = {
            let upper = full_name.to_uppercase();
            let parts: Vec<&str> = upper.split('.').collect();
            let name_ok = parts[0].len() <= 8
                && parts[0]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_');
            let ext_ok = parts.len() == 1
                || (parts[1].len() <= 3
                    && parts[1]
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_'));
            !(name_ok && ext_ok)
        };

        if needs_lfn {
            if Self::update_dir_entry(part, path, file_entry, starting_cluster, Some(full_name))
                .is_err()
            {
                return Err(FileStatus::UnknownFail);
            }
        } else {
            if Self::update_dir_entry(part, path, file_entry, starting_cluster, None).is_err() {
                return Err(FileStatus::UnknownFail);
            }
        }

        Ok(())
    }
    pub fn list_dir(part: &mut Partition, path: &str) -> Result<Vec<String>, FileStatus> {
        let dir_entry = Self::find_dir(part, path)?;
        let files = Self::read_dir(part, dir_entry.get_cluster())?;

        if files.last().unwrap().name == "..".as_bytes() {
            return Err(FileStatus::BadPath);
        }

        let mut results = Vec::new();
        let mut pending_lfn_parts: Vec<FileEntry> = Vec::new();

        for entry in &files {
            if entry.attributes == 0x0F {
                // This is an LFN entry — store it for later assembly
                pending_lfn_parts.push(entry.clone());
            } else if entry.name[0] == 0x00 || entry.name[0] == 0xE5 {
                // Unused or deleted entry, clear any pending LFN data
                pending_lfn_parts.clear();
            } else {
                if !pending_lfn_parts.is_empty() {
                    pending_lfn_parts.reverse();

                    let mut utf16_name = Vec::new();
                    for lfn in &pending_lfn_parts {
                        let raw: [u8; 32] = unsafe { core::mem::transmute(*lfn) };

                        for k in (1..11).step_by(2) {
                            utf16_name.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                        for k in (14..26).step_by(2) {
                            utf16_name.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                        for k in (28..32).step_by(2) {
                            utf16_name.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                    }

                    if let Some(pos) = utf16_name.iter().position(|&c| c == 0x0000) {
                        utf16_name.truncate(pos);
                    }

                    let assembled_name = String::from_utf16_lossy(&utf16_name);
                    results.push(assembled_name);

                    pending_lfn_parts.clear();
                } else {
                    let name = entry
                        .name
                        .iter()
                        .take_while(|&&c| c != 0 && c != b' ')
                        .cloned()
                        .collect::<Vec<u8>>();

                    let ext = entry
                        .extension
                        .iter()
                        .take_while(|&&c| c != 0 && c != b' ')
                        .cloned()
                        .collect::<Vec<u8>>();

                    let mut full_name = String::from_utf8_lossy(&name).to_string();
                    if !ext.is_empty() {
                        full_name.push('.');
                        full_name.push_str(&String::from_utf8_lossy(&ext));
                    }
                    results.push(full_name);
                }
            }
        }

        Ok(results)
    }

    pub fn read_file(part: &mut Partition, path: &str) -> Result<Vec<u8>, FileStatus> {
        let entry = Self::find_file(part, path)?;
        let mut file_data = vec![0u8; entry.file_size as usize];
        let remainder = entry.file_size % CLUSTER_OFFSET;
        let clusters = Self::get_all_clusters(part, entry.get_cluster());
        for i in 0..clusters.len() {
            let mut cluster = vec![0u8; CLUSTER_OFFSET as usize];
            Self::read_cluster(part, clusters[i], &mut cluster)?;
            let base_offset = i * CLUSTER_OFFSET as usize;

            if (i + 1) != clusters.len() || remainder == 0 {
                for j in 0..cluster.len() {
                    file_data[j + base_offset] = cluster[j];
                }
            } else {
                for j in 0..remainder as usize {
                    file_data[j + base_offset] = cluster[j];
                }
            }
        }
        return Ok(file_data);
    }
    pub fn delete_file(part: &mut Partition, path: &str) -> Result<(), FileStatus> {
        if path == "\\" {
            return Ok(());
        }

        // Figure out if it's a directory or a file
        let entry = if Self::get_text_after_last_dot(path).is_empty() {
            Self::find_dir(part, path)?
        } else {
            Self::find_file(part, path)?
        };

        let clusters = Self::get_all_clusters(part, entry.get_cluster());

        // Locate and delete both LFN and SFN entries
        let dir_path = File::remove_file_from_path(path);
        let dir_entry = Self::find_dir(part, dir_path)?;
        let dir_clusters = Self::get_all_clusters(part, dir_entry.get_cluster());
        let mut dir_buffer = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];

        for cluster in dir_clusters {
            Self::read_cluster(part, cluster, &mut dir_buffer)?;
            let entry_size = 32;

            for i in (0..dir_buffer.len()).step_by(entry_size) {
                let entry_starting_cluster =
                    u32::from_le_bytes([dir_buffer[i + 26], dir_buffer[i + 27], 0, 0]);

                if entry_starting_cluster == entry.get_cluster() {
                    // Delete SFN
                    dir_buffer[i] = 0xE5;

                    // Delete any preceding LFN entries
                    let mut j = i;
                    while j >= entry_size {
                        if dir_buffer[j - entry_size + 11] == 0x0F {
                            dir_buffer[j - entry_size] = 0xE5;
                            j -= entry_size;
                        } else {
                            break;
                        }
                    }

                    Self::write_cluster(part, cluster, &dir_buffer)?;
                    break;
                }
            }
        }

        // Free all clusters used by the file/dir
        for cluster in clusters {
            Self::update_fat(part, cluster, 0x00000000);
        }

        Ok(())
    }
    ///set ignore cluster to 0 to ignore no clusters
    fn find_free_cluster(part: &mut Partition, ignore_cluster: u32) -> u32 {
        let fat_sectors = Self::calculate_max_fat_size(part.size);
        for i in 0..fat_sectors {
            let mut buffer = vec![0u8; 512];
            part.read(i + RESERVED_SECTORS, &mut buffer);
            for j in 0..128 {
                // 128 = 512 bytes / 4 bytes per FAT entry
                let entry = u32::from_le_bytes([
                    buffer[j * 4],
                    buffer[j * 4 + 1],
                    buffer[j * 4 + 2],
                    buffer[j * 4 + 3],
                ]);
                if entry == 0x00000000 {
                    return (i * 128 + j as u32);
                }
            }
        }

        0xFFFFFFFF
    }
    ///starting cluster is the cluster that will be searched for NOT the one it will be updated to
    pub fn update_dir_entry(
        part: &mut Partition,
        path: &str,
        new_entry: FileEntry,
        starting_cluster: u32,
        long_name: Option<String>,
    ) -> Result<(), FileStatus> {
        let dir_path = File::remove_file_from_path(path);
        let dir_entry = Self::find_dir(part, dir_path)?;
        let dir_clusters = Self::get_all_clusters(part, dir_entry.get_cluster());
        let mut dir_buffer = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];

        for cluster in dir_clusters {
            Self::read_cluster(part, cluster, &mut dir_buffer)?;
            let entry_size = 32;

            for i in (0..dir_buffer.len()).step_by(entry_size) {
                let entry_starting_cluster =
                    u32::from_le_bytes([dir_buffer[i + 26], dir_buffer[i + 27], 0, 0]);

                if entry_starting_cluster == starting_cluster {
                    if let Some(ln) = &long_name {
                        let mut j = i;
                        while j >= entry_size {
                            if dir_buffer[j + 11] == 0x0F {
                                dir_buffer[j] = 0xE5;
                                j -= entry_size;
                            } else {
                                break;
                            }
                        }
                        dir_buffer[i] = 0xE5;
                        Self::write_cluster(part, cluster, &dir_buffer)?;

                        let (base, ext) = match ln.rsplit_once('.') {
                            Some((b, e)) => (b.to_string(), e.to_string()),
                            None => (ln.clone(), String::new()),
                        };
                        let new_entries =
                            FileEntry::new_long_name(&base, &ext, new_entry.get_cluster());

                        for e in &new_entries {
                            Self::write_file_to_dir(part, e, dir_entry.get_cluster(), None)?;
                        }
                        return Ok(());
                    } else {
                        new_entry.write_to_buffer(&mut dir_buffer, i);
                        Self::write_cluster(part, cluster, &dir_buffer)?;
                        return Ok(());
                    }
                }
            }
        }

        Err(FileStatus::PathNotFound)
    }

    fn write_file_to_dir(
        part: &mut Partition,
        entry: &FileEntry,
        start_cluster_of_dir: u32,
        long_name: Option<String>,
    ) -> Result<(), FileStatus> {
        if let Some(ln) = long_name {
            let (name_part, ext_part) = match ln.rsplit_once('.') {
                Some((n, e)) => (n.to_string(), e.to_string()),
                None => (ln.clone(), String::new()),
            };

            let entries = FileEntry::new_long_name(&name_part, &ext_part, entry.get_cluster());

            for e in &entries {
                Self::write_file_to_dir(part, e, start_cluster_of_dir, None)?;
            }
            return Ok(());
        }

        let mut dir_buf = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];
        let clusters = Self::get_all_clusters(part, start_cluster_of_dir);
        Self::read_cluster(part, clusters[clusters.len() - 1], &mut dir_buf)?;

        let entry_size = 32;
        let mut entry_offset = None;

        for i in (0..dir_buf.len()).step_by(entry_size) {
            if dir_buf[i] == 0x00 || dir_buf[i] == 0xE5 {
                entry_offset = Some(i);
                break;
            }
        }

        if entry_offset.is_none() {
            let free_cluster = Self::find_free_cluster(part, 0);
            if free_cluster != 0xFFFFFFFF {
                Self::update_fat(part, clusters[clusters.len() - 1], free_cluster);
                Self::update_fat(part, free_cluster, 0xFFFFFFFF);
                return Self::write_file_to_dir(part, entry, start_cluster_of_dir, None);
            }
        }

        if let Some(offset) = entry_offset {
            entry.write_to_buffer(&mut dir_buf, offset);
            Self::write_cluster(part, clusters[clusters.len() - 1], &dir_buf)?;
        } else {
            println!("No free directory entry found!");
        }

        Ok(())
    }
    fn write_cluster(part: &mut Partition, cluster: u32, buffer: &[u8]) -> Result<(), FileStatus> {
        if cluster < 2 {
            return Err(FileStatus::CorruptFat);
        }

        let real_cluster = cluster.checked_sub(2).ok_or(FileStatus::CorruptFat)?;
        let start_sector = Self::cluster_to_sector(part.size, real_cluster as u32);

        let sector_count = SECTORS_PER_CLUSTER;

        if buffer.len() < (sector_count as usize * 512) {
            return Err(FileStatus::UnknownFail);
        }

        for i in 0..sector_count {
            let start_idx = (i * 512) as usize;
            let end_idx = ((i + 1) * 512) as usize;
            let sector = &buffer[start_idx..end_idx];
            let current_sector = start_sector + i;

            part.write(current_sector, sector);
        }
        Ok(())
    }

    fn read_cluster(
        part: &mut Partition,
        cluster: u32,
        buffer: &mut [u8],
    ) -> Result<(), FileStatus> {
        if cluster < 2 {
            return Err(FileStatus::CorruptFat);
        }

        let real_cluster = cluster.checked_sub(2).ok_or(FileStatus::CorruptFat)?;
        let start_sector = Self::cluster_to_sector(part.size, real_cluster);

        let sector_count = SECTORS_PER_CLUSTER;

        if buffer.len() < (sector_count as usize * 512) {
            return Err(FileStatus::UnknownFail);
        }

        for i in 0..sector_count {
            let mut sector = [0u8; 512];
            part.read(start_sector + i, &mut sector);
            buffer[(i * 512) as usize..((i + 1) * 512) as usize].copy_from_slice(&sector);
        }
        Ok(())
    }

    fn sector_for_cluster(cluster: u32) -> u32 {
        (cluster / (512 / 4)) + RESERVED_SECTORS
    }
    fn is_cluster_in_sector(cluster: u32, sector: u32) -> bool {
        if (FileSystem::sector_for_cluster(cluster) != sector) {
            return false;
        }
        true
    }
    fn cluster_in_sector(cluster: u32) -> usize {
        ((cluster as usize % (512 / 4)) * 4)
    }
    fn get_all_clusters(part: &mut Partition, mut starting_cluster: u32) -> Vec<u32> {
        let mut out_vec: Vec<u32> = Vec::new();
        out_vec.push(starting_cluster);
        let mut entry = 0x00000000;
        while (entry != 0xFFFFFFFF && entry >= 0x00000002) {
            let mut sector = vec![0u8; 512];
            let starting_sector = FileSystem::sector_for_cluster(starting_cluster);
            let sector_index = FileSystem::cluster_in_sector(starting_cluster);
            part.read(starting_sector, &mut sector);
            entry = u32::from_le_bytes([
                sector[sector_index],
                sector[sector_index + 1],
                sector[sector_index + 2],
                sector[sector_index + 3],
            ]);
            if entry != 0xFFFFFFFF && entry >= 0x00000002 {
                out_vec.push(entry);
            } else if (entry >= 0x00000002) {
                println!("maybe corrupt");
                //TODO: corruption warning
            }
            starting_cluster = entry;
        }
        out_vec
    }
    fn calculate_max_fat_size(volume_size: u64) -> u32 {
        let size = volume_size - (RESERVED_SECTORS * 512) as u64;
        let total_clusters = size / CLUSTER_OFFSET as u64;
        ((total_clusters * 4) / 512) as u32
    }
    fn calculate_data_region_start(volume_size: u64) -> u32 {
        Self::calculate_max_fat_size(volume_size) + RESERVED_SECTORS
    }

    fn cluster_to_sector(volume_size: u64, cluster: u32) -> u32 {
        let cluster_offset = SECTORS_PER_CLUSTER;
        let cluster_start = cluster_offset as u64 * cluster as u64
            + Self::calculate_data_region_start(volume_size) as u64;
        cluster_start as u32
    }
}
