use crate::drivers::drive::generic_drive::FormatStatus;
use crate::drivers::drive::generic_drive::FormatStatus::TooCorrupted;
use crate::drivers::drive::gpt::Partition;
use crate::drivers::drive::ram_disk::RamDiskController;
use crate::file_system::file::FileStatus::PathNotFound;
use crate::file_system::file::{File, FileAttribute, FileStatus};
use crate::println;
use crate::util::BootPkg;
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
const SECTORS_PER_CLUSTER: u32 = (CLUSTER_SIZE * 1024) / 512;
const RESERVED_SECTORS: u32 = 32;
pub const INFO_SECTOR: u32 = 1;
const NUM_FATS: u8 = 1;
const SECTOR_SIZE: u16 = 512;
#[derive(Clone, Copy, Debug)]
pub struct FatParams {
    pub bps: u16,            // bytes per sector
    pub spc: u8,             // sectors per cluster
    pub rsvd: u16,           // reserved sectors
    pub nfats: u8,           // number of FATs
    pub fatsz: u32,          // sectors per FAT (FATSz32)
    pub totsec: u32,         // total sectors (TotSec32 or 16)
    pub root_clus: u32,      // BPB_RootClus
    pub fsinfo_sec: u16,     // BPB_FSInfo
    pub bkboot_sec: u16,     // BPB_BkBootSec
    pub ext_flags: u16,      // BPB_ExtFlags (mirroring / active FAT)
    pub fat_start_lba: u32,  // derived: first FAT LBA
    pub data_start_lba: u32, // derived: first data sector LBA
}
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
        let mut name_arr = [b' '; 8];
        let mut ext_arr = [b' '; 3];

        // Special-case . and ..
        if name == "." || name == ".." {
            let bytes = name.as_bytes();
            name_arr[..bytes.len()].copy_from_slice(bytes);
        } else {
            let name_bytes = name
                .chars()
                .map(|c| c.to_ascii_uppercase())
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c as u8
                    } else {
                        b'_'
                    }
                })
                .take(8)
                .collect::<Vec<u8>>();
            name_arr[..name_bytes.len()].copy_from_slice(&name_bytes);
        }

        let ext_bytes = extension
            .chars()
            .map(|c| c.to_ascii_uppercase())
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c as u8
                } else {
                    b'_'
                }
            })
            .take(3)
            .collect::<Vec<u8>>();
        ext_arr[..ext_bytes.len()].copy_from_slice(&ext_bytes);

        FileEntry {
            name: name_arr,
            extension: ext_arr,
            attributes: 0x20, // ATTR_ARCHIVE
            nt_reserved: 0,
            creation_time_tenth: 0,
            creation_time: 0,
            creation_date: 0,
            last_access_date: 0,
            first_cluster_high: ((starting_cluster >> 16) & 0xFFFF) as u16,
            write_time: 0,
            write_date: 0,
            first_cluster_low: (starting_cluster & 0xFFFF) as u16,
            file_size: 0,
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
        (((self.first_cluster_high as u32) << 16) | (self.first_cluster_low as u32)) & 0x0FFF_FFFF
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
        utf16.push(0x0000);

        let total_slots = (utf16.len() + 12) / 13;

        utf16.resize(total_slots * 13, 0xFFFF);

        let mut out = Vec::with_capacity(total_slots + 1);
        for slot_idx in (0..total_slots).rev() {
            let seq_num = (slot_idx + 1) as u8
                | if slot_idx == total_slots - 1 {
                    0x40
                } else {
                    0x00
                };
            let chunk = &utf16[slot_idx * 13..slot_idx * 13 + 13];
            out.push(FileEntry::from_buffer(&Self::build_lfn_slot(
                seq_num, chk, chunk,
            )));
        }

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
        fn clean_ascii(s: &str) -> Vec<u8> {
            s.chars()
                .map(|c| c.to_ascii_uppercase())
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c as u32 as u8
                    } else {
                        b'_'
                    }
                })
                .collect()
        }

        let mut name_arr = [b' '; 8];
        let mut ext_arr = [b' '; 3];

        let name_c = clean_ascii(name);
        let ext_c = clean_ascii(ext);

        let prefix_len = name_c.len().min(6);
        let mut base = Vec::with_capacity(8);
        base.extend_from_slice(&name_c[..prefix_len]);
        base.extend_from_slice(b"~1");

        let copy_len = base.len().min(8);
        name_arr[..copy_len].copy_from_slice(&base[..copy_len]);

        let ext_len = ext_c.len().min(3);
        ext_arr[..ext_len].copy_from_slice(&ext_c[..ext_len]);

        (name_arr, ext_arr)
    }
}

#[repr(C, packed)]
#[derive(Debug)]
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
#[derive(Debug)]
pub struct FileSystem {
    pub params: FatParams,
    pub info: InfoSector,
    pub label: String,
}
impl FileSystem {
    pub fn parse_bpb(part: &mut Partition) -> Result<FatParams, FileStatus> {
        fn parse(sector: &[u8]) -> Option<FatParams> {
            if sector.len() < 512 {
                return None;
            }
            if u16::from_le_bytes([sector[510], sector[511]]) != 0xAA55 {
                return None;
            }

            let bps = u16::from_le_bytes([sector[11], sector[12]]);
            let spc = sector[13];
            let rsvd = u16::from_le_bytes([sector[14], sector[15]]);
            let nf = sector[16];
            let root_ent_cnt = u16::from_le_bytes([sector[17], sector[18]]);
            let tot16 = u16::from_le_bytes([sector[19], sector[20]]);
            let media = sector[21];
            let fatsz16 = u16::from_le_bytes([sector[22], sector[23]]);
            let spt = u16::from_le_bytes([sector[24], sector[25]]);
            let nheads = u16::from_le_bytes([sector[26], sector[27]]);
            let hidsec = u32::from_le_bytes([sector[28], sector[29], sector[30], sector[31]]);
            let tot32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
            let fatsz32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
            let ext_flags = u16::from_le_bytes([sector[40], sector[41]]);
            let fs_ver = u16::from_le_bytes([sector[42], sector[43]]);
            //let root_clus = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
            let root_clus = 2;
            let fsinfo_sec = u16::from_le_bytes([sector[48], sector[49]]);
            let bkboot_sec = u16::from_le_bytes([sector[50], sector[51]]);

            if bps == 0 || (bps & (bps - 1)) != 0 {
                return None;
            }
            if spc == 0 || (spc & (spc - 1)) != 0 {
                return None;
            }
            if nf == 0 {
                return None;
            }

            let fatsz = if fatsz16 != 0 {
                fatsz16 as u32
            } else {
                fatsz32
            };
            let totsec = if tot16 != 0 { tot16 as u32 } else { tot32 };
            if fatsz == 0 || totsec == 0 {
                return None;
            }

            let root_dir_sectors = ((root_ent_cnt as u32 * 32) + (bps as u32 - 1)) / bps as u32;

            let fat_start_lba = rsvd as u32;
            let first_data_lba = rsvd as u32 + (nf as u32) * fatsz + root_dir_sectors;
            let data_sectors = totsec.saturating_sub(first_data_lba);
            let cluster_count = data_sectors / spc as u32;

            Some(FatParams {
                bps,
                spc,
                rsvd,
                nfats: nf,
                fatsz,
                totsec,
                root_clus,
                fsinfo_sec,
                bkboot_sec,
                ext_flags,
                fat_start_lba: fat_start_lba,
                data_start_lba: first_data_lba,
            })
        }

        let mut vbr = vec![0u8; 512];
        part.read(0, &mut vbr);
        if let Some(p) = parse(&vbr) {
            return Ok(p);
        }

        let mut vbr_bk = vec![0u8; 512];
        part.read(6, &mut vbr_bk);
        if let Some(mut p) = parse(&vbr_bk) {
            return Ok(p);
        }

        Err(FileStatus::NotFat)
    }
    pub fn mount(part: &mut Partition) -> Result<Self, FileStatus> {
        let params = Self::parse_bpb(part)?;
        let mut info_sec_buf = vec![0u8; params.bps as usize];
        if params.fsinfo_sec != 0 && params.fsinfo_sec != 0xFFFF {
            part.read(params.fsinfo_sec as u32, &mut info_sec_buf);
        }
        let info = InfoSector::from_buffer(&info_sec_buf).unwrap_or_else(InfoSector::default);

        Ok(Self {
            params,
            info,
            label: String::new(),
        })
    }
    pub fn is_fat_present(sector: Vec<u8>) -> bool {
        if let Some(info) = InfoSector::from_buffer(&sector) {
            let sig3 = info.signature3;
            if (info.signature1 == [0x52, 0x52, 0x61, 0x41]
                && info.signature2 == [0x72, 0x72, 0x41, 0x61]
                && info.signature3 == 0xAA55)
            {
                return true;
            }
        }
        false
    }
    #[inline]
    fn compute_fatsz32(totsec: u32, rsvd: u32, spc: u32, nfats: u32, bps: u32) -> u32 {
        let mut fatsz = 1u32.max(((totsec.saturating_sub(rsvd)) + bps - 1) / bps);
        loop {
            let data_sec = totsec.saturating_sub(rsvd + nfats * fatsz);
            let cluster_count = data_sec / spc.max(1);
            let needed = cluster_count.saturating_add(2);
            let new_fatsz = ((needed * 4) + (bps - 1)) / bps;
            if new_fatsz == fatsz {
                return fatsz;
            }
            fatsz = new_fatsz.max(1);
        }
    }
    pub fn format_drive(part: &mut Partition) -> Result<(), FormatStatus> {
        let bps = SECTOR_SIZE as u16;
        if bps != 512 {
            return Err(TooCorrupted);
        }
        let spc = SECTORS_PER_CLUSTER as u8;
        let rsvd = RESERVED_SECTORS as u16;
        let nfats = NUM_FATS;
        let totsec = (part.size / bps as u64) as u32;

        let fatsz =
            Self::compute_fatsz32(totsec, rsvd as u32, spc as u32, nfats as u32, bps as u32);

        let mut bpb = BIOSParameterBlock::new(totsec, fatsz);
        bpb.bytes_per_sector = bps;
        bpb.sectors_per_cluster = spc;
        bpb.reserved_sectors = rsvd;
        bpb.num_fats = nfats;
        bpb.media_descriptor = 0xF8;
        bpb.root_cluster = 2;
        bpb.fs_info_sector = 1;
        bpb.backup_boot_sector = 6;

        let mut vbr = vec![0u8; bps as usize];
        bpb.write_to_buffer(&mut vbr);
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        part.write(0, &vbr);
        if bpb.backup_boot_sector != 0 {
            part.write(bpb.backup_boot_sector as u32, &vbr);
        }

        let mut fsinfo = InfoSector::default();
        fsinfo.free_clusters = 0xFFFF_FFFF; // unknown
        fsinfo.recently_allocated_cluster = 0xFFFF_FFFF;
        let mut fsinfo_buf = vec![0u8; bps as usize];
        fsinfo_buf[0x00..0x04].copy_from_slice(&fsinfo.signature1);
        fsinfo_buf[0x1E4..0x1E8].copy_from_slice(&fsinfo.signature2);
        fsinfo_buf[0x1E8..0x1EC].copy_from_slice(&fsinfo.free_clusters.to_le_bytes());
        fsinfo_buf[0x1EC..0x1F0].copy_from_slice(&fsinfo.recently_allocated_cluster.to_le_bytes());
        fsinfo_buf[0x1FE..0x200].copy_from_slice(&fsinfo.signature3.to_le_bytes());
        part.write(bpb.fs_info_sector as u32, &fsinfo_buf);

        let fat_start_lba = rsvd as u32;
        let mut zero = vec![0u8; bps as usize];
        for copy in 0..(nfats as u32) {
            let base = fat_start_lba + copy * fatsz;
            for s in 0..fatsz {
                part.write(base + s, &zero);
            }
        }

        let mut fat0 = vec![0u8; bps as usize];
        let fat0_val = (0x0FFF_FF00u32 | (bpb.media_descriptor as u32)).to_le_bytes();
        fat0[0..4].copy_from_slice(&fat0_val);
        fat0[4..8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        fat0[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());

        for copy in 0..(nfats as u32) {
            let lba = fat_start_lba + copy * fatsz;
            part.write(lba, &fat0);
        }

        let first_data_lba = rsvd as u32 + (nfats as u32) * fatsz;
        let root_first_lba = first_data_lba + (bpb.root_cluster - 2) * (spc as u32);
        for i in 0..(spc as u32) {
            part.write(root_first_lba + i, &zero);
        }

        Ok(())
    }
    fn ensure_dir(&self, part: &mut Partition, path: &str) -> Result<(), FileStatus> {
        match self.create_dir(part, path) {
            Ok(()) => Ok(()),
            Err(FileStatus::FileAlreadyExist) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn attach_bytes_zero_copy(
        &self,
        part: &mut Partition,
        ram: &mut RamDiskController,
        path: &str,
        src: &'static [u8],
    ) -> Result<(), FileStatus> {
        let mut entry = self.find_file(part, path)?;
        let cluster_sz = self.calc_cluster_size();
        let bps = self.params.bps as usize;
        let spc = self.params.spc as usize;

        let needed_clusters = core::cmp::max(1, (src.len() + cluster_sz - 1) / cluster_sz);

        let mut chain = self.get_all_clusters(part, entry.get_cluster())?;

        while chain.len() < needed_clusters {
            let prev = *chain.last().unwrap();
            let next = self.find_free_cluster(part, prev);
            if next == 0xFFFF_FFFF {
                return Err(FileStatus::UnknownFail);
            }
            self.update_fat(part, prev, next);
            self.update_fat(part, next, 0xFFFF_FFFF);
            chain.push(next);
        }

        for &cl in chain[needed_clusters..].iter() {
            self.update_fat(part, cl, 0x0000_0000);
        }
        chain.truncate(needed_clusters);

        entry.file_size = src.len() as u32;
        self.update_dir_entry(part, path, entry, chain[0], None)?;

        let mut off = 0usize;
        for &cl in &chain {
            let first_lba = self.cluster_to_sector(part.size, cl);
            for s in 0..spc {
                if off >= src.len() {
                    break;
                }
                let lba = first_lba + s as u32;
                ram.map_lba_from_slice(lba, src, off);
                off = off.saturating_add(bps);
            }
        }
        Ok(())
    }
    fn update_fat(&self, part: &mut Partition, cluster_number: u32, next_cluster: u32) {
        let bps = self.params.bps as u32;
        let fat_off_bytes = cluster_number * 4;

        let sector_in_fat = fat_off_bytes / bps;
        let entry_off = (fat_off_bytes % bps) as usize;

        let mirroring_disabled = (self.params.ext_flags & 0x0080) != 0;
        let active_idx = (self.params.ext_flags & 0x000F) as u32;

        let mut write_copy = |fat_idx: u32, buf: &mut [u8]| {
            let lba = self.params.fat_start_lba + fat_idx * self.params.fatsz + sector_in_fat;
            part.read(lba, buf);

            let mut cur = u32::from_le_bytes([
                buf[entry_off],
                buf[entry_off + 1],
                buf[entry_off + 2],
                buf[entry_off + 3],
            ]);

            let new_val = (cur & 0xF000_0000) | (next_cluster & 0x0FFF_FFFF);
            buf[entry_off..entry_off + 4].copy_from_slice(&new_val.to_le_bytes());

            part.write(lba, buf);
        };

        let mut secbuf = vec![0u8; self.params.bps as usize];

        if mirroring_disabled {
            write_copy(active_idx, &mut secbuf);
        } else {
            // Update all FAT copies
            for i in 0..(self.params.nfats as u32) {
                write_copy(i, &mut secbuf);
            }
        }
    }
    pub fn create_dir(&self, part: &mut Partition, path: &str) -> Result<(), FileStatus> {
        if self.find_dir(part, path).is_ok() {
            return Err(FileStatus::FileAlreadyExist);
        }
        let files = FileSystem::file_parser(path);
        let mut current_cluster = self.params.root_clus;

        for dir_name in files {
            let parent_cluster = current_cluster;

            match self.file_present(part, dir_name, FileAttribute::Directory, parent_cluster) {
                Ok(file) => {
                    current_cluster = file.get_cluster();
                }
                Err(FileStatus::PathNotFound) => {
                    let free_cluster = self.find_free_cluster(part, 0);

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
                        self.write_file_to_dir(
                            part,
                            &entry,
                            parent_cluster,
                            Some(dir_name.to_string()),
                        )?;
                    } else {
                        self.write_file_to_dir(part, &entry, parent_cluster, None)?;
                    }

                    self.update_fat(part, free_cluster, 0xFFFFFFFF);
                    self.initialize_directory(part, free_cluster, parent_cluster)?;
                    current_cluster = free_cluster;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn initialize_directory(
        &self,
        part: &mut Partition,
        new_cluster: u32,
        parent_cluster: u32,
    ) -> Result<(), FileStatus> {
        let empty_buffer = vec![0u8; self.params.bps as usize];
        self.write_cluster(part, new_cluster, &empty_buffer)?;

        let mut entry = FileEntry::new(".", "", new_cluster);
        entry.attributes = FileAttribute::Directory as u8;
        self.write_file_to_dir(part, &entry, new_cluster, None)?;

        let parent_cluster_ref = if parent_cluster == self.params.root_clus {
            0
        } else {
            parent_cluster
        };
        let mut entry = FileEntry::new("..", "", parent_cluster_ref);
        entry.attributes = FileAttribute::Directory as u8;
        // Create the '..' entry
        self.write_file_to_dir(part, &entry, new_cluster, None)?;

        Ok(())
    }

    pub fn read_dir(
        &self,
        part: &mut Partition,
        starting_cluster: u32,
    ) -> Result<Vec<FileEntry>, FileStatus> {
        let dirs = self.get_all_clusters(part, starting_cluster)?;

        let mut root_dir =
            vec![0u8; (self.params.spc as usize * self.params.bps as usize) as usize];
        let entry_size = 32;
        let mut file_entries = Vec::new();
        for j in 0..dirs.len() {
            self.read_cluster(part, dirs[j], &mut root_dir)?;

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
    pub fn remove_dir(&self, part: &mut Partition, path: String) -> Result<(), FileStatus> {
        // Get the directory and its contents.
        let dir = self.find_dir(part, &path)?;
        let files = self.read_dir(part, dir.get_cluster())?;

        for entry in files {
            if entry.get_name() == "." || entry.get_name() == ".." {
                continue;
            }

            let child_path = if path == "\\" {
                format!("\\{}", entry.get_name())
            } else {
                format!("{}\\{}", path, entry.get_name())
            };

            if entry.attributes == u8::from(FileAttribute::Archive) {
                let file_path = format!("{}.{}", child_path, entry.get_extension());
                self.delete_file(part, &file_path)?;
            } else if entry.attributes == u8::from(FileAttribute::Directory) {
                if (entry.get_name() == ".." || entry.get_name() == ".") {
                    self.delete_file(part, &child_path)?;
                    continue;
                }

                self.remove_dir(part, child_path)?;
            }
        }

        self.delete_file(part, &path)?;
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
        &self,
        part: &mut Partition,
        file_name: &str,
        file_attribute: FileAttribute,
        starting_cluster: u32,
    ) -> Result<FileEntry, FileStatus> {
        let clusters = self.get_all_clusters(part, starting_cluster)?;

        for &cluster in &clusters {
            let dir = self.read_dir(part, cluster)?;

            let assembled = Self::assemble_entries(&dir);

            for (name, attr, idx) in assembled {
                if name.eq_ignore_ascii_case(file_name) && attr == file_attribute {
                    return Ok(dir[idx].clone());
                }
            }
        }

        Err(FileStatus::PathNotFound)
    }
    pub(crate) fn find_file(
        &self,
        part: &mut Partition,
        path: &str,
    ) -> Result<FileEntry, FileStatus> {
        let files = Self::file_parser(path);
        let mut current_cluster = self.params.root_clus;
        if (path == "\\") {
            let mut root_dir = FileEntry::new("", "", self.params.root_clus);
            root_dir.attributes = u8::from(FileAttribute::Directory);
            return Ok(root_dir);
        }
        for i in 0..files.len() {
            let mut attribute = FileAttribute::Directory;
            if (i == files.len() - 1) {
                attribute = FileAttribute::Archive;
            }

            let current_file = self.file_present(part, files[i], attribute, current_cluster)?;

            if (i == files.len() - 1) {
                return Ok(current_file);
            } else {
                current_cluster = current_file.get_cluster();
            }
        }
        Err(FileStatus::PathNotFound)
    }
    pub fn find_dir(&self, part: &mut Partition, path: &str) -> Result<FileEntry, FileStatus> {
        if (path == "\\") {
            let mut root_dir = FileEntry::new("", "", self.params.root_clus);
            root_dir.attributes = u8::from(FileAttribute::Directory);
            return Ok(root_dir);
        }
        let files = Self::file_parser(path);
        let mut current_cluster = self.params.root_clus;
        for i in 0..files.len() {
            let attribute = FileAttribute::Directory;

            let current_file = self.file_present(part, files[i], attribute, current_cluster)?;

            if i == files.len() - 1 {
                return Ok(current_file);
            } else {
                current_cluster = current_file.get_cluster();
            }
        }
        Err(PathNotFound)
    }
    pub fn create_file(
        &self,
        part: &mut Partition,
        file_name: &str,
        file_extension: &str,
        path: &str,
    ) -> Result<(), FileStatus> {
        let file_path = format!("{}\\{}.{}", path, file_name, file_extension);

        if self.find_file(part, file_path.as_str()).is_ok() {
            return Err(FileStatus::FileAlreadyExist);
        }

        let dir = self.find_dir(part, File::remove_file_from_path(&file_path));
        match dir {
            Ok(dir) => {
                let free_cluster = self.find_free_cluster(part, 0);
                if free_cluster == 0xFFFFFFFF {
                    return Err(FileStatus::UnknownFail);
                }

                self.update_fat(part, free_cluster, 0xFFFFFFFF);
                let mut entry = FileEntry::new(file_name, file_extension, free_cluster);
                entry.file_size = 0;

                let full_name = if file_extension.is_empty() {
                    file_name.to_string()
                } else {
                    format!("{}.{}", file_name, file_extension)
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
                    self.write_file_to_dir(part, &entry, dir.get_cluster(), Some(full_name))?;
                } else {
                    self.write_file_to_dir(part, &entry, dir.get_cluster(), None)?;
                }

                Ok(())
            }
            Err(FileStatus::PathNotFound) => Err(FileStatus::InternalError),
            Err(err) => Err(err),
        }
    }
    fn calc_cluster_size(&self) -> usize {
        (self.params.bps as usize * self.params.spc as usize)
    }
    pub fn write_file(
        &self,
        part: &mut Partition,
        file_data: &[u8],
        path: &str,
    ) -> Result<(), FileStatus> {
        let mut file_entry = self.find_file(part, path)?;
        let cluster_size = self.calc_cluster_size();
        let new_clusters_needed = (file_data.len() + cluster_size - 1) / cluster_size;
        let old_clusters = self.get_all_clusters(part, file_entry.get_cluster())?;
        let old_clusters_needed = old_clusters.len();

        let mut buffer = vec![0u8; cluster_size];
        let mut current_cluster = file_entry.get_cluster();

        for i in 0..new_clusters_needed {
            let data_offset = i * cluster_size;
            let bytes_to_copy = core::cmp::min(cluster_size, file_data.len() - data_offset);

            buffer[..bytes_to_copy]
                .copy_from_slice(&file_data[data_offset..data_offset + bytes_to_copy]);

            self.write_cluster(part, current_cluster, &buffer)?;

            if i < new_clusters_needed - 1 {
                if i < old_clusters_needed - 1 {
                    current_cluster = old_clusters[i + 1];
                } else {
                    let next_cluster = self.find_free_cluster(part, current_cluster);
                    if next_cluster == 0xFFFFFFFF {
                        return Err(FileStatus::UnknownFail);
                    }
                    self.update_fat(part, current_cluster, next_cluster);
                    current_cluster = next_cluster;
                }
            } else {
                self.update_fat(part, current_cluster, 0xFFFFFFFF);
            }
        }

        if old_clusters_needed > new_clusters_needed {
            for cluster in &old_clusters[new_clusters_needed..] {
                self.update_fat(part, *cluster, 0x00000000);
            }
        }

        file_entry.file_size = file_data.len() as u32;
        let starting_cluster = file_entry.get_cluster();

        if self
            .update_dir_entry(part, path, file_entry, starting_cluster, None)
            .is_err()
        {
            return Err(FileStatus::UnknownFail);
        }
        Ok(())
    }
    pub fn list_dir(&self, part: &mut Partition, path: &str) -> Result<Vec<String>, FileStatus> {
        let parsed = FileSystem::file_parser(path);
        let dir_entry = self.find_dir(part, path)?;
        let files = self.read_dir(part, dir_entry.get_cluster())?;
        if let Some(last) = parsed.last() {
            if last.to_string() == ".." {
                return Err(FileStatus::BadPath);
            }
        }
        let names: Vec<String> = Self::assemble_entries(&files)
            .into_iter()
            .map(|(name, _, _)| name)
            .collect();

        Ok(names)
    }
    pub fn assemble_entries(files: &[FileEntry]) -> Vec<(String, FileAttribute, usize)> {
        let mut out: Vec<(String, FileAttribute, usize)> = Vec::new();
        let mut pending_lfn: Vec<FileEntry> = Vec::new();

        for (i, entry) in files.iter().enumerate() {
            let attr = FileAttribute::try_from(entry.attributes).unwrap();

            if attr == FileAttribute::LFN {
                pending_lfn.push(*entry);
                continue;
            }

            if entry.name.get(0).copied() == Some(0x00) || entry.name.get(0).copied() == Some(0xE5)
            {
                pending_lfn.clear();
                continue;
            }

            let name = if !pending_lfn.is_empty() {
                pending_lfn.reverse();
                let mut utf16: Vec<u16> = Vec::new();

                for lfn in &pending_lfn {
                    let raw: [u8; 32] =
                        unsafe { core::mem::transmute::<FileEntry, [u8; 32]>(*lfn) };

                    for k in (1..11).step_by(2) {
                        utf16.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                    }
                    for k in (14..26).step_by(2) {
                        utf16.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                    }
                    for k in (28..32).step_by(2) {
                        utf16.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                    }
                }

                if let Some(pos) = utf16.iter().position(|&w| w == 0x0000) {
                    utf16.truncate(pos);
                }
                utf16.retain(|&w| w != 0xFFFF);

                pending_lfn.clear();
                String::from_utf16_lossy(&utf16)
            } else {
                let base_raw = entry
                    .name
                    .iter()
                    .take_while(|&&c| c != 0 && c != b' ')
                    .copied()
                    .collect::<Vec<u8>>();
                let ext_raw = entry
                    .extension
                    .iter()
                    .take_while(|&&c| c != 0 && c != b' ')
                    .copied()
                    .collect::<Vec<u8>>();

                let mut s = String::from_utf8_lossy(&base_raw).to_string();
                if !ext_raw.is_empty() {
                    s.push('.');
                    s.push_str(&String::from_utf8_lossy(&ext_raw));
                }
                s
            };

            out.push((name, attr, i));
        }

        out
    }

    pub fn read_file(&self, part: &mut Partition, path: &str) -> Result<Vec<u8>, FileStatus> {
        let entry = self.find_file(part, path)?;
        let file_size = entry.file_size as usize;
        let cluster_sz = self.calc_cluster_size();
        let clusters = self.get_all_clusters(part, entry.get_cluster())?;

        let mut file_data = vec![0u8; file_size];
        let mut cluster = vec![0u8; cluster_sz];

        for (i, &cl) in clusters.iter().enumerate() {
            let base = i * cluster_sz;
            if base >= file_size {
                break;
            }
            self.read_cluster(part, cl, &mut cluster)?;

            let remaining = file_size - base;
            let take = core::cmp::min(cluster_sz, remaining);
            file_data[base..base + take].copy_from_slice(&cluster[..take]);
        }

        Ok(file_data)
    }
    pub fn delete_file(&self, part: &mut Partition, path: &str) -> Result<(), FileStatus> {
        if path == "\\" {
            return Ok(());
        }

        let entry = if Self::get_text_after_last_dot(path).is_empty() {
            self.find_dir(part, path)?
        } else {
            self.find_file(part, path)?
        };

        let clusters = self.get_all_clusters(part, entry.get_cluster())?;

        let dir_path = File::remove_file_from_path(path);
        let dir_entry = self.find_dir(part, dir_path)?;
        let dir_clusters = self.get_all_clusters(part, dir_entry.get_cluster())?;
        let mut dir_buffer = vec![0u8; (self.params.spc as usize * self.params.bps as usize)];

        for cluster in dir_clusters {
            self.read_cluster(part, cluster, &mut dir_buffer)?;
            let entry_size = 32;

            for i in (0..dir_buffer.len()).step_by(entry_size) {
                let entry_starting_cluster =
                    u32::from_le_bytes([dir_buffer[i + 26], dir_buffer[i + 27], 0, 0]);

                if entry_starting_cluster == entry.get_cluster() {
                    dir_buffer[i] = 0xE5;

                    let mut j = i;
                    while j >= entry_size {
                        if dir_buffer[j - entry_size + 11] == 0x0F {
                            dir_buffer[j - entry_size] = 0xE5;
                            j -= entry_size;
                        } else {
                            break;
                        }
                    }

                    self.write_cluster(part, cluster, &dir_buffer)?;
                    break;
                }
            }
        }

        for cluster in clusters {
            self.update_fat(part, cluster, 0x00000000);
        }

        Ok(())
    }
    ///set ignore cluster to 0 to ignore no clusters
    fn find_free_cluster(&self, part: &mut Partition, ignore: u32) -> u32 {
        let bps = self.params.bps as usize;
        let ents_per_sec = (bps / 4) as u32;
        let fat_sectors = self.params.fatsz;

        let mirroring_disabled = (self.params.ext_flags & 0x0080) != 0;
        let active = if mirroring_disabled {
            (self.params.ext_flags & 0x000F) as u32
        } else {
            0
        };
        let base_lba = self.params.fat_start_lba + active * fat_sectors;

        let cluster_count =
            (self.params.totsec - self.params.data_start_lba) / self.params.spc as u32;

        let mut sec = vec![0u8; bps];
        for i in 0..fat_sectors {
            part.read(base_lba + i, &mut sec);
            for j in 0..ents_per_sec {
                let idx = i * ents_per_sec + j;
                if idx < 2 || idx == ignore {
                    continue;
                }
                if idx >= cluster_count + 2 {
                    continue;
                }

                let off = (j * 4) as usize;
                let ent = u32::from_le_bytes([sec[off], sec[off + 1], sec[off + 2], sec[off + 3]])
                    & 0x0FFF_FFFF;

                if ent == 0 {
                    // free
                    return idx;
                }
            }
        }
        0xFFFF_FFFF
    }
    pub fn update_dir_entry(
        &self,
        part: &mut Partition,
        path: &str,
        new_entry: FileEntry,
        starting_cluster: u32,
        long_name: Option<String>,
    ) -> Result<(), FileStatus> {
        let dir_path = File::remove_file_from_path(path);
        let dir_entry = self.find_dir(part, dir_path)?;
        let dir_clusters = self.get_all_clusters(part, dir_entry.get_cluster())?;
        let mut dir_buffer =
            vec![0u8; (self.params.spc as usize * self.params.bps as usize) as usize];

        for cluster in dir_clusters {
            self.read_cluster(part, cluster, &mut dir_buffer)?;
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
                        self.write_cluster(part, cluster, &dir_buffer)?;

                        let (base, ext) = match ln.rsplit_once('.') {
                            Some((b, e)) => (b.to_string(), e.to_string()),
                            None => (ln.clone(), String::new()),
                        };
                        let new_entries =
                            FileEntry::new_long_name(&base, &ext, new_entry.get_cluster());

                        for e in &new_entries {
                            self.write_file_to_dir(part, e, dir_entry.get_cluster(), None)?;
                        }
                        return Ok(());
                    } else {
                        new_entry.write_to_buffer(&mut dir_buffer, i);
                        self.write_cluster(part, cluster, &dir_buffer)?;
                        return Ok(());
                    }
                }
            }
        }

        Err(FileStatus::PathNotFound)
    }

    fn write_file_to_dir(
        &self,
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
                self.write_file_to_dir(part, e, start_cluster_of_dir, None)?;
            }
            return Ok(());
        }
        let mut dir_buf = vec![0u8; (self.params.spc as usize * self.params.bps as usize) as usize];
        let clusters = self.get_all_clusters(part, start_cluster_of_dir)?;
        self.read_cluster(part, clusters[clusters.len() - 1], &mut dir_buf)?;

        let entry_size = 32;
        let mut entry_offset = None;

        for i in (0..dir_buf.len()).step_by(entry_size) {
            if dir_buf[i] == 0x00 || dir_buf[i] == 0xE5 {
                entry_offset = Some(i);
                break;
            }
        }

        if entry_offset.is_none() {
            let free_cluster = self.find_free_cluster(part, 0);
            if free_cluster != 0xFFFFFFFF {
                self.update_fat(part, clusters[clusters.len() - 1], free_cluster);
                self.update_fat(part, free_cluster, 0xFFFFFFFF);
                return self.write_file_to_dir(part, entry, start_cluster_of_dir, long_name);
            }
        }

        if let Some(offset) = entry_offset {
            entry.write_to_buffer(&mut dir_buf, offset);
            self.write_cluster(part, clusters[clusters.len() - 1], &dir_buf)?;
        } else {
            println!("No free directory entry found!");
        }

        Ok(())
    }
    fn write_cluster(
        &self,
        part: &mut Partition,
        cluster: u32,
        buffer: &[u8],
    ) -> Result<(), FileStatus> {
        if cluster < 2 {
            return Err(FileStatus::CorruptFat);
        }

        if cluster < 2 {
            return Err(FileStatus::CorruptFat);
        }
        let start_sector = self.cluster_to_sector(part.size, cluster);

        let sector_count = self.params.spc as u32;

        if buffer.len() < (sector_count as usize * self.params.bps as usize) {
            return Err(FileStatus::UnknownFail);
        }

        for i in 0..sector_count {
            let start_idx = (i * self.params.bps as u32) as usize;
            let end_idx = ((i + 1) * self.params.bps as u32) as usize;
            let sector = &buffer[start_idx..end_idx];
            let current_sector = start_sector + i;

            part.write(current_sector, sector);
        }
        Ok(())
    }

    fn read_cluster(
        &self,
        part: &mut Partition,
        cluster: u32,
        buffer: &mut [u8],
    ) -> Result<(), FileStatus> {
        if cluster < 2 {
            return Err(FileStatus::CorruptFat);
        }

        if cluster < 2 {
            return Err(FileStatus::CorruptFat);
        }
        let start_sector = self.cluster_to_sector(part.size, cluster);

        let sector_count = self.params.spc as u32;

        if buffer.len() < (sector_count as usize * self.params.bps as usize) {
            return Err(FileStatus::UnknownFail);
        }

        for i in 0..sector_count {
            let mut sector = vec![0u8; self.params.bps as usize];
            part.read(start_sector + i, &mut sector);
            buffer[(i * self.params.bps as u32) as usize
                ..((i + 1) * self.params.bps as u32) as usize]
                .copy_from_slice(&sector);
        }
        Ok(())
    }

    #[inline]
    fn fat_base_lba(&self) -> u32 {
        let mirroring_disabled = (self.params.ext_flags & 0x0080) != 0;
        let active_idx = (self.params.ext_flags & 0x000F) as u32;
        if mirroring_disabled {
            self.params.fat_start_lba + active_idx * self.params.fatsz
        } else {
            self.params.fat_start_lba
        }
    }

    #[inline]
    fn fat_entries_per_sector(&self) -> u32 {
        (self.params.bps as u32) / 4
    }

    fn sector_for_cluster(&self, cluster: u32) -> u32 {
        let ents_per_sec = self.fat_entries_per_sector();
        let sector_in_fat = cluster / ents_per_sec;
        self.fat_base_lba() + sector_in_fat
    }

    fn is_cluster_in_sector(&self, cluster: u32, sector_lba: u32) -> bool {
        self.sector_for_cluster(cluster) == sector_lba
    }

    fn cluster_in_sector(&self, cluster: u32) -> usize {
        let ents_per_sec = self.fat_entries_per_sector();
        let idx_in_sector = cluster % ents_per_sec;
        (idx_in_sector * 4) as usize
    }

    fn fat_entry(&self, part: &mut Partition, cl: u32) -> Result<u32, FileStatus> {
        let bps = self.params.bps as usize;

        let sector = self.sector_for_cluster(cl);
        let off = self.cluster_in_sector(cl);

        let mut sec = vec![0u8; bps];
        part.read(sector, &mut sec);

        let raw =
            u32::from_le_bytes([sec[off], sec[off + 1], sec[off + 2], sec[off + 3]]) & 0x0FFF_FFFF;
        Ok(raw)
    }

    fn is_eoc(v: u32) -> bool {
        v >= 0x0FFF_FFF8 && v <= 0x0FFF_FFFF
    }

    pub fn get_all_clusters(
        &self,
        part: &mut Partition,
        start: u32,
    ) -> Result<Vec<u32>, FileStatus> {
        let mut out = Vec::new();
        let mut cl = start & 0x0FFF_FFFF;

        if cl < 2 {
            return Ok(out);
        }

        loop {
            out.push(cl);
            let next = self.fat_entry(part, cl)?;
            if Self::is_eoc(next) {
                break;
            }
            if next == 0x0FFF_FFF7 {
                return Err(FileStatus::CorruptFat);
            }
            if next < 2 {
                break;
            }
            cl = next;
        }
        Ok(out)
    }
    #[inline]
    fn calculate_data_region_start(&self) -> u32 {
        self.params.rsvd as u32 + (self.params.nfats as u32) * self.params.fatsz
    }

    fn cluster_to_sector(&self, volume_size: u64, cluster: u32) -> u32 {
        let cluster_offset = self.params.spc as u64;
        let data_start = self.calculate_data_region_start() as u64;
        let cluster_index = cluster as u64 - 2;
        (cluster_index * cluster_offset + data_start) as u32
    }
}
pub fn format_boot_drive(
    part: &mut Partition,
    ram: &mut RamDiskController,
    boot: &[BootPkg],
) -> Result<(), FileStatus> {
    FileSystem::format_drive(part).map_err(|_| FileStatus::InternalError)?;

    let fs = FileSystem::mount(part)?;

    fs.ensure_dir(part, "\\INSTALL")?;
    fs.ensure_dir(part, "\\INSTALL\\DRIVERS")?;

    for bp in boot {
        let base_dir = alloc::format!("\\INSTALL\\DRIVERS\\{}", bp.name);
        fs.ensure_dir(part, &base_dir)?;

        // TOML
        fs.create_file(part, bp.name, "toml", &base_dir)?;
        let toml_path = alloc::format!("{}\\{}.toml", base_dir, bp.name);
        fs.attach_bytes_zero_copy(part, ram, &toml_path, bp.toml)?;

        // DLL
        fs.create_file(part, bp.name, "dll", &base_dir)?;
        let dll_path = alloc::format!("{}\\{}.dll", base_dir, bp.name);
        fs.attach_bytes_zero_copy(part, ram, &dll_path, bp.image)?;
    }

    Ok(())
}
