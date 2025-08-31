use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
#[repr(C)]
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
pub struct InfoSector {
    pub signature1: [u8; 4],  // Offset: 0x00 ("RRaA" - 0x52 0x52 0x61 0x41)
    pub reserved1: [u8; 480], // Offset: 0x04 - 0x1E3 (Reserved, usually 0)
    pub signature2: [u8; 4],  // Offset: 0x1E4 ("rrAa" - 0x72 0x72 0x61 0x41)
    pub free_clusters: u32,   // Offset: 0x1E8 (Last known free cluster count)
    pub recently_allocated_cluster: u32, // Offset: 0x1EC (Next free cluster hint)
    pub reserved2: [u8; 12],  // Offset: 0x1F0 - 0x1FB (Reserved, should be 0)
    pub signature3: u16,      // Offset: 0x1FC (0xAA55 - Boot sector signature)
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
