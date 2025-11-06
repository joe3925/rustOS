use crate::alloc::format;
use crate::alloc::vec;
use crate::structs::{FatParams, InfoSector};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_api::FileStatus;
use kernel_api::FileStatus::PathNotFound;
use kernel_api::alloc_api::ffi::{pnp_send_request, pnp_wait_for_request};
use kernel_api::{
    DeviceObject, DriverStatus, FileAttribute, IoTarget, Request, RequestType, println,
};
use spin::RwLock;
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
// TODO: This panics sometimes in unsafe cell when writing to the file system
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

pub struct Fat32 {
    pub params: FatParams,
    pub info: InfoSector,
    pub volume: Arc<IoTarget>,
}
impl Fat32 {
    pub fn parse_bpb(volume: &Arc<IoTarget>) -> Result<FatParams, FileStatus> {
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
            let root_clus = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);

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
        read_sectors_sync(volume, 0, 1, 512, &mut vbr);
        if let Some(p) = parse(&vbr) {
            return Ok(p);
        }

        let mut vbr_bk = vec![0u8; 512];
        read_sectors_sync(volume, 6, 1, 512, &mut vbr_bk);
        if let Some(mut p) = parse(&vbr_bk) {
            return Ok(p);
        }

        Err(FileStatus::NotFat)
    }
    pub fn mount(volume: &Arc<IoTarget>) -> Result<Self, FileStatus> {
        let params = Self::parse_bpb(volume)?;
        let mut info_sec_buf = vec![0u8; params.bps as usize];
        if params.fsinfo_sec != 0 && params.fsinfo_sec != 0xFFFF {
            read_sectors_sync(volume, params.fsinfo_sec as u64, 1, 512, &mut info_sec_buf)
                .expect("sector read fail");
        }
        let info = InfoSector::from_buffer(&info_sec_buf).unwrap_or_else(InfoSector::default);

        Ok(Self {
            params,
            info,
            volume: volume.clone(),
        })
    }
    #[inline]
    fn bytes_per_cluster(&self) -> usize {
        self.params.bps as usize * self.params.spc as usize
    }
    #[inline]
    fn data_start_lba(&self) -> u32 {
        self.params.rsvd as u32 + (self.params.nfats as u32) * self.params.fatsz
    }
    #[inline]
    fn cluster_to_sector(&self, cluster: u32) -> u32 {
        let idx = cluster.saturating_sub(2) as u64;
        (idx * self.params.spc as u64 + self.data_start_lba() as u64) as u32
    }
    #[inline]
    fn cluster_from_dirent_bytes(ent: &[u8]) -> u32 {
        let lo = u16::from_le_bytes([ent[26], ent[27]]) as u32;
        let hi = u16::from_le_bytes([ent[20], ent[21]]) as u32;
        ((hi << 16) | lo) & 0x0FFF_FFFF
    }
    pub fn read_clusters_sync(
        &self,
        first_cluster: u32,
        cluster_count: u32,
        out: &mut [u8],
    ) -> Result<(), FileStatus> {
        if first_cluster < 2 || cluster_count == 0 {
            println!("Corrupt fat read");
            return Err(FileStatus::CorruptFat);
        }
        let sectors = (self.params.spc as usize)
            .checked_mul(cluster_count as usize)
            .ok_or(FileStatus::UnknownFail)?;
        read_sectors_sync(
            &self.volume,
            self.cluster_to_sector(first_cluster) as u64,
            sectors,
            self.params.bps as usize,
            out,
        )
    }

    pub fn write_clusters_sync(
        &self,
        first_cluster: u32,
        cluster_count: u32,
        data: &[u8],
    ) -> Result<(), FileStatus> {
        if first_cluster < 2 || cluster_count == 0 {
            println!(
                "Corrupt fat write cluster count: {}, first cluster: {},",
                first_cluster, cluster_count
            );
            return Err(FileStatus::CorruptFat);
        }
        let sectors = (self.params.spc as usize)
            .checked_mul(cluster_count as usize)
            .ok_or(FileStatus::UnknownFail)?;
        write_sectors_sync(
            &self.volume,
            self.cluster_to_sector(first_cluster) as u64,
            sectors,
            self.params.bps as usize,
            data,
        )
    }

    #[inline]
    pub fn read_cluster_sync(&self, cluster: u32, out: &mut [u8]) -> Result<(), FileStatus> {
        self.read_clusters_sync(cluster, 1, out)
    }
    #[inline]
    pub fn write_cluster_sync(&self, cluster: u32, data: &[u8]) -> Result<(), FileStatus> {
        self.write_clusters_sync(cluster, 1, data)
    }

    fn update_fat(&self, cluster_number: u32, next_cluster: u32) {
        let bps = self.params.bps as u32;
        let fat_off_bytes = cluster_number * 4;

        let sector_in_fat = fat_off_bytes / bps;
        let entry_off = (fat_off_bytes % bps) as usize;

        let mirroring_disabled = (self.params.ext_flags & 0x0080) != 0;
        let active_idx = (self.params.ext_flags & 0x000F) as u32;

        let mut write_copy = |fat_idx: u32, buf: &mut [u8]| {
            let lba = self.params.fat_start_lba + fat_idx * self.params.fatsz + sector_in_fat;

            read_sectors_sync(&self.volume, lba as u64, 1, self.params.bps as usize, buf);
            let cur = u32::from_le_bytes([
                buf[entry_off],
                buf[entry_off + 1],
                buf[entry_off + 2],
                buf[entry_off + 3],
            ]);
            let new_val = (cur & 0xF000_0000) | (next_cluster & 0x0FFF_FFFF);
            buf[entry_off..entry_off + 4].copy_from_slice(&new_val.to_le_bytes());
            write_sectors_sync(&self.volume, lba as u64, 1, self.params.bps as usize, buf);
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
    pub fn create_dir(&self, path: &str) -> Result<(), FileStatus> {
        if self.find_dir(path).is_ok() {
            return Err(FileStatus::FileAlreadyExist);
        }
        let files = Self::file_parser(path);
        let mut current_cluster = self.params.root_clus;

        for dir_name in files {
            let parent_cluster = current_cluster;

            match self.file_present(dir_name, FileAttribute::Directory, parent_cluster) {
                Ok(file) => {
                    current_cluster = file.get_cluster();
                }
                Err(FileStatus::PathNotFound) => {
                    let free_cluster = self.find_free_cluster(0);

                    let mut entry = FileEntry::new(dir_name, "", free_cluster);
                    entry.attributes = FileAttribute::Directory as u8;

                    let needs_lfn = {
                        let upper = dir_name.to_uppercase();
                        upper.len() > 8
                            || upper.contains('.')
                            || upper
                                .chars()
                                .any(|c| !c.is_ascii_alphanumeric() && c != '_')
                    };

                    if needs_lfn {
                        self.write_file_to_dir(&entry, parent_cluster, Some(dir_name.to_string()))?;
                    } else {
                        self.write_file_to_dir(&entry, parent_cluster, None)?;
                    }

                    self.update_fat(free_cluster, 0xFFFFFFFF);
                    self.initialize_directory(free_cluster, parent_cluster)?;
                    current_cluster = free_cluster;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn move_file_nocopy(&self, src_path: &str, dst_path: &str) -> Result<(), FileStatus> {
        let src_entry = self.find_file(src_path)?;
        let src_cluster = src_entry.get_cluster();
        let src_size = src_entry.file_size;

        let dst_dir_path = remove_file_from_path(dst_path);
        let dst_dir = self.find_dir(dst_dir_path)?;
        let binding = Self::file_parser(dst_path);
        let leaf = binding.last().ok_or(FileStatus::BadPath)?;
        let name = Self::get_text_before_last_dot(leaf);
        let ext = Self::get_text_after_last_dot(leaf);

        if self.find_file(dst_path).is_ok() {
            return Err(FileStatus::FileAlreadyExist);
        }

        let mut new_e = FileEntry::new(name, ext, src_cluster);
        new_e.file_size = src_size;

        let full = if ext.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", name, ext)
        };
        let needs_lfn = {
            let upper = full.to_uppercase();
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
            self.write_file_to_dir(&new_e, dst_dir.get_cluster(), Some(full))?;
        } else {
            self.write_file_to_dir(&new_e, dst_dir.get_cluster(), None)?;
        }

        self.mark_dir_entry_deleted_only(src_path, src_cluster)?;

        Ok(())
    }

    fn mark_dir_entry_deleted_only(
        &self,

        src_path: &str,
        start_cluster: u32,
    ) -> Result<(), FileStatus> {
        let dir_path = remove_file_from_path(src_path);
        let dir_entry = self.find_dir(dir_path)?;
        let dir_clusters = self.get_all_clusters(dir_entry.get_cluster())?;
        let mut dir_buffer = vec![0u8; (self.params.spc as usize * self.params.bps as usize)];

        for cluster in dir_clusters {
            self.read_cluster_sync(cluster, &mut dir_buffer)?;
            let entry_size = 32;

            for i in (0..dir_buffer.len()).step_by(entry_size) {
                let cl_lo = u16::from_le_bytes([dir_buffer[i + 26], dir_buffer[i + 27]]) as u32;
                let cl_hi = u16::from_le_bytes([dir_buffer[i + 20], dir_buffer[i + 21]]) as u32;
                let entry_cluster = Self::cluster_from_dirent_bytes(&dir_buffer[i..i + 32]);

                if entry_cluster == start_cluster {
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
                    self.write_cluster_sync(cluster, &dir_buffer)?;
                    return Ok(());
                }
            }
        }

        Err(FileStatus::PathNotFound)
    }

    fn initialize_directory(
        &self,

        new_cluster: u32,
        parent_cluster: u32,
    ) -> Result<(), FileStatus> {
        let empty_buffer = vec![0u8; self.params.bps as usize * self.params.spc as usize];
        self.write_cluster_sync(new_cluster, &empty_buffer)?;

        let mut entry = FileEntry::new(".", "", new_cluster);
        entry.attributes = FileAttribute::Directory as u8;
        self.write_file_to_dir(&entry, new_cluster, None)?;

        let parent_cluster_ref = if parent_cluster == self.params.root_clus {
            0
        } else {
            parent_cluster
        };
        let mut entry = FileEntry::new("..", "", parent_cluster_ref);
        entry.attributes = FileAttribute::Directory as u8;
        // Create the '..' entry
        self.write_file_to_dir(&entry, new_cluster, None)?;

        Ok(())
    }

    pub fn read_dir(&self, starting_cluster: u32) -> Result<Vec<FileEntry>, FileStatus> {
        let dirs = self.get_all_clusters(starting_cluster)?;

        let mut root_dir =
            vec![0u8; (self.params.spc as usize * self.params.bps as usize) as usize];
        let entry_size = 32;
        let mut file_entries = Vec::new();
        for j in 0..dirs.len() {
            self.read_cluster_sync(dirs[j], &mut root_dir)?;

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
    pub fn remove_dir(&self, path: String) -> Result<(), FileStatus> {
        // Get the directory and its contents.
        let dir = self.find_dir(&path)?;
        let files = self.read_dir(dir.get_cluster())?;

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
                self.delete_file(&file_path)?;
            } else if entry.attributes == u8::from(FileAttribute::Directory) {
                if (entry.get_name() == ".." || entry.get_name() == ".") {
                    self.delete_file(&child_path)?;
                    continue;
                }

                self.remove_dir(child_path)?;
            }
        }

        self.delete_file(&path)?;
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
        if let Some(pos) = Fat32::find_last_dot(s) {
            &s[..pos]
        } else {
            s
        }
    }
    pub fn get_text_after_last_dot(s: &str) -> &str {
        if let Some(pos) = Fat32::find_last_dot(s) {
            &s[pos + 1..]
        } else {
            ""
        }
    }
    fn file_present(
        &self,

        file_name: &str,
        file_attribute: FileAttribute,
        starting_cluster: u32,
    ) -> Result<FileEntry, FileStatus> {
        let clusters = self.get_all_clusters(starting_cluster)?;

        for &cluster in &clusters {
            let dir = self.read_dir(cluster)?;

            let assembled = Self::assemble_entries(&dir);

            for (name, attr, idx) in assembled {
                if name.eq_ignore_ascii_case(file_name) && attr == file_attribute {
                    return Ok(dir[idx].clone());
                }
            }
        }

        Err(FileStatus::PathNotFound)
    }
    pub(crate) fn find_file(&self, path: &str) -> Result<FileEntry, FileStatus> {
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

            let current_file = self.file_present(files[i], attribute, current_cluster)?;

            if (i == files.len() - 1) {
                return Ok(current_file);
            } else {
                current_cluster = current_file.get_cluster();
            }
        }
        Err(FileStatus::PathNotFound)
    }
    pub fn find_dir(&self, path: &str) -> Result<FileEntry, FileStatus> {
        if (path == "\\") {
            let mut root_dir = FileEntry::new("", "", self.params.root_clus);
            root_dir.attributes = u8::from(FileAttribute::Directory);
            return Ok(root_dir);
        }
        let files = Self::file_parser(path);
        let mut current_cluster = self.params.root_clus;
        for i in 0..files.len() {
            let attribute = FileAttribute::Directory;

            let current_file = self.file_present(files[i], attribute, current_cluster)?;

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

        file_name: &str,
        file_extension: &str,
        path: &str,
    ) -> Result<(), FileStatus> {
        let file_path = format!("{}\\{}.{}", path, file_name, file_extension);

        if self.find_file(file_path.as_str()).is_ok() {
            return Err(FileStatus::FileAlreadyExist);
        }

        let dir = self.find_dir(remove_file_from_path(&file_path));
        match dir {
            Ok(dir) => {
                let free_cluster = self.find_free_cluster(0);
                if free_cluster == 0xFFFFFFFF {
                    return Err(FileStatus::UnknownFail);
                }

                self.update_fat(free_cluster, 0xFFFFFFFF);
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
                    self.write_file_to_dir(&entry, dir.get_cluster(), Some(full_name))?;
                } else {
                    self.write_file_to_dir(&entry, dir.get_cluster(), None)?;
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
    pub fn write_file(&self, file_data: &[u8], path: &str) -> Result<(), FileStatus> {
        let mut fe = self.find_file(path)?;
        let cluster_sz = self.calc_cluster_size();

        if file_data.is_empty() {
            fe.file_size = 0;
            self.update_dir_entry(path, fe, fe.get_cluster(), None).ok();
            return Ok(());
        }

        let mut cur = fe.get_cluster();
        if cur < 2 {
            let new = self.find_free_cluster(0);
            if new == 0xFFFF_FFFF {
                return Err(FileStatus::UnknownFail);
            }
            self.update_fat(new, 0xFFFF_FFFF);

            let zero = vec![0u8; cluster_sz];
            self.write_cluster_sync(new, &zero)?;

            fe.first_cluster_low = (new & 0xFFFF) as u16;
            fe.first_cluster_high = ((new >> 16) & 0xFFFF) as u16;

            // starting_cluster==0 matches the pre-allocation entry
            self.update_dir_entry(path, fe, 0, None)?;
            cur = new;
        }

        let old_chain = self.get_all_clusters(cur)?;
        let old_len = old_chain.len();
        let need = (file_data.len() + cluster_sz - 1) / cluster_sz;

        let mut buf = vec![0u8; cluster_sz];
        let mut wcur = cur;

        for i in 0..need {
            let off = i * cluster_sz;
            let n = core::cmp::min(cluster_sz, file_data.len() - off);

            for b in &mut buf {
                *b = 0;
            }
            buf[..n].copy_from_slice(&file_data[off..off + n]);

            self.write_cluster_sync(wcur, &buf)?;

            if i < need - 1 {
                if i < old_len - 1 {
                    wcur = old_chain[i + 1];
                } else {
                    let next = self.find_free_cluster(wcur);
                    if next == 0xFFFF_FFFF {
                        return Err(FileStatus::UnknownFail);
                    }
                    self.update_fat(wcur, next);
                    wcur = next;

                    let zero = vec![0u8; cluster_sz];
                    self.write_cluster_sync(wcur, &zero)?;
                }
            } else {
                self.update_fat(wcur, 0xFFFF_FFFF);
            }
        }

        if old_len > need {
            for cl in &old_chain[need..] {
                self.update_fat(*cl, 0x0000_0000);
            }
        }

        fe.file_size = file_data.len() as u32;
        self.update_dir_entry(path, fe, fe.get_cluster(), None).ok();
        Ok(())
    }
    pub fn list_dir(&self, path: &str) -> Result<Vec<String>, FileStatus> {
        let parsed = Self::file_parser(path);
        let dir_entry = self.find_dir(path)?;
        let files = self.read_dir(dir_entry.get_cluster())?;
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
    #[inline]
    fn is_dir_attr(attr: u8) -> bool {
        (attr & 0x10) != 0
    }
    #[inline]
    fn is_lfn_attr(attr: u8) -> bool {
        attr == 0x0F
    }

    pub fn assemble_entries(files: &[FileEntry]) -> Vec<(String, FileAttribute, usize)> {
        let mut out = Vec::new();
        let mut lfn_buf: Vec<[u8; 32]> = Vec::new();

        for (i, e) in files.iter().enumerate() {
            let attr = e.attributes;

            if Self::is_lfn_attr(attr) {
                let mut raw = [0u8; 32];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (e as *const FileEntry) as *const u8,
                        raw.as_mut_ptr(),
                        32,
                    );
                }
                lfn_buf.push(raw);
                continue;
            }

            let first = e.name[0];
            if first == 0x00 || first == 0xE5 {
                lfn_buf.clear();
                continue;
            }

            let name = if !lfn_buf.is_empty() {
                let mut sfn = [0x20u8; 11];
                sfn[..8].copy_from_slice(&e.name);
                sfn[8..].copy_from_slice(&e.extension);
                let chk = FileEntry::lfn_checksum(&sfn);

                lfn_buf.reverse();

                let valid = lfn_buf.iter().all(|raw| raw[13] == chk);
                let mut utf16 = Vec::<u16>::new();
                if valid {
                    for raw in &lfn_buf {
                        // Name1
                        for k in (1..11).step_by(2) {
                            utf16.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                        // Name2
                        for k in (14..26).step_by(2) {
                            utf16.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                        // Name3
                        for k in (28..32).step_by(2) {
                            utf16.push(u16::from_le_bytes([raw[k], raw[k + 1]]));
                        }
                    }
                    if let Some(pos) = utf16.iter().position(|&w| w == 0x0000) {
                        utf16.truncate(pos);
                    }
                    utf16.retain(|&w| w != 0xFFFF);
                    lfn_buf.clear();
                    String::from_utf16_lossy(&utf16)
                } else {
                    lfn_buf.clear();
                    let mut s = {
                        let base = e
                            .name
                            .iter()
                            .take_while(|&&c| c != 0 && c != b' ')
                            .copied()
                            .collect::<Vec<u8>>();
                        String::from_utf8_lossy(&base).to_string()
                    };
                    let ext = e
                        .extension
                        .iter()
                        .take_while(|&&c| c != 0 && c != b' ')
                        .copied()
                        .collect::<Vec<u8>>();
                    if !ext.is_empty() {
                        s.push('.');
                        s.push_str(&String::from_utf8_lossy(&ext));
                    }
                    s
                }
            } else {
                let mut s = {
                    let base = e
                        .name
                        .iter()
                        .take_while(|&&c| c != 0 && c != b' ')
                        .copied()
                        .collect::<Vec<u8>>();
                    String::from_utf8_lossy(&base).to_string()
                };
                let ext = e
                    .extension
                    .iter()
                    .take_while(|&&c| c != 0 && c != b' ')
                    .copied()
                    .collect::<Vec<u8>>();
                if !ext.is_empty() {
                    s.push('.');
                    s.push_str(&String::from_utf8_lossy(&ext));
                }
                s
            };

            let fa = if Self::is_dir_attr(attr) {
                FileAttribute::Directory
            } else {
                FileAttribute::Archive
            };
            out.push((name, fa, i));
        }
        out
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, FileStatus> {
        let entry = self.find_file(path)?;
        let file_size = entry.file_size as usize;
        let cluster_sz = self.calc_cluster_size();
        let clusters = self.get_all_clusters(entry.get_cluster())?;

        let mut file_data = vec![0u8; file_size];
        let mut cluster = vec![0u8; cluster_sz];

        for (i, &cl) in clusters.iter().enumerate() {
            let base = i * cluster_sz;
            if base >= file_size {
                break;
            }
            self.read_cluster_sync(cl, &mut cluster)?;

            let remaining = file_size - base;
            let take = core::cmp::min(cluster_sz, remaining);
            file_data[base..base + take].copy_from_slice(&cluster[..take]);
        }

        Ok(file_data)
    }
    pub fn delete_file(&self, path: &str) -> Result<(), FileStatus> {
        if path == "\\" {
            return Ok(());
        }

        let entry = if Self::get_text_after_last_dot(path).is_empty() {
            self.find_dir(path)?
        } else {
            self.find_file(path)?
        };

        let clusters = self.get_all_clusters(entry.get_cluster())?;

        let dir_path = remove_file_from_path(path);
        let dir_entry = self.find_dir(dir_path)?;
        let dir_clusters = self.get_all_clusters(dir_entry.get_cluster())?;
        let mut dir_buffer = vec![0u8; (self.params.spc as usize * self.params.bps as usize)];

        for cluster in dir_clusters {
            self.read_cluster_sync(cluster, &mut dir_buffer)?;
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

                    self.write_cluster_sync(cluster, &dir_buffer)?;
                    break;
                }
            }
        }

        for cluster in clusters {
            self.update_fat(cluster, 0x00000000);
        }

        Ok(())
    }
    ///set ignore cluster to 0 to ignore no clusters
    fn find_free_cluster(&self, ignore: u32) -> u32 {
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
            read_sectors_sync(&self.volume, (base_lba + i) as u64, 1, 512, &mut sec);
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

        path: &str,
        new_entry: FileEntry,
        starting_cluster: u32,
        long_name: Option<String>,
    ) -> Result<(), FileStatus> {
        let dir_path = remove_file_from_path(path);
        let dir_entry = self.find_dir(dir_path)?;
        let dir_clusters = self.get_all_clusters(dir_entry.get_cluster())?;
        let mut dir_buffer =
            vec![0u8; (self.params.spc as usize * self.params.bps as usize) as usize];

        for cluster in dir_clusters {
            self.read_cluster_sync(cluster, &mut dir_buffer)?;
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
                        self.write_cluster_sync(cluster, &dir_buffer)?;

                        let (base, ext) = match ln.rsplit_once('.') {
                            Some((b, e)) => (b.to_string(), e.to_string()),
                            None => (ln.clone(), String::new()),
                        };
                        let new_entries =
                            FileEntry::new_long_name(&base, &ext, new_entry.get_cluster());

                        for e in &new_entries {
                            self.write_file_to_dir(e, dir_entry.get_cluster(), None)?;
                        }
                        return Ok(());
                    } else {
                        new_entry.write_to_buffer(&mut dir_buffer, i);
                        self.write_cluster_sync(cluster, &dir_buffer)?;
                        return Ok(());
                    }
                }
            }
        }

        Err(FileStatus::PathNotFound)
    }

    fn find_free_dir_run(&self, dir_clusters: &[u32], need_slots: usize) -> Option<(u32, usize)> {
        let esz = 32;
        let bpc = self.params.bps as usize * self.params.spc as usize;
        let mut buf = vec![0u8; bpc];

        for &cl in dir_clusters {
            self.read_cluster_sync(cl, &mut buf).ok()?;
            let mut run = 0usize;
            let mut start = 0usize;
            for i in (0..bpc).step_by(esz) {
                let b = buf[i];
                if b == 0x00 || b == 0xE5 {
                    if run == 0 {
                        start = i;
                    }
                    run += 1;
                    if run >= need_slots {
                        return Some((cl, start));
                    }
                } else {
                    run = 0;
                }
            }
        }
        None
    }

    fn write_dir_run(
        &self,
        cluster: u32,
        offset: usize,
        entries: &[[u8; 32]],
    ) -> Result<(), FileStatus> {
        let bpc = self.params.bps as usize * self.params.spc as usize;
        let mut buf = vec![0u8; bpc];
        self.read_cluster_sync(cluster, &mut buf)?;
        for (k, e) in entries.iter().enumerate() {
            let off = offset + k * 32;
            buf[off..off + 32].copy_from_slice(e);
        }
        self.write_cluster_sync(cluster, &buf)
    }

    fn write_file_to_dir(
        &self,
        entry: &FileEntry,
        start_cluster_of_dir: u32,
        long_name: Option<String>,
    ) -> Result<(), FileStatus> {
        let (records, total) = if let Some(ref ln) = long_name {
            let (name_part, ext_part) = ln
                .rsplit_once('.')
                .map(|(n, e)| (n, e))
                .unwrap_or((ln.as_str(), ""));
            let entries = FileEntry::new_long_name(name_part, ext_part, entry.get_cluster());

            let mut recs: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
            for e in &entries {
                let mut b = [0u8; 32];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (e as *const FileEntry) as *const u8,
                        b.as_mut_ptr(),
                        32,
                    );
                }
                recs.push(b);
            }
            if let Some(last) = recs.last_mut() {
                last[11] = entry.attributes;
                last[28..32].copy_from_slice(&entry.file_size.to_le_bytes());
                last[20..22].copy_from_slice(&entry.first_cluster_high.to_le_bytes());
                last[26..28].copy_from_slice(&entry.first_cluster_low.to_le_bytes());
            }
            (recs, entries.len())
        } else {
            let mut b = [0u8; 32];
            let mut tmp = [0u8; 32];
            entry.write_to_buffer(&mut tmp, 0);
            b.copy_from_slice(&tmp);
            (vec![b], 1)
        };

        let dir_clusters = self.get_all_clusters(start_cluster_of_dir)?;
        if let Some((cl, off)) = self.find_free_dir_run(&dir_clusters, total) {
            return self.write_dir_run(cl, off, &records);
        }

        let free = self.find_free_cluster(0);
        if free == 0xFFFF_FFFF {
            return Err(FileStatus::UnknownFail);
        }
        let last = *dir_clusters.last().ok_or(FileStatus::UnknownFail)?;
        self.update_fat(last, free);
        self.update_fat(free, 0xFFFF_FFFF);
        let zero = vec![0u8; self.calc_cluster_size()];
        self.write_cluster_sync(free, &zero)?;
        self.write_file_to_dir(entry, start_cluster_of_dir, long_name)
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

    fn fat_entry(&self, cl: u32) -> Result<u32, FileStatus> {
        let bps = self.params.bps as usize;
        let sector = self.sector_for_cluster(cl);
        let off = self.cluster_in_sector(cl);
        let mut sec = vec![0u8; bps];
        read_sectors_sync(&self.volume, sector as u64, 1, bps, &mut sec)?;
        Ok(u32::from_le_bytes([sec[off], sec[off + 1], sec[off + 2], sec[off + 3]]) & 0x0FFF_FFFF)
    }
    fn is_eoc(v: u32) -> bool {
        v >= 0x0FFF_FFF8 && v <= 0x0FFF_FFFF
    }

    pub fn get_all_clusters(&self, start: u32) -> Result<Vec<u32>, FileStatus> {
        let mut out = Vec::new();
        let mut cl = start & 0x0FFF_FFFF;

        if cl < 2 {
            return Ok(out);
        }

        loop {
            out.push(cl);
            let next = self.fat_entry(cl)?;
            if Self::is_eoc(next) {
                break;
            }
            if next == 0x0FFF_FFF7 {
                println!("Corrupt fat table");
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
}
pub fn read_sectors_sync(
    target: &Arc<IoTarget>,
    lba: u64,
    sectors: usize,
    bps: usize,
    out: &mut [u8],
) -> Result<(), FileStatus> {
    let bytes = sectors.checked_mul(bps).ok_or(FileStatus::UnknownFail)?;
    if out.len() < bytes {
        return Err(FileStatus::UnknownFail);
    }
    let mut req = Arc::new(RwLock::new(Request::new(
        RequestType::Read {
            offset: lba.checked_mul(bps as u64).ok_or(FileStatus::UnknownFail)?,
            len: bytes,
        },
        vec![0u8; bytes].into_boxed_slice(),
    )));
    unsafe { pnp_send_request(target.as_ref(), req.clone()) };
    unsafe { pnp_wait_for_request(&req) };
    if req.read().data.len() < bytes {
        return Err(FileStatus::UnknownFail);
    }
    out[..bytes].copy_from_slice(&req.read().data[..bytes]);
    Ok(())
}

pub fn write_sectors_sync(
    target: &Arc<IoTarget>,
    lba: u64,
    sectors: usize,
    bps: usize,
    data: &[u8],
) -> Result<(), FileStatus> {
    let bytes = sectors.checked_mul(bps).ok_or(FileStatus::UnknownFail)?;
    if data.len() < bytes {
        return Err(FileStatus::UnknownFail);
    }
    let mut req = Arc::new(RwLock::new(Request::new(
        RequestType::Write {
            offset: lba.checked_mul(bps as u64).ok_or(FileStatus::UnknownFail)?,
            len: bytes,
        },
        data[..bytes].to_vec().into_boxed_slice(),
    )));
    unsafe { pnp_send_request(&**target, req.clone()) };
    unsafe { pnp_wait_for_request(&req) };
    Ok(())
}
pub extern "win64" fn remove_file_from_path(path: &str) -> &str {
    let parent = path.rsplit_once('\\').map_or("", |(parent, _)| parent);

    if parent.is_empty() {
        "\\"
    } else if parent == "\\\\" {
        "\\"
    } else {
        parent
    }
}
