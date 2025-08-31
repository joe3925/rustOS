use alloc::sync::Arc;
use kernel_api::alloc_api::ffi::{pnp_send_request, pnp_wait_for_request};
use kernel_api::{DeviceObject, DriverStatus, FileStatus, IoTarget, Request, RequestType, println};
use spin::RwLock;

use crate::alloc::vec;
use crate::structs::{FatParams, InfoSector};
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

    pub fn read_clusters_sync(
        &self,
        first_cluster: u32,
        cluster_count: u32,
        out: &mut [u8],
    ) -> Result<(), FileStatus> {
        if first_cluster < 2 || cluster_count == 0 {
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
