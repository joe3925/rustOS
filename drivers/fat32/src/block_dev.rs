#![no_std]

use alloc::{sync::Arc, vec, vec::Vec};
use core::cmp::min;
use spin::RwLock;

use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    FileStatus, IoTarget, Request, RequestType,
    alloc_api::ffi::{pnp_send_request, pnp_wait_for_request},
    println,
};

#[derive(Clone)]
pub struct BlockDev {
    volume: Arc<IoTarget>,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlkError {
    InvalidInput,
    Io,
}
impl From<FileStatus> for BlkError {
    fn from(_v: FileStatus) -> Self {
        BlkError::Io
    }
}

/* fatfs requires Error = () for IoBase on this crate version */
impl IoBase for BlockDev {
    type Error = ();
}

impl BlockDev {
    pub fn new(volume: Arc<IoTarget>, sector_size: u16, total_sectors: u64) -> Self {
        Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
        }
    }

    #[inline]
    fn capacity_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.sector_size as u64)
    }

    #[inline]
    fn clamp_len(&self, want: usize) -> usize {
        let cap = self.capacity_bytes();
        if self.pos >= cap {
            return 0;
        }
        let remain = (cap - self.pos) as usize;
        min(remain, want)
    }

    #[inline]
    fn lba_of(&self, byte_off: u64) -> u64 {
        byte_off / self.sector_size as u64
    }
    #[inline]
    fn in_sector_off(&self, byte_off: u64) -> usize {
        (byte_off % self.sector_size as u64) as usize
    }

    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize, BlkError> {
        let to_read = self.clamp_len(dst.len());
        if to_read == 0 {
            return Ok(0);
        }

        let bps = self.sector_size as usize;
        let start_lba = self.lba_of(self.pos);
        let end_byte = self.pos + to_read as u64;
        let end_lba = self.lba_of(end_byte - 1) + 1;
        let n_sectors = (end_lba - start_lba) as usize;

        let mut tmp = Vec::with_capacity(n_sectors * bps);
        unsafe {
            tmp.set_len(n_sectors * bps);
        }

        read_sectors_sync(&self.volume, start_lba, n_sectors, bps, &mut tmp[..])
            .map_err(BlkError::from)?;

        let in_off = self.in_sector_off(self.pos);
        dst[..to_read].copy_from_slice(&tmp[in_off..in_off + to_read]);
        self.pos += to_read as u64;
        Ok(to_read)
    }

    fn write_bytes(&mut self, src: &[u8]) -> Result<usize, BlkError> {
        let to_write = self.clamp_len(src.len());
        if to_write == 0 {
            return Ok(0);
        }

        let bps = self.sector_size as usize;
        let start_lba = self.lba_of(self.pos);
        let end_byte = self.pos + to_write as u64;
        let end_lba = self.lba_of(end_byte - 1) + 1;
        let n_sectors = (end_lba - start_lba) as usize;

        let head_off = self.in_sector_off(self.pos);
        let tail_bytes = ((self.pos as usize + to_write) % bps) as usize;

        if head_off == 0 && tail_bytes == 0 {
            let sectors_exact = to_write / bps;
            let buf = &src[..to_write];
            write_sectors_sync(&self.volume, start_lba, sectors_exact, bps, buf)
                .map_err(BlkError::from)?;
        } else {
            let mut buf = Vec::with_capacity(n_sectors * bps);
            unsafe {
                buf.set_len(n_sectors * bps);
            }
            read_sectors_sync(&self.volume, start_lba, n_sectors, bps, &mut buf[..])
                .map_err(BlkError::from)?;
            buf[head_off..head_off + to_write].copy_from_slice(&src[..to_write]);
            write_sectors_sync(&self.volume, start_lba, n_sectors, bps, &buf[..])
                .map_err(BlkError::from)?;
        }

        self.pos += to_write as u64;
        Ok(to_write)
    }
}

/* === fatfs::Read/Write/Seek impls (map internal BlkError -> ()) === */
impl Read for BlockDev {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.read_bytes(buf).map_err(|_| ())
    }
}

impl Write for BlockDev {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.write_bytes(buf).map_err(|_| ())
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Seek for BlockDev {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        let cap = self.capacity_bytes();
        let new = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::End(off) => {
                let base = cap as i128 + off as i128;
                if base < 0 {
                    return Err(());
                }
                base as u64
            }
            SeekFrom::Current(off) => {
                let base = self.pos as i128 + off as i128;
                if base < 0 {
                    return Err(());
                }
                base as u64
            }
        };
        if new > cap {
            return Err(());
        }
        self.pos = new;
        Ok(self.pos)
    }
}

/* === Sector IO === */
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
    let req = Arc::new(RwLock::new(Request::new(
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
    let req = Arc::new(RwLock::new(Request::new(
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
