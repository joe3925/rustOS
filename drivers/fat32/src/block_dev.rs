#![no_std]

use alloc::{sync::Arc, vec, vec::Vec};
use core::cmp::min;
use spin::RwLock;

use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    RequestExt,
    kernel_types::io::IoTarget,
    pnp::pnp_send_request,
    println,
    request::{Request, RequestType, TraversalPolicy},
    status::DriverStatus,
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
    Driver(DriverStatus),
}
impl From<DriverStatus> for BlkError {
    fn from(_v: DriverStatus) -> Self {
        Self::Driver(_v)
    }
}

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

    async fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize, BlkError> {
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

        read_sectors_async(&self.volume, start_lba, n_sectors, bps, &mut tmp[..])
            .await
            .map_err(BlkError::from)?;

        let in_off = self.in_sector_off(self.pos);
        dst[..to_read].copy_from_slice(&tmp[in_off..in_off + to_read]);
        self.pos += to_read as u64;
        Ok(to_read)
    }

    async fn write_bytes(&mut self, src: &[u8]) -> Result<usize, BlkError> {
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
            write_sectors_async(&self.volume, start_lba, sectors_exact, bps, buf)
                .await
                .map_err(BlkError::from)?;
        } else {
            let mut buf = Vec::with_capacity(n_sectors * bps);
            unsafe {
                buf.set_len(n_sectors * bps);
            }
            read_sectors_async(&self.volume, start_lba, n_sectors, bps, &mut buf[..])
                .await
                .map_err(BlkError::from)?;
            buf[head_off..head_off + to_write].copy_from_slice(&src[..to_write]);
            write_sectors_async(&self.volume, start_lba, n_sectors, bps, &buf[..])
                .await
                .map_err(BlkError::from)?;
        }

        self.pos += to_write as u64;
        Ok(to_write)
    }
}

impl Read for BlockDev {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        todo!();
        //block_on(self.read_bytes(buf)).map_err(|_| ())
    }
}

impl Write for BlockDev {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        todo!();
        //block_on(self.write_bytes(buf)).map_err(|_| ())
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
// pub fn read_sectors_sync(
//     target: &Arc<IoTarget>,
//     lba: u64,
//     sectors: usize,
//     bps: usize,
//     out: &mut [u8],
// ) -> Result<(), DriverStatus> {
//     let bytes = match sectors.checked_mul(bps) {
//         Some(b) => b,
//         None => return Err(DriverStatus::InvalidParameter),
//     };

//     if out.len() < bytes {
//         return Err(DriverStatus::InvalidParameter);
//     }

//     let offset = match lba.checked_mul(bps as u64) {
//         Some(o) => o,
//         None => return Err(DriverStatus::InvalidParameter),
//     };

//     let req = Arc::new(RwLock::new(Request::new(
//         RequestType::Read { offset, len: bytes },
//         alloc::vec![0u8; bytes].into_boxed_slice(),
//     )));

//     unsafe { pnp_send_request(target.as_ref(), req.clone()) };
//     unsafe { pnp_wait_for_request(&req) };

//     let r = req.read();
//     if r.status != DriverStatus::Success {
//         println!("")
//         return Err(r.status);
//     }

//     if r.data.len() < bytes {
//         return Err(DriverStatus::Unsuccessful);
//     }

//     out[..bytes].copy_from_slice(&r.data[..bytes]);
//     Ok(())
// }

// pub fn write_sectors_sync(
//     target: &Arc<IoTarget>,
//     lba: u64,
//     sectors: usize,
//     bps: usize,
//     data: &[u8],
// ) -> Result<(), DriverStatus> {
//     let bytes = match sectors.checked_mul(bps) {
//         Some(b) => b,
//         None => return Err(DriverStatus::InvalidParameter),
//     };

//     if data.len() < bytes {
//         return Err(DriverStatus::InvalidParameter);
//     }

//     let offset = match lba.checked_mul(bps as u64) {
//         Some(o) => o,
//         None => return Err(DriverStatus::InvalidParameter),
//     };

//     let req = Arc::new(RwLock::new(Request::new(
//         RequestType::Write { offset, len: bytes },
//         data[..bytes].to_vec().into_boxed_slice(),
//     )));

//     unsafe { pnp_send_request(&**target, req.clone()) };
//     unsafe { pnp_wait_for_request(&req) };

//     let status = req.read().status;
//     if status == DriverStatus::Success {
//         Ok(())
//     } else {
//         Err(status)
//     }
// }
pub async fn read_sectors_async(
    target: &Arc<IoTarget>,
    lba: u64,
    sectors: usize,
    bps: usize,
    out: &mut [u8],
) -> Result<(), DriverStatus> {
    let bytes = match sectors.checked_mul(bps) {
        Some(b) => b,
        None => return Err(DriverStatus::InvalidParameter),
    };

    if out.len() < bytes {
        return Err(DriverStatus::InvalidParameter);
    }

    let offset = match lba.checked_mul(bps as u64) {
        Some(o) => o,
        None => return Err(DriverStatus::InvalidParameter),
    };
    let mut req_owned = Request::new(
        RequestType::Read { offset, len: bytes },
        alloc::vec![0u8; bytes].into_boxed_slice(),
    );
    req_owned.traversal_policy = TraversalPolicy::ForwardLower;
    let req = Arc::new(RwLock::new(req_owned));

    unsafe { pnp_send_request(target.as_ref(), req.clone()) }?.await;
    let r = req.read();
    if r.status != DriverStatus::Success {
        println!(
            "Read failed: LBA={} Count={} Status={:?}",
            lba, sectors, r.status
        );
        return Err(r.status);
    }

    if r.data.len() < bytes {
        println!("Read incomplete: expected {} got {}", bytes, r.data.len());
        return Err(DriverStatus::Unsuccessful);
    }

    out[..bytes].copy_from_slice(&r.data[..bytes]);
    Ok(())
}

pub async fn write_sectors_async(
    target: &Arc<IoTarget>,
    lba: u64,
    sectors: usize,
    bps: usize,
    data: &[u8],
) -> Result<(), DriverStatus> {
    let bytes = match sectors.checked_mul(bps) {
        Some(b) => b,
        None => return Err(DriverStatus::InvalidParameter),
    };

    if data.len() < bytes {
        return Err(DriverStatus::InvalidParameter);
    }

    let offset = match lba.checked_mul(bps as u64) {
        Some(o) => o,
        None => return Err(DriverStatus::InvalidParameter),
    };
    let mut req_owned = Request::new(
        RequestType::Write { offset, len: bytes },
        data[..bytes].to_vec().into_boxed_slice(),
    );
    req_owned.traversal_policy = TraversalPolicy::ForwardLower;
    let req = Arc::new(RwLock::new(req_owned));

    unsafe { pnp_send_request(&**target, req.clone()) }?.await;

    let status = req.read().status;
    if status == DriverStatus::Success {
        Ok(())
    } else {
        println!(
            "Write failed: LBA={} Count={} Status={:?}",
            lba, sectors, status
        );
        Err(status)
    }
}
