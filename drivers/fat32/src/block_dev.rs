use alloc::{vec, vec::Vec};
use core::{cmp::min, mem::transmute};

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    kernel_types::{io::IoTarget, request::RequestData},
    pnp::pnp_send_request,
    println,
    request::{RequestHandle, RequestType, SharedRequest, TraversalPolicy},
    runtime::block_on,
    status::DriverStatus,
};

const MAX_CHUNK_BYTES: usize = 256 * 1024;

pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    /// Scratch buffer used for partial-sector R/W to avoid per-call allocations.
    scratch: Vec<u8>,
    /// Shared flush flag with VolCtrlDevExt
    pub(crate) should_flush: Arc<AtomicBool>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlkError {
    InvalidInput,
    Io,
    Driver(DriverStatus),
}

impl From<DriverStatus> for BlkError {
    fn from(v: DriverStatus) -> Self {
        Self::Driver(v)
    }
}

impl IoBase for BlockDev {
    type Error = ();
}

impl BlockDev {
    #[inline]
    unsafe fn borrowed_reqdata_from_mut(buf: &mut [u8]) -> RequestData {
        // Extend the lifetime to 'static for the duration of the request.
        let static_ref: &'static mut u8 = transmute(buf.as_mut_ptr());
        let mut data = RequestData::from_borrowed_t(static_ref);
        data.set_len(buf.len());
        data
    }

    #[inline]
    unsafe fn borrowed_reqdata_from(buf: &[u8]) -> RequestData {
        // Read-only borrow; lower drivers must not mutate.
        let static_ref: &'static mut u8 = transmute(buf.as_ptr() as *mut u8);
        let mut data = RequestData::from_borrowed_t(static_ref);
        data.set_len(buf.len());
        data
    }

    pub fn new(
        volume: IoTarget,
        sector_size: u16,
        total_sectors: u64,
        should_flush: Arc<AtomicBool>,
    ) -> Self {
        let scratch = vec![0u8; sector_size as usize];
        Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
            scratch,
            should_flush,
        }
    }

    #[inline]
    fn bps(&self) -> usize {
        self.sector_size as usize
    }

    #[inline]
    fn capacity_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.sector_size as u64)
    }

    #[inline]
    fn lba_of(&self, byte_off: u64) -> u64 {
        byte_off / self.sector_size as u64
    }

    #[inline]
    fn in_sector_off(&self, byte_off: u64) -> usize {
        (byte_off % self.sector_size as u64) as usize
    }

    /// Read into a buffer using pre-allocated request
    async fn pnp_read_into(
        volume: &IoTarget,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), DriverStatus> {
        let len = buf.len();

        let mut req = unsafe {
            RequestHandle::new(
                RequestType::Read { offset, len },
                Self::borrowed_reqdata_from_mut(buf),
            )
        };
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        let st = pnp_send_request(volume.clone(), &mut req).await;

        if st == DriverStatus::Success {
            return Ok(());
        }
        println!("Error: {:#?}", st);
        Err(st)
    }

    /// Write from a buffer using pre-allocated request
    async fn pnp_write_from(
        volume: &IoTarget,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), DriverStatus> {
        let len = buf.len();

        let mut req = unsafe {
            RequestHandle::new(
                RequestType::Write {
                    offset,
                    len,
                    flush_write_through: false,
                },
                Self::borrowed_reqdata_from(buf),
            )
        };
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        let st = pnp_send_request(volume.clone(), &mut req).await;

        if st == DriverStatus::Success {
            Ok(())
        } else {
            println!("Error: {:#?}", st);
            Err(st)
        }
    }

    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize, DriverStatus> {
        let mut remaining = dst.len();
        if remaining == 0 {
            return Ok(0);
        }

        let cap_bytes = self.capacity_bytes();
        if self.pos >= cap_bytes {
            return Ok(0);
        }

        // Clamp reads that would pass the end of the device.
        remaining = min(remaining, (cap_bytes - self.pos) as usize);
        let mut written = 0usize;
        let mut cur_off = self.pos;
        let bps = self.bps();
        let volume = &self.volume;

        // Handle leading partial sector, if any.
        let in_sector = self.in_sector_off(cur_off);
        if in_sector != 0 {
            let lba_base = cur_off - in_sector as u64;
            let take = min(bps - in_sector, remaining);
            let scratch = &mut self.scratch[..bps];

            block_on(async { Self::pnp_read_into(volume, lba_base, scratch).await })?;
            dst[..take].copy_from_slice(&scratch[in_sector..in_sector + take]);

            cur_off += take as u64;
            written += take;
            remaining -= take;
        }

        // Whole aligned sectors can stream directly into destination in chunks.
        let aligned_bytes = remaining - (remaining % bps);
        if aligned_bytes != 0 {
            let mut done = 0;
            while done < aligned_bytes {
                // Cap each IO to MAX_CHUNK_BYTES while staying sector aligned.
                let max_chunk = MAX_CHUNK_BYTES - (MAX_CHUNK_BYTES % bps);
                let chunk = if max_chunk == 0 {
                    // Fallback for unusually large sector sizes.
                    min(bps, aligned_bytes - done)
                } else {
                    min(max_chunk, aligned_bytes - done)
                };
                let dst_slice = &mut dst[written + done..written + done + chunk];
                block_on(async { Self::pnp_read_into(volume, cur_off, dst_slice).await })?;

                cur_off += chunk as u64;
                done += chunk;
            }
            written += aligned_bytes;
            remaining -= aligned_bytes;
        }

        // Trailing partial sector.
        if remaining != 0 {
            let scratch = &mut self.scratch[..bps];
            block_on(async { Self::pnp_read_into(volume, cur_off, scratch).await })?;
            dst[written..written + remaining].copy_from_slice(&scratch[..remaining]);

            cur_off += remaining as u64;
            written += remaining;
        }

        self.pos = cur_off;
        Ok(written)
    }

    fn write_bytes(&mut self, src: &[u8]) -> Result<usize, DriverStatus> {
        let mut remaining = src.len();
        if remaining == 0 {
            return Ok(0);
        }

        let cap_bytes = self.capacity_bytes();
        if self.pos >= cap_bytes {
            return Ok(0);
        }

        // Clamp writes beyond end of device.
        remaining = min(remaining, (cap_bytes - self.pos) as usize);
        let mut written = 0usize;
        let mut cur_off = self.pos;
        let bps = self.bps();
        let volume = &self.volume;

        // Leading partial sector (read-modify-write).
        let in_sector = self.in_sector_off(cur_off);
        if in_sector != 0 {
            let lba_base = cur_off - in_sector as u64;
            let write_len = min(bps - in_sector, remaining);
            let scratch = &mut self.scratch[..bps];

            block_on(async { Self::pnp_read_into(volume, lba_base, scratch).await })?;
            scratch[in_sector..in_sector + write_len].copy_from_slice(&src[..write_len]);
            block_on(async { Self::pnp_write_from(volume, lba_base, scratch).await })?;

            cur_off += write_len as u64;
            written += write_len;
            remaining -= write_len;
        }

        // Aligned middle portion.
        let aligned_bytes = remaining - (remaining % bps);
        if aligned_bytes != 0 {
            let mut done = 0;
            while done < aligned_bytes {
                let max_chunk = MAX_CHUNK_BYTES - (MAX_CHUNK_BYTES % bps);
                let chunk = if max_chunk == 0 {
                    min(bps, aligned_bytes - done)
                } else {
                    min(max_chunk, aligned_bytes - done)
                };
                let src_slice = &src[written + done..written + done + chunk];
                block_on(async { Self::pnp_write_from(volume, cur_off, src_slice).await })?;

                cur_off += chunk as u64;
                done += chunk;
            }
            written += aligned_bytes;
            remaining -= aligned_bytes;
        }

        // Trailing partial sector (read-modify-write).
        if remaining != 0 {
            let scratch = &mut self.scratch[..bps];
            block_on(async { Self::pnp_read_into(volume, cur_off, scratch).await })?;
            scratch[..remaining].copy_from_slice(&src[written..written + remaining]);
            block_on(async { Self::pnp_write_from(volume, cur_off, scratch).await })?;

            cur_off += remaining as u64;
            written += remaining;
        }

        self.pos = cur_off;
        Ok(written)
    }
}

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
        self.should_flush.store(true, Ordering::SeqCst);
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
