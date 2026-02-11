use alloc::{vec, vec::Vec};
use core::cmp::min;

use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    kernel_types::{io::IoTarget, request::RequestData},
    pnp::pnp_send_request,
    request::{Request, RequestHandle, RequestType, TraversalPolicy},
    runtime::block_on,
    status::DriverStatus,
};

const MAX_CHUNK_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    /// Small buffer only for unaligned partial-sector reads/writes
    sector_buf: Vec<u8>,
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
    pub fn new(volume: IoTarget, sector_size: u16, total_sectors: u64) -> Self {
        Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
            sector_buf: vec![0u8; sector_size as usize],
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

    /// Read into a buffer (allocates internal buffer, copies result)
    async fn pnp_read_into(
        volume: &IoTarget,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), DriverStatus> {
        let len = buf.len();
        let mut handle = RequestHandle::new(
            RequestType::Read { offset, len },
            RequestData::from_boxed_bytes(alloc::vec![0u8; len].into_boxed_slice()),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower);

        let st = pnp_send_request(volume.clone(), &mut handle).await;
        if st == DriverStatus::Success {
            let data = handle.read();
            buf.copy_from_slice(data.data.as_slice());
        }

        if st == DriverStatus::Success {
            Ok(())
        } else {
            Err(st)
        }
    }

    /// Write from a buffer (copies data into request)
    async fn pnp_write_from(
        volume: &IoTarget,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), DriverStatus> {
        let len = buf.len();
        let mut handle = RequestHandle::new(
            RequestType::Write {
                offset,
                len,
                flush_write_through: false,
            },
            RequestData::from_boxed_bytes(buf.to_vec().into_boxed_slice()),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower);

        let st = pnp_send_request(volume.clone(), &mut handle).await;

        if st == DriverStatus::Success {
            Ok(())
        } else {
            Err(st)
        }
    }

    async fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize, BlkError> {
        let to_read = self.clamp_len(dst.len());
        if to_read == 0 {
            return Ok(0);
        }

        let bps = self.bps();
        let mut remaining = to_read;
        let mut out_off = 0usize;

        while remaining != 0 {
            let pos = self.pos;
            let lba = self.lba_of(pos);
            let in_off = self.in_sector_off(pos);
            let room = bps - in_off;

            // Unaligned or partial sector read - must use sector buffer
            if in_off != 0 || remaining < bps {
                let sector_off = lba * bps as u64;
                Self::pnp_read_into(&self.volume, sector_off, &mut self.sector_buf[..bps])
                    .await
                    .map_err(BlkError::from)?;
                let take = min(remaining, room);
                dst[out_off..out_off + take]
                    .copy_from_slice(&self.sector_buf[in_off..in_off + take]);
                self.pos += take as u64;
                out_off += take;
                remaining -= take;
                continue;
            }

            // Aligned read - read into destination buffer
            let full_sectors = remaining / bps;
            let max_sectors = (MAX_CHUNK_BYTES / bps).max(1);
            let chunk_sectors = min(full_sectors, max_sectors);
            let chunk_bytes = chunk_sectors * bps;

            let byte_off = lba * bps as u64;
            Self::pnp_read_into(
                &self.volume,
                byte_off,
                &mut dst[out_off..out_off + chunk_bytes],
            )
            .await
            .map_err(BlkError::from)?;

            self.pos += chunk_bytes as u64;
            out_off += chunk_bytes;
            remaining -= chunk_bytes;
        }

        Ok(to_read)
    }

    async fn write_bytes(&mut self, src: &[u8]) -> Result<usize, BlkError> {
        let to_write = self.clamp_len(src.len());
        if to_write == 0 {
            return Ok(0);
        }

        let bps = self.bps();
        let mut remaining = to_write;
        let mut in_off_src = 0usize;

        while remaining != 0 {
            let pos = self.pos;
            let lba = self.lba_of(pos);
            let in_off = self.in_sector_off(pos);
            let room = bps - in_off;

            // Unaligned or partial sector write - need read-modify-write
            if in_off != 0 || remaining < bps {
                let sector_off = lba * bps as u64;

                // Read existing sector
                Self::pnp_read_into(&self.volume, sector_off, &mut self.sector_buf[..bps])
                    .await
                    .map_err(BlkError::from)?;

                // Modify
                let take = min(remaining, room);
                self.sector_buf[in_off..in_off + take]
                    .copy_from_slice(&src[in_off_src..in_off_src + take]);

                // Write back
                Self::pnp_write_from(&self.volume, sector_off, &self.sector_buf[..bps])
                    .await
                    .map_err(BlkError::from)?;

                self.pos += take as u64;
                in_off_src += take;
                remaining -= take;
                continue;
            }

            // Aligned write - write from source
            let full_sectors = remaining / bps;
            let max_sectors = (MAX_CHUNK_BYTES / bps).max(1);
            let chunk_sectors = min(full_sectors, max_sectors);
            let chunk_bytes = chunk_sectors * bps;

            let byte_off = lba * bps as u64;

            Self::pnp_write_from(
                &self.volume,
                byte_off,
                &src[in_off_src..in_off_src + chunk_bytes],
            )
            .await
            .map_err(BlkError::from)?;

            self.pos += chunk_bytes as u64;
            in_off_src += chunk_bytes;
            remaining -= chunk_bytes;
        }

        Ok(to_write)
    }
}

impl Read for BlockDev {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        block_on(self.read_bytes(buf)).map_err(|_| ())
    }
}

impl Write for BlockDev {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        block_on(self.write_bytes(buf)).map_err(|_| ())
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
