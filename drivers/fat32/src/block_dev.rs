use alloc::{vec, vec::Vec};
use core::cmp::min;

use alloc::sync::Arc;
use core::mem;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    kernel_types::{io::IoTarget, request::RequestData},
    pnp::pnp_send_request,
    println,
    request::{BorrowedHandle, BufSlice, RequestHandle, RequestType, TraversalPolicy},
    runtime::block_on,
    status::DriverStatus,
};

use crate::volume::VolCtrlDevExt;

const DEVICE_MAX_IO_BYTES: usize = 64 * 1024;

pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    /// Scratch buffer used only for partial-sector R/W (the single allocation).
    scratch: Vec<u8>,
    /// Reusable request — data slot is overwritten each call via BorrowedHandle.
    req: RequestHandle<'static>,
    /// Shared flush flag with VolCtrlDevExt
    pub(crate) should_flush: Arc<AtomicBool>,
    /// Current file owner tag — set before FS writes, read by prep_write_req.
    pub(crate) current_owner: Arc<AtomicU64>,
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
    pub fn new(
        volume: IoTarget,
        sector_size: u16,
        total_sectors: u64,
        should_flush: Arc<AtomicBool>,
        current_owner: Arc<AtomicU64>,
    ) -> Self {
        let scratch = vec![0u8; sector_size as usize];
        let req = RequestHandle::new(
            RequestType::Read { offset: 0, len: 0 },
            RequestData::empty(),
        );
        Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
            scratch,
            req,
            should_flush,
            current_owner,
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
    fn in_sector_off(&self, byte_off: u64) -> usize {
        (byte_off % self.sector_size as u64) as usize
    }

    /// Reset the request header for a read, leaving data empty.
    #[inline]
    fn prep_req_read(&mut self, offset: u64, len: usize) {
        match &mut self.req {
            RequestHandle::Owned(r) => {
                r.kind = RequestType::Read { offset, len };
                r.completed = false;
                r.status = DriverStatus::ContinueStep;
                r.traversal_policy = TraversalPolicy::ForwardLower;
                r.pnp = None;
                r.completion_routine = None;
                r.completion_context = 0;
            }
            _ => unreachable!(),
        }
    }

    /// Reset the request header for a write, leaving data empty.
    #[inline]
    fn prep_req_write(&mut self, offset: u64, len: usize, flush_write_through: bool) {
        match &mut self.req {
            RequestHandle::Owned(r) => {
                r.kind = RequestType::Write {
                    offset,
                    len,
                    flush_write_through,
                    owner: self.current_owner.load(Ordering::Acquire),
                };
                r.completed = false;
                r.status = DriverStatus::ContinueStep;
                r.traversal_policy = TraversalPolicy::ForwardLower;
                r.pnp = None;
                r.completion_routine = None;
                r.completion_context = 0;
            }
            _ => unreachable!(),
        }
    }

    /// Send a read, borrowing `dst` directly so the lower driver writes into it.
    async fn send_read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), DriverStatus> {
        let len = dst.len();
        let volume = self.volume.clone();
        self.prep_req_read(offset, len);

        let mut buf = BufSlice::new(dst);
        let status = {
            let mut borrow = BorrowedHandle::<BufSlice>::new(&mut self.req, &mut buf);
            pnp_send_request(volume, borrow.handle()).await
        };

        if status == DriverStatus::Success {
            Ok(())
        } else {
            println!("Read Error: {:#?}", status);
            Err(status)
        }
    }

    /// Send a write, borrowing `src` directly — zero copy for aligned data.
    async fn send_write(&mut self, offset: u64, src: &mut [u8]) -> Result<(), DriverStatus> {
        let len = src.len();
        let volume = self.volume.clone();
        self.prep_req_write(offset, len, false);

        let mut buf = BufSlice::new(src);
        let status = {
            let mut borrow = BorrowedHandle::<BufSlice>::new(&mut self.req, &mut buf);
            pnp_send_request(volume, borrow.handle()).await
        };

        if status == DriverStatus::Success {
            Ok(())
        } else {
            println!("Write Error: {:#?}", status);
            Err(status)
        }
    }

    /// Send a write from an immutable source. Uses `BufSlice::from_const`;
    /// lower stack must not mutate write buffers.
    async fn send_write_immut(&mut self, offset: u64, src: &[u8]) -> Result<(), DriverStatus> {
        let len = src.len();
        let volume = self.volume.clone();
        self.prep_req_write(offset, len, false);

        // SAFETY: lower drivers only read from write-request buffers.
        let mut buf = unsafe { BufSlice::from_const(src) };
        let status = {
            let mut borrow = BorrowedHandle::<BufSlice>::new(&mut self.req, &mut buf);
            pnp_send_request(volume, borrow.handle()).await
        };

        if status == DriverStatus::Success {
            Ok(())
        } else {
            println!("Write Error: {:#?}", status);
            Err(status)
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

        remaining = min(remaining, (cap_bytes - self.pos) as usize);
        let mut written = 0usize;
        let mut cur_off = self.pos;
        let bps = self.bps();

        // Leading partial sector — uses scratch buffer.
        let in_sector = self.in_sector_off(cur_off);
        if in_sector != 0 {
            let lba_base = cur_off - in_sector as u64;
            let take = min(bps - in_sector, remaining);

            // Take scratch out of self so we can pass &mut self to send_read.
            let mut scratch = mem::take(&mut self.scratch);
            block_on(self.send_read(lba_base, &mut scratch[..bps]))?;
            dst[..take].copy_from_slice(&scratch[in_sector..in_sector + take]);
            self.scratch = scratch;

            cur_off += take as u64;
            written += take;
            remaining -= take;
        }

        // Whole aligned sectors stream directly into destination — zero copy.
        let aligned_bytes = remaining - (remaining % bps);
        if aligned_bytes != 0 {
            let mut done = 0;
            while done < aligned_bytes {
                let device_cap = DEVICE_MAX_IO_BYTES - (DEVICE_MAX_IO_BYTES % bps);
                let chunk_cap = if device_cap == 0 { bps } else { device_cap };
                let chunk = min(aligned_bytes - done, chunk_cap);
                let dst_slice = &mut dst[written + done..written + done + chunk];
                block_on(self.send_read(cur_off, dst_slice))?;

                cur_off += chunk as u64;
                done += chunk;
            }
            written += aligned_bytes;
            remaining -= aligned_bytes;
        }

        // Trailing partial sector — uses scratch buffer.
        if remaining != 0 {
            let mut scratch = mem::take(&mut self.scratch);
            block_on(self.send_read(cur_off, &mut scratch[..bps]))?;
            let tail_in_sector = self.in_sector_off(cur_off);
            dst[written..written + remaining]
                .copy_from_slice(&scratch[tail_in_sector..tail_in_sector + remaining]);
            self.scratch = scratch;

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

        remaining = min(remaining, (cap_bytes - self.pos) as usize);
        let mut written = 0usize;
        let mut cur_off = self.pos;
        let bps = self.bps();

        // Leading partial sector (read-modify-write via scratch).
        let in_sector = self.in_sector_off(cur_off);
        if in_sector != 0 {
            let lba_base = cur_off - in_sector as u64;
            let write_len = min(bps - in_sector, remaining);

            let mut scratch = mem::take(&mut self.scratch);
            block_on(self.send_read(lba_base, &mut scratch[..bps]))?;
            scratch[in_sector..in_sector + write_len].copy_from_slice(&src[..write_len]);
            block_on(self.send_write(lba_base, &mut scratch[..bps]))?;
            self.scratch = scratch;

            cur_off += write_len as u64;
            written += write_len;
            remaining -= write_len;
        }

        // Aligned middle — borrow src directly, zero copy.
        let aligned_bytes = remaining - (remaining % bps);
        if aligned_bytes != 0 {
            let mut done = 0;
            while done < aligned_bytes {
                let device_cap = DEVICE_MAX_IO_BYTES - (DEVICE_MAX_IO_BYTES % bps);
                let chunk_cap = if device_cap == 0 { bps } else { device_cap };
                let chunk = min(aligned_bytes - done, chunk_cap);
                let src_slice = &src[written + done..written + done + chunk];
                block_on(self.send_write_immut(cur_off, src_slice))?;

                cur_off += chunk as u64;
                done += chunk;
            }
            written += aligned_bytes;
            remaining -= aligned_bytes;
        }

        // Trailing partial sector (read-modify-write via scratch).
        if remaining != 0 {
            let mut scratch = mem::take(&mut self.scratch);
            block_on(self.send_read(cur_off, &mut scratch[..bps]))?;
            scratch[..remaining].copy_from_slice(&src[written..written + remaining]);
            block_on(self.send_write(cur_off, &mut scratch[..bps]))?;
            self.scratch = scratch;

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
        Ok(())
    }
}
pub fn flush(vdx: &VolCtrlDevExt) {
    vdx.pending_flush_block.store(false, Ordering::SeqCst);
    vdx.should_flush.store(true, Ordering::SeqCst);
}

/// Kick a non-blocking cache flush for `owner`. The flush completes asynchronously.
pub fn flush_owner(vdx: &VolCtrlDevExt, owner: u64) {
    vdx.pending_flush_owner.store(owner, Ordering::SeqCst);
    vdx.pending_flush_block.store(false, Ordering::SeqCst);
    vdx.should_flush.store(true, Ordering::SeqCst);
}

/// Kick a blocking cache flush for `owner`. The caller will wait until the cache
/// confirms the data has been written (used for write-through writes and explicit flushes).
pub fn flush_owner_blocking(vdx: &VolCtrlDevExt, owner: u64) {
    vdx.pending_flush_owner.store(owner, Ordering::SeqCst);
    vdx.pending_flush_block.store(true, Ordering::SeqCst);
    vdx.should_flush.store(true, Ordering::SeqCst);
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
