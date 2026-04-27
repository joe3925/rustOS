use core::cmp::min;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    kernel_types::{io::IoTarget, request::RequestData},
    pnp::pnp_send_request,
    println,
    request::{BorrowedHandle, RequestHandle, RequestType, TraversalPolicy},
    runtime::block_on,
    status::DriverStatus,
};

use crate::volume::VolCtrlDevExt;

pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    /// Reusable request — data slot is overwritten each call via BorrowedHandle.
    req: RequestHandle<'static>,
    /// Shared flush flag with VolCtrlDevExt
    pub(crate) should_flush: Arc<AtomicBool>,
    /// Current file owner tag — set before FS writes, read by prep_write_req.
    pub(crate) current_owner: Arc<AtomicU64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
        let req = RequestHandle::new(
            RequestType::Read { offset: 0, len: 0 },
            RequestData::empty(),
        );
        Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
            req,
            should_flush,
            current_owner,
        }
    }

    #[inline]
    fn capacity_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.sector_size as u64)
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

        let status = {
            let mut borrow = BorrowedHandle::writable(&mut self.req, dst);
            pnp_send_request(volume, borrow.handle()).await
        };

        if status == DriverStatus::Success {
            Ok(())
        } else {
            println!("Read Error: {:#?}", status);
            Err(status)
        }
    }

    /// Send a write from an immutable source.
    async fn send_write_immut(&mut self, offset: u64, src: &[u8]) -> Result<(), DriverStatus> {
        let len = src.len();
        let volume = self.volume.clone();
        self.prep_req_write(offset, len, false);

        let status = {
            let mut borrow = BorrowedHandle::read_only(&mut self.req, src);
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
        if dst.is_empty() {
            return Ok(0);
        }
        let cap_bytes = self.capacity_bytes();
        if self.pos >= cap_bytes {
            return Ok(0);
        }
        let len = min(dst.len(), (cap_bytes - self.pos) as usize);
        block_on(self.send_read(self.pos, &mut dst[..len]))?;
        self.pos += len as u64;
        Ok(len)
    }

    fn write_bytes(&mut self, src: &[u8]) -> Result<usize, DriverStatus> {
        if src.is_empty() {
            return Ok(0);
        }
        let cap_bytes = self.capacity_bytes();
        if self.pos >= cap_bytes {
            return Ok(0);
        }
        let len = min(src.len(), (cap_bytes - self.pos) as usize);
        block_on(self.send_write_immut(self.pos, &src[..len]))?;
        self.pos += len as u64;
        Ok(len)
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
