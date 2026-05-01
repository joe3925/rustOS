use core::cmp::min;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    kernel_types::{io::IoTarget, request::RequestData},
    pnp::pnp_send_request,
    println,
    request::{BorrowedHandle, RequestHandle, RequestType, TraversalPolicy},
    status::DriverStatus,
};

use crate::volume::{METADATA_OWNER_ID, VolCtrlDevExt};

pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    /// Shared flush flag with VolCtrlDevExt
    pub(crate) should_flush: Arc<AtomicBool>,
    /// Current owner tag — set once per FS op, read by prep_write_req.
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
        Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
            should_flush,
            current_owner,
        }
    }

    #[inline]
    fn capacity_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.sector_size as u64)
    }

    /// Send a read, borrowing `dst` directly so the lower driver writes into it.
    async fn send_read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), DriverStatus> {
        let volume = self.volume.clone();
        let mut req = RequestHandle::new(
            RequestType::Read {
                offset,
                len: dst.len(),
            },
            RequestData::empty(),
        );
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        let status = {
            let mut borrow = BorrowedHandle::writable(&mut req, dst);
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
        let volume = self.volume.clone();
        let mut req = RequestHandle::new(
            RequestType::Write {
                offset,
                len: src.len(),
                flush_write_through: false,
                owner: self.current_owner.load(Ordering::Acquire),
            },
            RequestData::empty(),
        );
        req.set_traversal_policy(TraversalPolicy::ForwardLower);

        let status = {
            let mut borrow = BorrowedHandle::read_only(&mut req, src);
            pnp_send_request(volume, borrow.handle()).await
        };

        if status == DriverStatus::Success {
            Ok(())
        } else {
            println!("Write Error: {:#?}", status);
            Err(status)
        }
    }

    async fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize, DriverStatus> {
        if dst.is_empty() {
            return Ok(0);
        }
        let cap_bytes = self.capacity_bytes();
        if self.pos >= cap_bytes {
            return Ok(0);
        }
        let len = min(dst.len(), (cap_bytes - self.pos) as usize);
        self.send_read(self.pos, &mut dst[..len]).await?;
        self.pos += len as u64;
        Ok(len)
    }

    async fn write_bytes(&mut self, src: &[u8]) -> Result<usize, DriverStatus> {
        if src.is_empty() {
            return Ok(0);
        }
        let cap_bytes = self.capacity_bytes();
        if self.pos >= cap_bytes {
            println!(
                "attempt to sec to pos {}, with capacity {}",
                cap_bytes,
                self.capacity_bytes()
            );
            return Ok(0);
        }
        let len = min(
            src.len(),
            (cap_bytes.checked_sub(self.pos).unwrap()) as usize,
        );
        self.send_write_immut(self.pos, &src[..len]).await?;
        self.pos += len as u64;
        if (len == 0) {
            println!("len is zero cap is {}", self.capacity_bytes())
        }
        Ok(len)
    }
}

use kernel_api::kernel_types::async_ffi::{FfiFuture, FutureExt};

impl Read for BlockDev {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> FfiFuture<Result<usize, Self::Error>> {
        async move { self.read_bytes(buf).await.map_err(|_| ()) }.into_ffi()
    }
}

impl Write for BlockDev {
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> FfiFuture<Result<usize, Self::Error>> {
        async move { self.write_bytes(buf).await.map_err(|_| ()) }.into_ffi()
    }

    fn flush(&mut self) -> FfiFuture<Result<(), Self::Error>> {
        async move { Ok(()) }.into_ffi()
    }
}
pub fn flush(vdx: &VolCtrlDevExt) {
    vdx.pending_flush_owner
        .store(METADATA_OWNER_ID, Ordering::SeqCst);
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
