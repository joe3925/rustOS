use alloc::{vec, vec::Vec};
use core::cmp::min;

use core::sync::atomic::Ordering;
use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    kernel_types::{io::IoTarget, request::RequestData},
    pnp::pnp_send_request,
    println,
    request::{RequestHandle, RequestType, SharedRequest, TraversalPolicy},
    runtime::block_on,
    status::DriverStatus,
};

use crate::volume::VolCtrlDevExt;

const MAX_CHUNK_BYTES: usize = 256 * 1024;

/// Pre-allocated request storage for allocation-free I/O operations.
/// The RequestData owns the buffer. We only replace it with a larger one
/// if a request needs more space than currently allocated.
struct PreallocatedRequest {
    /// The shared request handle, pre-promoted to avoid allocation on each I/O
    shared: SharedRequest,
    /// Current capacity of the buffer owned by RequestData
    current_capacity: usize,
}

impl PreallocatedRequest {
    fn new() -> Self {
        // Create a minimal request that we'll reuse
        let handle = RequestHandle::new(
            RequestType::Read { offset: 0, len: 0 },
            RequestData::empty(),
        );
        Self {
            shared: handle.into_shared(),
            current_capacity: 0,
        }
    }
}

pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    /// Small buffer only for unaligned partial-sector reads/writes
    sector_buf: Vec<u8>,
    /// Pre-allocated request for read operations
    read_request: PreallocatedRequest,
    /// Pre-allocated request for write operations
    write_request: PreallocatedRequest,
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
            read_request: PreallocatedRequest::new(),
            write_request: PreallocatedRequest::new(),
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

    /// Read into a buffer using pre-allocated request (allocation-free after warmup)
    async fn pnp_read_into(
        volume: &IoTarget,
        req: &mut PreallocatedRequest,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), DriverStatus> {
        let len = buf.len();

        // Reset the request for reuse
        {
            let mut guard = req.shared.write();
            guard.kind = RequestType::Read { offset, len };
            guard.completed = false;
            guard.status = DriverStatus::ContinueStep;
            guard.traversal_policy = TraversalPolicy::ForwardLower;
            guard.completion_routine = None;
            guard.completion_context = 0;
            guard.waker = None;

            // Only allocate a new buffer if we need more space than current capacity
            if len > req.current_capacity {
                guard.data = RequestData::from_boxed_bytes(vec![0u8; len].into_boxed_slice());
                req.current_capacity = len;
            } else {
                // Reusing existing buffer - update the size field to match current request
                guard.data.set_len(len);
            }
        }

        let mut handle = RequestHandle::Shared(req.shared.clone());
        let st = pnp_send_request(volume.clone(), &mut handle).await;

        if st == DriverStatus::Success {
            let guard = req.shared.read();
            buf.copy_from_slice(guard.data.as_slice());
            return Ok(());
        }
        println!("Error: {:#?}", st);
        Err(st)
    }

    /// Write from a buffer using pre-allocated request (allocation-free after warmup)
    async fn pnp_write_from(
        volume: &IoTarget,
        req: &mut PreallocatedRequest,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), DriverStatus> {
        let len = buf.len();

        // Reset the request for reuse
        {
            let mut guard = req.shared.write();
            guard.kind = RequestType::Write {
                offset,
                len,
                flush_write_through: false,
            };
            guard.completed = false;
            guard.status = DriverStatus::ContinueStep;
            guard.traversal_policy = TraversalPolicy::ForwardLower;
            guard.completion_routine = None;
            guard.completion_context = 0;
            guard.waker = None;

            // Only allocate a new buffer if we need more space than current capacity
            if len > req.current_capacity {
                guard.data = RequestData::from_boxed_bytes(vec![0u8; len].into_boxed_slice());
                req.current_capacity = len;
            } else {
                // Reusing existing buffer - update the size field to match current request
                guard.data.set_len(len);
            }

            // Copy source data into the buffer
            guard.data.as_mut_slice().copy_from_slice(buf);
        }

        let mut handle = RequestHandle::Shared(req.shared.clone());
        let st = pnp_send_request(volume.clone(), &mut handle).await;

        if st == DriverStatus::Success {
            Ok(())
        } else {
            println!("Error: {:#?}", st);
            Err(st)
        }
    }

    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize, BlkError> {
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

                // Minimal async closure - only capture what's needed for the I/O
                let volume = &self.volume;
                let req = &mut self.read_request;
                let sector_buf = &mut self.sector_buf[..bps];
                block_on(async { Self::pnp_read_into(volume, req, sector_off, sector_buf).await })
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

            let volume = &self.volume;
            let req = &mut self.read_request;
            let dst_slice = &mut dst[out_off..out_off + chunk_bytes];
            block_on(async { Self::pnp_read_into(volume, req, byte_off, dst_slice).await })
                .map_err(BlkError::from)?;

            self.pos += chunk_bytes as u64;
            out_off += chunk_bytes;
            remaining -= chunk_bytes;
        }

        Ok(to_read)
    }

    fn write_bytes(&mut self, src: &[u8]) -> Result<usize, BlkError> {
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

                // Read existing sector - minimal async closure
                {
                    let volume = &self.volume;
                    let req = &mut self.read_request;
                    let sector_buf = &mut self.sector_buf[..bps];
                    block_on(async {
                        Self::pnp_read_into(volume, req, sector_off, sector_buf).await
                    })
                    .map_err(BlkError::from)?;
                }

                // Modify
                let take = min(remaining, room);
                self.sector_buf[in_off..in_off + take]
                    .copy_from_slice(&src[in_off_src..in_off_src + take]);

                // Write back - minimal async closure
                {
                    let volume = &self.volume;
                    let req = &mut self.write_request;
                    let sector_buf = &self.sector_buf[..bps];
                    block_on(async {
                        Self::pnp_write_from(volume, req, sector_off, sector_buf).await
                    })
                    .map_err(BlkError::from)?;
                }

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

            // Minimal async closure - only capture what's needed for the I/O
            let volume = &self.volume;
            let req = &mut self.write_request;
            let src_slice = &src[in_off_src..in_off_src + chunk_bytes];
            block_on(async { Self::pnp_write_from(volume, req, byte_off, src_slice).await })
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
        self.read_bytes(buf).map_err(|_| ())
    }
}

impl Write for BlockDev {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.write_bytes(buf).map_err(|_| ())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        let ext = self.volume.try_devext::<VolCtrlDevExt>();
        if let Some(ext) = ext.ok() {
            ext.should_flush.store(true, Ordering::SeqCst);
        } else {
            return Err(());
        }

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
