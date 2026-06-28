use core::cmp::min;
use core::hint::{cold_path, likely, unlikely};

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{IoBase, IoKind, Read, ReadIoBuffer, Seek, SeekFrom, Write, WriteIoBuffer};
use kernel_api::{
    kernel_types::{
        async_ffi::{FfiFuture, FutureExt},
        dma::{
            FromDevice, IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc,
            IoBufferBackingScratch, ToDevice,
        },
        io::IoTarget,
    },
    pnp::io,
    println,
    request::{Read as ReadRequest, Write as WriteRequest},
    status::DriverStatus,
};

use crate::volume::{METADATA_OWNER_ID, VolCtrlDevExt};

pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    pub(crate) should_flush: Arc<AtomicBool>,
    pub(crate) current_owner: Arc<AtomicU64>,
    io_scratch: Option<IoBufferBackingScratch>,
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
            io_scratch: Some(IoBufferBackingScratch::new()),
        }
    }

    #[inline]
    fn capacity_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.sector_size as u64)
    }

    #[inline]
    fn take_io_scratch(&mut self) -> IoBufferBackingScratch {
        self.io_scratch.take().unwrap_or_default()
    }

    #[inline]
    fn restore_io_scratch(&mut self, scratch: IoBufferBackingScratch) {
        self.io_scratch = Some(scratch);
    }

    async fn send_read(
        &mut self,
        offset: u64,
        dst: &mut [u8],
        _kind: IoKind,
    ) -> Result<(), DriverStatus> {
        let volume = self.volume.clone();
        let len = dst.len();
        let scratch = self.take_io_scratch();

        let backing = match IoBufferBacking::from_scratch(
            IoBufferBackingDesc::SliceMut(dst),
            IoBufferBackingConfig::worst_case_for_len(len),
            scratch,
        ) {
            Ok(backing) => backing,
            Err(_) => {
                cold_path();
                self.restore_io_scratch(IoBufferBackingScratch::new());
                return Err(DriverStatus::InsufficientResources);
            }
        };

        let buffer = match backing.create_from_device(0, len) {
            Ok(buffer) => buffer,
            Err(_) => {
                cold_path();
                self.restore_io_scratch(IoBufferBackingScratch::new());
                return Err(DriverStatus::InvalidParameter);
            }
        };

        let mut req = ReadRequest::new(offset, len, false, Some(buffer));

        let status = io::send_down_stack(volume, &mut req).await;

        drop(req);

        self.restore_io_scratch(backing.into_scratch());

        if likely(status == DriverStatus::Success) {
            Ok(())
        } else {
            cold_path();
            println!("Read Error: {:#?}", status);
            Err(status)
        }
    }

    async fn send_read_iobuffer<'buffer>(
        &mut self,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, FromDevice>,
    ) -> Result<usize, DriverStatus> {
        let len = buffer.len();
        let mut req = ReadRequest::new(offset, len, false, Some(buffer));
        let status = io::send_down_stack(self.volume.clone(), &mut req).await;
        let completed = req.len;
        if status == DriverStatus::Success {
            Ok(completed)
        } else {
            Err(status)
        }
    }

    async fn send_write_immut(
        &mut self,
        offset: u64,
        src: &[u8],
        _kind: IoKind,
    ) -> Result<(), DriverStatus> {
        let no_buffer = false;

        let volume = self.volume.clone();
        let len = src.len();

        let scratch = self.take_io_scratch();

        let backing = match IoBufferBacking::from_scratch(
            IoBufferBackingDesc::Slice(src),
            IoBufferBackingConfig::worst_case_for_len(len),
            scratch,
        ) {
            Ok(backing) => backing,
            Err(_) => {
                cold_path();
                self.restore_io_scratch(IoBufferBackingScratch::new());
                return Err(DriverStatus::InsufficientResources);
            }
        };

        let buffer = match backing.create_to_device(0, len) {
            Ok(buffer) => buffer,
            Err(_) => {
                cold_path();
                self.restore_io_scratch(IoBufferBackingScratch::new());
                return Err(DriverStatus::InvalidParameter);
            }
        };

        let mut req = WriteRequest::new(
            offset,
            len,
            no_buffer,
            self.current_owner.load(Ordering::Acquire),
            Some(buffer),
        );

        let status = io::send_down_stack(volume, &mut req).await;

        drop(req);

        self.restore_io_scratch(backing.into_scratch());

        if likely(status == DriverStatus::Success) {
            Ok(())
        } else {
            cold_path();
            println!("Write Error: {:#?}", status);
            Err(status)
        }
    }

    async fn send_write_iobuffer<'buffer>(
        &mut self,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
    ) -> Result<usize, DriverStatus> {
        let len = buffer.len();
        let mut req = WriteRequest::new(
            offset,
            len,
            false,
            self.current_owner.load(Ordering::Acquire),
            Some(buffer),
        );
        let status = io::send_down_stack(self.volume.clone(), &mut req).await;
        let completed = req.len;
        if status == DriverStatus::Success {
            Ok(completed)
        } else {
            Err(status)
        }
    }

    async fn read_bytes(&mut self, dst: &mut [u8], kind: IoKind) -> Result<usize, DriverStatus> {
        if unlikely(dst.is_empty()) {
            cold_path();
            return Ok(0);
        }

        let cap_bytes = self.capacity_bytes();
        if unlikely(self.pos >= cap_bytes) {
            cold_path();
            return Ok(0);
        }

        let len = min(dst.len(), (cap_bytes - self.pos) as usize);
        self.send_read(self.pos, &mut dst[..len], kind).await?;
        self.pos += len as u64;

        Ok(len)
    }

    async fn write_bytes(&mut self, src: &[u8], kind: IoKind) -> Result<usize, DriverStatus> {
        if unlikely(src.is_empty()) {
            cold_path();
            return Ok(0);
        }

        let cap_bytes = self.capacity_bytes();
        if unlikely(self.pos >= cap_bytes) {
            cold_path();
            println!(
                "attempt to sec to pos {}, with capacity {}",
                cap_bytes,
                self.capacity_bytes()
            );
            return Ok(0);
        }

        let len = min(src.len(), cap_bytes.saturating_sub(self.pos) as usize);
        self.send_write_immut(self.pos, &src[..len], kind).await?;
        self.pos += len as u64;

        Ok(len)
    }
}

impl Read for BlockDev {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        kind: IoKind,
    ) -> FfiFuture<Result<usize, Self::Error>> {
        async move { self.read_bytes(buf, kind).await.map_err(|_| ()) }.into_ffi()
    }
}

impl Write for BlockDev {
    fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
        kind: IoKind,
    ) -> FfiFuture<Result<usize, Self::Error>> {
        async move { self.write_bytes(buf, kind).await.map_err(|_| ()) }.into_ffi()
    }

    fn flush(&mut self) -> FfiFuture<Result<(), Self::Error>> {
        async move { Ok(()) }.into_ffi()
    }
}

impl ReadIoBuffer for BlockDev {
    fn read_iobuffer<'a, 'buffer>(
        &'a mut self,
        buffer: IoBuffer<'buffer, 'buffer, FromDevice>,
        kind: IoKind,
    ) -> FfiFuture<Result<usize, Self::Error>> {
        async move {
            if buffer.is_empty() {
                return Ok(0);
            }
            let cap_bytes = self.capacity_bytes();
            if self.pos >= cap_bytes {
                return Ok(0);
            }
            let len = min(buffer.len(), (cap_bytes - self.pos) as usize);
            let buffer = if len == buffer.len() {
                buffer
            } else {
                buffer.split_at(len).map_err(|_| ())?.0
            };
            let read = self
                .send_read_iobuffer(self.pos, buffer)
                .await
                .map_err(|_| ())?;
            self.pos += read as u64;
            let _ = kind;
            Ok(read)
        }
        .into_ffi()
    }
}

impl WriteIoBuffer for BlockDev {
    fn write_iobuffer<'a, 'buffer>(
        &'a mut self,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        kind: IoKind,
    ) -> FfiFuture<Result<usize, Self::Error>> {
        async move {
            if buffer.is_empty() {
                return Ok(0);
            }
            let cap_bytes = self.capacity_bytes();
            if self.pos >= cap_bytes {
                return Ok(0);
            }
            let len = min(buffer.len(), (cap_bytes - self.pos) as usize);
            let buffer = if len == buffer.len() {
                buffer
            } else {
                buffer.split_at(len).map_err(|_| ())?.0
            };
            let written = self
                .send_write_iobuffer(self.pos, buffer)
                .await
                .map_err(|_| ())?;
            self.pos += written as u64;
            let _ = kind;
            Ok(written)
        }
        .into_ffi()
    }
}

pub fn flush(vdx: &VolCtrlDevExt) {
    vdx.pending_flush_owner
        .store(METADATA_OWNER_ID, Ordering::SeqCst);
    vdx.pending_flush_block.store(false, Ordering::SeqCst);
    vdx.should_flush.store(true, Ordering::SeqCst);
}

pub fn flush_owner(vdx: &VolCtrlDevExt, owner: u64) {
    vdx.pending_flush_owner.store(owner, Ordering::SeqCst);
    vdx.pending_flush_block.store(false, Ordering::SeqCst);
    vdx.should_flush.store(true, Ordering::SeqCst);
}

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
                if unlikely(base < 0) {
                    cold_path();
                    return Err(());
                }
                base as u64
            }
            SeekFrom::Current(off) => {
                let base = self.pos as i128 + off as i128;
                if unlikely(base < 0) {
                    cold_path();
                    return Err(());
                }
                base as u64
            }
        };

        if unlikely(new > cap) {
            cold_path();
            return Err(());
        }

        self.pos = new;
        Ok(self.pos)
    }
}
