use core::cmp::min;
use core::hint::{cold_path, unlikely};

use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{IoBase, IoKind, Read, ReadIoBuffer, Seek, SeekFrom, Write, WriteIoBuffer};
use kernel_api::error::{DriverErrorKind, KernelError, ResultErrorContext, error};
use kernel_api::{
    kernel_types::{
        async_ffi::{AbiFuture, FutureExt},
        dma::{
            FromDevice, IoBuffer, IoBufferAccess, IoBufferBacking, IoBufferBackingConfig,
            IoBufferBackingDesc, ToDevice,
        },
        io::IoTarget,
    },
    pnp::io,
    println,
    request::{Read as ReadRequest, Write as WriteRequest},
};

use crate::volume::{METADATA_OWNER_ID, VolCtrlDevExt};

#[derive(Clone, Debug)]
pub struct FatIoError(pub KernelError);

impl fatfs::IoError for FatIoError {
    fn is_interrupted(&self) -> bool {
        false
    }

    fn new_unexpected_eof_error() -> Self {
        Self(
            error(DriverErrorKind::DeviceError)
                .with_context("unexpected end of the FAT32 block device"),
        )
    }

    fn new_write_zero_error() -> Self {
        Self(
            error(DriverErrorKind::DeviceError)
                .with_context("the FAT32 block device completed a zero-length write"),
        )
    }
}

pub struct BlockDev {
    volume: IoTarget,
    sector_size: u16,
    total_sectors: u64,
    pos: u64,
    scratch_backing: Option<IoBufferBacking<'static>>,
    scratch_memory: usize,
    pub(crate) should_flush: Arc<AtomicBool>,
    pub(crate) current_owner: Arc<AtomicU64>,
}

impl IoBase for BlockDev {
    type Error = FatIoError;
}

fn clip_iobuffer<'buffer, Access: IoBufferAccess>(
    buffer: IoBuffer<'buffer, 'buffer, Access>,
    len: usize,
    context: &'static str,
) -> Result<IoBuffer<'buffer, 'buffer, Access>, FatIoError> {
    if len == buffer.len() {
        Ok(buffer)
    } else {
        buffer.split_at(len).map(|parts| parts.0).map_err(|_| {
            FatIoError(error(DriverErrorKind::InvalidParameter).with_context(context))
        })
    }
}

impl BlockDev {
    pub fn new(
        volume: IoTarget,
        sector_size: u16,
        total_sectors: u64,
        should_flush: Arc<AtomicBool>,
        current_owner: Arc<AtomicU64>,
    ) -> Result<Self, KernelError> {
        let scratch_memory = Box::into_raw(Box::new([0u8; 512]));
        let scratch_slice =
            unsafe { core::slice::from_raw_parts_mut(scratch_memory.cast::<u8>(), 512) };
        let scratch_backing = match IoBufferBacking::new(
            IoBufferBackingDesc::SliceMut(scratch_slice),
            IoBufferBackingConfig {
                lease_capacity: 1,
                ..IoBufferBackingConfig::default()
            },
        ) {
            Ok(backing) => backing,
            Err(_) => {
                unsafe {
                    drop(Box::from_raw(scratch_memory));
                }
                return Err(error(DriverErrorKind::InsufficientResources)
                    .with_context("creating the FAT32 scratch backing"));
            }
        };
        Ok(Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
            scratch_backing: Some(scratch_backing),
            scratch_memory: scratch_memory as usize,
            should_flush,
            current_owner,
        })
    }

    #[inline]
    fn capacity_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.sector_size as u64)
    }

    async fn send_read(
        &mut self,
        offset: u64,
        dst: &mut [u8],
        _kind: IoKind,
    ) -> Result<(), KernelError> {
        let backing = self
            .scratch_backing
            .as_ref()
            .expect("FAT32 scratch backing is present");
        for (index, chunk) in dst.chunks_mut(backing.len()).enumerate() {
            let len = chunk.len();
            let offset = offset + (index * backing.len()) as u64;
            let buffer = backing.create_from_device(0, backing.len()).map_err(|_| {
                error(DriverErrorKind::InsufficientResources)
                    .with_context("leasing the FAT32 read scratch buffer")
            })?;
            let mut req = ReadRequest::new(offset, len, false, Some(buffer));
            io::send_down_stack(self.volume.clone(), &mut req)
                .await
                .with_context(|| {
                    alloc::format!("reading FAT32 volume at offset {offset} for {len} bytes")
                })?;
            let completed = req.len;
            drop(req);
            if completed != len {
                return Err(error(DriverErrorKind::DeviceError)
                    .with_context("the FAT32 scratch read completed with an incorrect length"));
            }
            let buffer = backing.create_to_device(0, backing.len()).map_err(|_| {
                error(DriverErrorKind::InsufficientResources)
                    .with_context("leasing the completed FAT32 read scratch buffer")
            })?;
            buffer.copy_to_slice(0, chunk).map_err(|_| {
                error(DriverErrorKind::InvalidParameter)
                    .with_context("copying the FAT32 read scratch buffer")
            })?;
        }
        Ok(())
    }

    async fn send_read_iobuffer<'buffer>(
        &mut self,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, FromDevice>,
    ) -> Result<usize, KernelError> {
        let len = buffer.len();
        let mut req = ReadRequest::new(offset, len, false, Some(buffer));
        let result = io::send_down_stack(self.volume.clone(), &mut req).await;
        let completed = req.len;
        result.map(|_| completed).with_context(|| {
            alloc::format!("reading FAT32 I/O buffer at offset {offset} for {len} bytes")
        })
    }

    async fn send_write_immut(
        &mut self,
        offset: u64,
        src: &[u8],
        _kind: IoKind,
    ) -> Result<(), KernelError> {
        let backing = self
            .scratch_backing
            .as_ref()
            .expect("FAT32 scratch backing is present");
        for (index, chunk) in src.chunks(backing.len()).enumerate() {
            let len = chunk.len();
            let offset = offset + (index * backing.len()) as u64;
            let mut edit = backing
                .create_bidirectional(0, backing.len())
                .map_err(|_| {
                    error(DriverErrorKind::InsufficientResources)
                        .with_context("leasing the FAT32 write scratch buffer")
                })?;
            edit.copy_from_slice(0, chunk).map_err(|_| {
                error(DriverErrorKind::InvalidParameter)
                    .with_context("copying the FAT32 write scratch buffer")
            })?;
            drop(edit);
            let buffer = backing.create_to_device(0, backing.len()).map_err(|_| {
                error(DriverErrorKind::InsufficientResources)
                    .with_context("leasing the prepared FAT32 write scratch buffer")
            })?;
            let mut req = WriteRequest::new(
                offset,
                len,
                false,
                self.current_owner.load(Ordering::Acquire),
                Some(buffer),
            );
            io::send_down_stack(self.volume.clone(), &mut req)
                .await
                .with_context(|| {
                    alloc::format!("writing FAT32 volume at offset {offset} for {len} bytes")
                })?;
            if req.len != len {
                return Err(error(DriverErrorKind::DeviceError)
                    .with_context("the FAT32 scratch write completed with an incorrect length"));
            }
        }
        Ok(())
    }

    async fn send_write_iobuffer<'buffer>(
        &mut self,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
    ) -> Result<usize, KernelError> {
        let len = buffer.len();
        let mut req = WriteRequest::new(
            offset,
            len,
            false,
            self.current_owner.load(Ordering::Acquire),
            Some(buffer),
        );
        let result = io::send_down_stack(self.volume.clone(), &mut req).await;
        let completed = req.len;
        result.map(|_| completed).with_context(|| {
            alloc::format!("writing FAT32 I/O buffer at offset {offset} for {len} bytes")
        })
    }

    async fn read_bytes(&mut self, dst: &mut [u8], kind: IoKind) -> Result<usize, KernelError> {
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

    async fn write_bytes(&mut self, src: &[u8], kind: IoKind) -> Result<usize, KernelError> {
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

impl Drop for BlockDev {
    fn drop(&mut self) {
        drop(self.scratch_backing.take());
        unsafe {
            drop(Box::from_raw(self.scratch_memory as *mut [u8; 512]));
        }
    }
}

impl Read for BlockDev {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        kind: IoKind,
    ) -> AbiFuture<Result<usize, Self::Error>> {
        async move { self.read_bytes(buf, kind).await.map_err(FatIoError) }.into_abi()
    }
}

impl Write for BlockDev {
    fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
        kind: IoKind,
    ) -> AbiFuture<Result<usize, Self::Error>> {
        async move { self.write_bytes(buf, kind).await.map_err(FatIoError) }.into_abi()
    }

    fn flush(&mut self) -> AbiFuture<Result<(), Self::Error>> {
        async move { Ok(()) }.into_abi()
    }
}

impl ReadIoBuffer for BlockDev {
    fn read_iobuffer<'a, 'buffer>(
        &'a mut self,
        buffer: IoBuffer<'buffer, 'buffer, FromDevice>,
        kind: IoKind,
    ) -> AbiFuture<Result<usize, Self::Error>> {
        async move {
            if buffer.is_empty() {
                return Ok(0);
            }
            let cap_bytes = self.capacity_bytes();
            if self.pos >= cap_bytes {
                return Ok(0);
            }
            let len = min(buffer.len(), (cap_bytes - self.pos) as usize);
            let buffer = clip_iobuffer(buffer, len, "splitting a FAT32 read I/O buffer")?;
            let read = self
                .send_read_iobuffer(self.pos, buffer)
                .await
                .map_err(FatIoError)?;
            self.pos += read as u64;
            let _ = kind;
            Ok(read)
        }
        .into_abi()
    }
}

impl WriteIoBuffer for BlockDev {
    fn write_iobuffer<'a, 'buffer>(
        &'a mut self,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        kind: IoKind,
    ) -> AbiFuture<Result<usize, Self::Error>> {
        async move {
            if buffer.is_empty() {
                return Ok(0);
            }
            let cap_bytes = self.capacity_bytes();
            if self.pos >= cap_bytes {
                return Ok(0);
            }
            let len = min(buffer.len(), (cap_bytes - self.pos) as usize);
            let buffer = clip_iobuffer(buffer, len, "splitting a FAT32 write I/O buffer")?;
            let written = self
                .send_write_iobuffer(self.pos, buffer)
                .await
                .map_err(FatIoError)?;
            self.pos += written as u64;
            let _ = kind;
            Ok(written)
        }
        .into_abi()
    }
}

pub fn flush(vdx: &VolCtrlDevExt) {
    request_flush(vdx, METADATA_OWNER_ID, false);
}

pub fn flush_owner(vdx: &VolCtrlDevExt, owner: u64) {
    request_flush(vdx, owner, false);
}

pub fn flush_owner_blocking(vdx: &VolCtrlDevExt, owner: u64) {
    request_flush(vdx, owner, true);
}

fn request_flush(vdx: &VolCtrlDevExt, owner: u64, blocking: bool) {
    vdx.pending_flush_owner.store(owner, Ordering::SeqCst);
    vdx.pending_flush_block.store(blocking, Ordering::SeqCst);
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
                    return Err(FatIoError(
                        error(DriverErrorKind::InvalidParameter)
                            .with_context("seeking before the start of a FAT32 volume"),
                    ));
                }
                base as u64
            }
            SeekFrom::Current(off) => {
                let base = self.pos as i128 + off as i128;
                if unlikely(base < 0) {
                    cold_path();
                    return Err(FatIoError(
                        error(DriverErrorKind::InvalidParameter)
                            .with_context("seeking before the current FAT32 position"),
                    ));
                }
                base as u64
            }
        };

        if unlikely(new > cap) {
            cold_path();
            return Err(FatIoError(
                error(DriverErrorKind::InvalidParameter).with_context(alloc::format!(
                    "seeking to FAT32 offset {new} beyond capacity {cap}"
                )),
            ));
        }

        self.pos = new;
        Ok(self.pos)
    }
}
