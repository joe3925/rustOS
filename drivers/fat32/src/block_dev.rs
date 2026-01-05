use alloc::{sync::Arc, vec, vec::Vec};
use core::{cmp::min, mem};
use spin::RwLock;

use fatfs::{IoBase, Read, Seek, SeekFrom, Write};
use kernel_api::{
    RequestExt,
    kernel_types::{io::IoTarget, request::RequestData},
    pnp::pnp_send_request,
    request::{Request, RequestType, TraversalPolicy},
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
    scratch: Vec<u8>,
    read_req: Arc<RwLock<Request>>,
    write_req: Arc<RwLock<Request>>,
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
        let bps = sector_size as usize;

        let mut r = Request::new(
            RequestType::Read {
                offset: 0,
                len: bps,
            },
            RequestData::from_boxed_bytes(vec![0u8; bps].into_boxed_slice()),
        );
        r.traversal_policy = TraversalPolicy::ForwardLower;

        let mut w = Request::new(
            RequestType::Write {
                offset: 0,
                len: bps,
            },
            RequestData::from_boxed_bytes(vec![0u8; bps].into_boxed_slice()),
        );
        w.traversal_policy = TraversalPolicy::ForwardLower;

        Self {
            volume,
            sector_size,
            total_sectors,
            pos: 0,
            scratch: vec![0u8; bps],
            read_req: Arc::new(RwLock::new(r)),
            write_req: Arc::new(RwLock::new(w)),
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

    #[inline]
    fn ensure_scratch(&mut self, need: usize) {
        if self.scratch.len() < need {
            self.scratch.resize(need, 0);
        }
    }

    async fn pnp_read_owned(
        &mut self,
        offset: u64,
        mut buf: Vec<u8>,
        len: usize,
    ) -> Result<Vec<u8>, DriverStatus> {
        if buf.len() < len {
            buf.resize(len, 0);
        }
        buf.truncate(len);

        {
            let mut g = self.read_req.write();
            g.kind = RequestType::Read { offset, len };
            g.data = RequestData::from_boxed_bytes(buf.into_boxed_slice());
        }

        pnp_send_request(self.volume.clone(), self.read_req.clone()).await;

        let mut g = self.read_req.write();
        let st = g.status;
        let boxed = g.take_data_bytes();
        let out = boxed.into_vec();

        if st == DriverStatus::Success {
            Ok(out)
        } else {
            Err(st)
        }
    }

    async fn pnp_write_owned(
        &mut self,
        offset: u64,
        buf: Vec<u8>,
    ) -> Result<Vec<u8>, DriverStatus> {
        let len = buf.len();

        {
            let mut g = self.write_req.write();
            g.kind = RequestType::Write { offset, len };
            g.data = RequestData::from_boxed_bytes(buf.into_boxed_slice());
        }

        pnp_send_request(self.volume.clone(), self.write_req.clone()).await;

        let mut g = self.write_req.write();
        let st = g.status;
        let boxed = g.take_data_bytes();
        let out = boxed.into_vec();

        if st == DriverStatus::Success {
            Ok(out)
        } else {
            Err(st)
        }
    }

    async fn pnp_read_into_scratch(&mut self, offset: u64, len: usize) -> Result<(), DriverStatus> {
        self.ensure_scratch(len);
        let buf = mem::take(&mut self.scratch);
        self.scratch = self.pnp_read_owned(offset, buf, len).await?;
        Ok(())
    }

    async fn pnp_write_from_slice(&mut self, offset: u64, data: &[u8]) -> Result<(), DriverStatus> {
        let len = data.len();
        self.ensure_scratch(len);
        self.scratch[..len].copy_from_slice(data);

        let mut buf = mem::take(&mut self.scratch);
        buf.truncate(len);

        self.scratch = self.pnp_write_owned(offset, buf).await?;
        Ok(())
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

            if in_off != 0 || remaining < bps {
                let sector_off = lba * bps as u64;
                self.pnp_read_into_scratch(sector_off, bps)
                    .await
                    .map_err(BlkError::from)?;
                let take = min(remaining, room);
                dst[out_off..out_off + take].copy_from_slice(&self.scratch[in_off..in_off + take]);
                self.pos += take as u64;
                out_off += take;
                remaining -= take;
                continue;
            }

            let full_sectors = remaining / bps;
            let max_sectors = (MAX_CHUNK_BYTES / bps).max(1);
            let chunk_sectors = min(full_sectors, max_sectors);
            let chunk_bytes = chunk_sectors * bps;

            let byte_off = lba * bps as u64;
            self.pnp_read_into_scratch(byte_off, chunk_bytes)
                .await
                .map_err(BlkError::from)?;
            dst[out_off..out_off + chunk_bytes].copy_from_slice(&self.scratch[..chunk_bytes]);

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

            if in_off != 0 || remaining < bps {
                let sector_off = lba * bps as u64;

                self.pnp_read_into_scratch(sector_off, bps)
                    .await
                    .map_err(BlkError::from)?;

                let take = min(remaining, room);
                self.scratch[in_off..in_off + take]
                    .copy_from_slice(&src[in_off_src..in_off_src + take]);

                let mut buf = mem::take(&mut self.scratch);
                buf.truncate(bps);

                self.scratch = self
                    .pnp_write_owned(sector_off, buf)
                    .await
                    .map_err(BlkError::from)?;

                self.pos += take as u64;
                in_off_src += take;
                remaining -= take;
                continue;
            }

            let full_sectors = remaining / bps;
            let max_sectors = (MAX_CHUNK_BYTES / bps).max(1);
            let chunk_sectors = min(full_sectors, max_sectors);
            let chunk_bytes = chunk_sectors * bps;

            let byte_off = lba * bps as u64;

            self.pnp_write_from_slice(byte_off, &src[in_off_src..in_off_src + chunk_bytes])
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
