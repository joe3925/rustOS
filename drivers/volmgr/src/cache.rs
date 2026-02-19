extern crate alloc;

use alloc::vec::Vec;
use alloc::{boxed::Box, vec};
use core::cmp::{max, min};
use heapless::index_map::FnvIndexMap;
use kernel_api::kernel_types::io::IoTarget;
use kernel_api::pnp::pnp_send_request;
use kernel_api::request::{RequestData, RequestHandle, RequestType};
use kernel_api::status::DriverStatus;
use spin::RwLock;

const MAX_CACHE_BYTES: usize = 20 * 1024 * 1024;
const MIN_BLOCK_SIZE: usize = 4096;

// heapless::IndexMap capacity must be a power of 2.
const MAX_ENTRIES: usize = 8192;

const MAX_SECTORS_PER_BLOCK: usize = 256;
const MASK_WORDS: usize = MAX_SECTORS_PER_BLOCK.div_ceil(64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    NotConfigured,
    BlockSizeTooSmall,
    BlockSizeMisaligned,
    CacheTooSmall,
    CapacityTooLarge,
    TooManySectorsPerBlock,
    CacheFull,
    NotFound,
    NotFullyCached,
    EntryExists,
    UnalignedRange,
    RangeOverflow,
    InternalInconsistent,
    IoFailed(DriverStatus),
}

#[derive(Clone, Copy)]
struct CacheEntry {
    block_idx: u64,
    valid: [u64; MASK_WORDS],
    dirty: [u64; MASK_WORDS],
    in_use: bool,
}

impl Default for CacheEntry {
    fn default() -> Self {
        CacheEntry {
            block_idx: 0,
            valid: [0u64; MASK_WORDS],
            dirty: [0u64; MASK_WORDS],
            in_use: false,
        }
    }
}

impl CacheEntry {
    fn reset(&mut self) {
        *self = CacheEntry::default();
    }
}

pub struct VolumeCache {
    max_bytes: usize,
    sector_size: usize,
    block_size: usize,
    sectors_per_block: usize,
    max_blocks: usize,

    backing: Vec<u8>,
    entries: Vec<CacheEntry>,
    free: Vec<u32>,

    map: Box<FnvIndexMap<u64, u32, MAX_ENTRIES>>,
}

impl VolumeCache {
    pub fn new(max_bytes: usize) -> Self {
        let clamped = min(max_bytes, MAX_CACHE_BYTES);
        VolumeCache {
            max_bytes: clamped,
            sector_size: 0,
            block_size: 0,
            sectors_per_block: 0,
            max_blocks: 0,
            backing: Vec::new(),
            entries: Vec::new(),
            free: Vec::new(),
            map: Box::new(FnvIndexMap::<u64, u32, MAX_ENTRIES>::new()),
        }
    }

    pub fn set_block_size(
        &mut self,
        block_size: usize,
        sector_size: usize,
    ) -> Result<(), CacheError> {
        if block_size < MIN_BLOCK_SIZE {
            return Err(CacheError::BlockSizeTooSmall);
        }
        if sector_size == 0 || !block_size.is_multiple_of(sector_size) {
            return Err(CacheError::BlockSizeMisaligned);
        }

        let sectors_per_block = block_size / sector_size;
        if sectors_per_block == 0 {
            return Err(CacheError::BlockSizeMisaligned);
        }
        if sectors_per_block > MAX_SECTORS_PER_BLOCK {
            return Err(CacheError::TooManySectorsPerBlock);
        }

        let max_blocks = self.max_bytes / block_size;
        if max_blocks == 0 {
            return Err(CacheError::CacheTooSmall);
        }
        if max_blocks > MAX_ENTRIES {
            return Err(CacheError::CapacityTooLarge);
        }
        if max_blocks > (u32::MAX as usize) {
            return Err(CacheError::CapacityTooLarge);
        }

        let backing_len = max_blocks
            .checked_mul(block_size)
            .ok_or(CacheError::RangeOverflow)?;

        self.backing = vec![0u8; backing_len];
        self.entries = vec![CacheEntry::default(); max_blocks];

        self.free = Vec::with_capacity(max_blocks);
        self.free.clear();
        for i in 0..max_blocks {
            self.free.push(i as u32);
        }

        self.map.clear();

        self.sector_size = sector_size;
        self.block_size = block_size;
        self.sectors_per_block = sectors_per_block;
        self.max_blocks = max_blocks;

        Ok(())
    }

    pub fn invalidate_all(&mut self) -> Result<(), CacheError> {
        if self.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }

        self.map.clear();

        for e in self.entries.iter_mut() {
            e.reset();
        }

        self.free.clear();
        for i in 0..self.max_blocks {
            self.free.push(i as u32);
        }

        Ok(())
    }

    pub fn invalidate_range(&mut self, offset: u64, len: u64) -> Result<(), CacheError> {
        if self.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }
        if len == 0 {
            return Ok(());
        }

        let end = offset.checked_add(len).ok_or(CacheError::RangeOverflow)?;
        let bs = self.block_size as u64;

        let first = offset / bs;
        let last = (end - 1) / bs;

        let mut b = first;
        while b <= last {
            if let Some(entry_idx) = self.map.remove(&b) {
                let ei = entry_idx as usize;
                if ei >= self.entries.len() {
                    return Err(CacheError::InternalInconsistent);
                }
                self.entries[ei].reset();
                self.free.push(entry_idx);
            }
            b = b.wrapping_add(1);
            if b == 0 {
                break;
            }
        }

        Ok(())
    }

    pub fn mark_clean_range(&mut self, offset: u64, len: u64) -> Result<(), CacheError> {
        if self.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }
        if len == 0 {
            return Ok(());
        }
        if !offset.is_multiple_of(self.sector_size as u64)
            || !(len as usize).is_multiple_of(self.sector_size)
        {
            return Err(CacheError::UnalignedRange);
        }

        let end = offset.checked_add(len).ok_or(CacheError::RangeOverflow)?;
        let bs = self.block_size as u64;

        let first = offset / bs;
        let last = (end - 1) / bs;

        let mut b = first;
        while b <= last {
            let entry_idx = match self.map.get(&b) {
                Some(x) => *x,
                None => {
                    b = b.wrapping_add(1);
                    if b == 0 {
                        break;
                    }
                    continue;
                }
            };

            let ei = entry_idx as usize;
            if ei >= self.entries.len() {
                return Err(CacheError::InternalInconsistent);
            }

            let block_base = b.checked_mul(bs).ok_or(CacheError::RangeOverflow)?;
            let seg_lo = max(offset, block_base);
            let seg_hi = min(end, block_base + bs);

            let within_lo = (seg_lo - block_base) as usize;
            let within_len = (seg_hi - seg_lo) as usize;

            let start_sector = within_lo / self.sector_size;
            let end_sector = (within_lo + within_len) / self.sector_size;

            let ent = &mut self.entries[ei];
            if !ent.in_use || ent.block_idx != b {
                return Err(CacheError::InternalInconsistent);
            }

            mask_clear_range(&mut ent.dirty, start_sector, end_sector);

            b = b.wrapping_add(1);
            if b == 0 {
                break;
            }
        }

        Ok(())
    }

    pub fn lookup(&self, offset: u64, dst: &mut [u8]) -> Result<(), CacheError> {
        if self.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }
        if dst.is_empty() {
            return Ok(());
        }

        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(CacheError::RangeOverflow)?;

        let bs_u64 = self.block_size as u64;
        let first = offset / bs_u64;
        let last = (end - 1) / bs_u64;

        let mut b = first;
        while b <= last {
            let entry_idx = *self.map.get(&b).ok_or(CacheError::NotFound)?;
            let ei = entry_idx as usize;
            if ei >= self.entries.len() {
                return Err(CacheError::InternalInconsistent);
            }

            let ent = &self.entries[ei];
            if !ent.in_use || ent.block_idx != b {
                return Err(CacheError::InternalInconsistent);
            }

            let block_base = b.checked_mul(bs_u64).ok_or(CacheError::RangeOverflow)?;
            let seg_lo = max(offset, block_base);
            let seg_hi = min(end, block_base + bs_u64);

            let within_lo = (seg_lo - block_base) as usize;
            let within_len = (seg_hi - seg_lo) as usize;

            let start_sector = within_lo / self.sector_size;
            let end_sector = (within_lo + within_len).div_ceil(self.sector_size);

            if end_sector > self.sectors_per_block {
                return Err(CacheError::InternalInconsistent);
            }
            if !mask_all_set(&ent.valid, start_sector, end_sector) {
                return Err(CacheError::NotFullyCached);
            }

            let src_off = (ei * self.block_size)
                .checked_add(within_lo)
                .ok_or(CacheError::RangeOverflow)?;
            let src_end = src_off
                .checked_add(within_len)
                .ok_or(CacheError::RangeOverflow)?;

            let dst_off = (seg_lo - offset) as usize;
            let dst_end = dst_off + within_len;

            if src_end > self.backing.len() || dst_end > dst.len() {
                return Err(CacheError::InternalInconsistent);
            }

            dst[dst_off..dst_end].copy_from_slice(&self.backing[src_off..src_end]);

            b = b.wrapping_add(1);
            if b == 0 {
                break;
            }
        }

        Ok(())
    }

    pub fn fill_clean(&mut self, offset: u64, data: &[u8]) -> Result<(), CacheError> {
        if self.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }
        if data.is_empty() {
            return Ok(());
        }
        if !offset.is_multiple_of(self.sector_size as u64)
            || !data.len().is_multiple_of(self.sector_size)
        {
            return Err(CacheError::UnalignedRange);
        }

        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(CacheError::RangeOverflow)?;

        let bs_u64 = self.block_size as u64;
        let first = offset / bs_u64;
        let last = (end - 1) / bs_u64;

        let mut needed_new = 0usize;
        let mut b = first;
        while b <= last {
            if !self.map.contains_key(&b) {
                needed_new += 1;
            }
            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        if needed_new > self.free.len() {
            return Err(CacheError::CacheFull);
        }

        b = first;
        while b <= last {
            let entry_idx = if let Some(v) = self.map.get(&b) {
                *v
            } else {
                let idx = self.free.pop().ok_or(CacheError::CacheFull)?;
                let ei = idx as usize;
                if ei >= self.entries.len() {
                    return Err(CacheError::InternalInconsistent);
                }
                self.entries[ei].reset();
                self.entries[ei].block_idx = b;
                self.entries[ei].in_use = true;
                let prev = self.map.insert(b, idx).map_err(|_| CacheError::CacheFull)?;
                if prev.is_some() {
                    return Err(CacheError::EntryExists);
                }
                idx
            };

            let ei = entry_idx as usize;
            if ei >= self.entries.len() {
                return Err(CacheError::InternalInconsistent);
            }

            let block_base = b.checked_mul(bs_u64).ok_or(CacheError::RangeOverflow)?;
            let seg_lo = max(offset, block_base);
            let seg_hi = min(end, block_base + bs_u64);

            let within_lo = (seg_lo - block_base) as usize;
            let within_len = (seg_hi - seg_lo) as usize;

            let start_sector = within_lo / self.sector_size;
            let end_sector = (within_lo + within_len) / self.sector_size;

            if end_sector > self.sectors_per_block {
                return Err(CacheError::InternalInconsistent);
            }

            let ent = &mut self.entries[ei];
            if !ent.in_use || ent.block_idx != b {
                return Err(CacheError::InternalInconsistent);
            }

            let mut s = start_sector;
            while s < end_sector {
                let is_dirty = mask_test_bit(&ent.dirty, s);
                if !is_dirty {
                    let byte_off_in_block = s * self.sector_size;
                    let src_base = (block_base + (byte_off_in_block as u64))
                        .checked_sub(offset)
                        .ok_or(CacheError::RangeOverflow)?
                        as usize;

                    let dst_base = (ei * self.block_size)
                        .checked_add(byte_off_in_block)
                        .ok_or(CacheError::RangeOverflow)?;

                    let src_end = src_base
                        .checked_add(self.sector_size)
                        .ok_or(CacheError::RangeOverflow)?;
                    let dst_end = dst_base
                        .checked_add(self.sector_size)
                        .ok_or(CacheError::RangeOverflow)?;

                    if src_end > data.len() || dst_end > self.backing.len() {
                        return Err(CacheError::InternalInconsistent);
                    }

                    self.backing[dst_base..dst_end].copy_from_slice(&data[src_base..src_end]);
                }
                s += 1;
            }

            mask_set_range(&mut ent.valid, start_sector, end_sector);

            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        Ok(())
    }
    pub fn upsert_dirty(&mut self, offset: u64, data: &[u8]) -> Result<(), CacheError> {
        if self.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }
        if data.is_empty() {
            return Ok(());
        }

        if !offset.is_multiple_of(self.sector_size as u64)
            || !data.len().is_multiple_of(self.sector_size)
        {
            return Err(CacheError::UnalignedRange);
        }

        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(CacheError::RangeOverflow)?;

        let bs_u64 = self.block_size as u64;
        let first = offset / bs_u64;
        let last = (end - 1) / bs_u64;

        let mut needed_new = 0usize;
        let mut b = first;
        while b <= last {
            if !self.map.contains_key(&b) {
                needed_new += 1;
            }
            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        if needed_new > self.free.len() {
            return Err(CacheError::CacheFull);
        }

        b = first;
        while b <= last {
            let entry_idx = if let Some(v) = self.map.get(&b) {
                *v
            } else {
                let idx = self.free.pop().ok_or(CacheError::CacheFull)?;
                let ei = idx as usize;
                if ei >= self.entries.len() {
                    return Err(CacheError::InternalInconsistent);
                }

                self.entries[ei].reset();
                self.entries[ei].block_idx = b;
                self.entries[ei].in_use = true;

                let prev = self.map.insert(b, idx).map_err(|_| CacheError::CacheFull)?;
                if prev.is_some() {
                    return Err(CacheError::EntryExists);
                }
                idx
            };

            let ei = entry_idx as usize;
            if ei >= self.entries.len() {
                return Err(CacheError::InternalInconsistent);
            }

            let block_base = b.checked_mul(bs_u64).ok_or(CacheError::RangeOverflow)?;
            let seg_lo = max(offset, block_base);
            let seg_hi = min(end, block_base + bs_u64);

            let within_lo = (seg_lo - block_base) as usize;
            let within_len = (seg_hi - seg_lo) as usize;

            let start_sector = within_lo / self.sector_size;
            let end_sector = (within_lo + within_len) / self.sector_size;

            if end_sector > self.sectors_per_block {
                return Err(CacheError::InternalInconsistent);
            }

            let src_off = (seg_lo - offset) as usize;

            let slot_base = ei
                .checked_mul(self.block_size)
                .ok_or(CacheError::RangeOverflow)?;
            let dst_off = slot_base
                .checked_add(within_lo)
                .ok_or(CacheError::RangeOverflow)?;
            let dst_end = dst_off
                .checked_add(within_len)
                .ok_or(CacheError::RangeOverflow)?;

            if src_off + within_len > data.len() || dst_end > self.backing.len() {
                return Err(CacheError::InternalInconsistent);
            }

            self.backing[dst_off..dst_end].copy_from_slice(&data[src_off..src_off + within_len]);

            let ent = &mut self.entries[ei];
            if !ent.in_use || ent.block_idx != b {
                return Err(CacheError::InternalInconsistent);
            }

            mask_set_range(&mut ent.valid, start_sector, end_sector);
            mask_set_range(&mut ent.dirty, start_sector, end_sector);

            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        Ok(())
    }
    pub fn dirty_percent(&self) -> Result<f32, CacheError> {
        if self.block_size == 0 || self.sector_size == 0 || self.sectors_per_block == 0 {
            return Err(CacheError::NotConfigured);
        }

        let total_sectors = self
            .max_blocks
            .checked_mul(self.sectors_per_block)
            .ok_or(CacheError::RangeOverflow)?;
        if total_sectors == 0 {
            return Ok(0.0);
        }

        let mut dirty_sectors = 0usize;
        for e in self.entries.iter() {
            if !e.in_use {
                continue;
            }

            let mut w = 0usize;
            while w < MASK_WORDS {
                dirty_sectors = dirty_sectors
                    .checked_add(e.dirty[w].count_ones() as usize)
                    .ok_or(CacheError::RangeOverflow)?;
                w += 1;
            }
        }

        let pct = (dirty_sectors as f64) * 100.0 / (total_sectors as f64);
        Ok(pct as f32)
    }
    pub async fn flush_dirty(cache_lock: &RwLock<Self>, tgt: IoTarget) -> Result<(), CacheError> {
        let mut io_buf: Box<[u8]> = Box::new([]);

        loop {
            let (run_start_sector, run_sector_count, sector_size, sectors_per_block, block_size) = {
                let cache = cache_lock.read();

                if cache.block_size == 0 || cache.sector_size == 0 || cache.sectors_per_block == 0 {
                    return Err(CacheError::NotConfigured);
                }

                let mut dirty_blocks: Vec<u64> = Vec::new();
                for (block_idx, entry_idx) in cache.map.iter() {
                    let ei = *entry_idx as usize;
                    if ei >= cache.entries.len() {
                        return Err(CacheError::InternalInconsistent);
                    }

                    let ent = &cache.entries[ei];
                    if !ent.in_use || ent.block_idx != *block_idx {
                        return Err(CacheError::InternalInconsistent);
                    }

                    let mut any_dirty = false;
                    let mut w = 0usize;
                    while w < MASK_WORDS {
                        if ent.dirty[w] != 0 {
                            any_dirty = true;
                            break;
                        }
                        w += 1;
                    }

                    if any_dirty {
                        dirty_blocks.push(*block_idx);
                    }
                }

                if dirty_blocks.is_empty() {
                    return Ok(());
                }

                dirty_blocks.sort_unstable();

                let mut best_start: u64 = 0;
                let mut best_end: u64 = 0;

                let mut cur_start: u64 = 0;
                let mut cur_end: u64 = 0;
                let mut cur_active = false;

                let mut i = 0usize;
                while i < dirty_blocks.len() {
                    let block_idx = dirty_blocks[i];

                    let entry_idx = *cache
                        .map
                        .get(&block_idx)
                        .ok_or(CacheError::InternalInconsistent)?;
                    let ei = entry_idx as usize;
                    if ei >= cache.entries.len() {
                        return Err(CacheError::InternalInconsistent);
                    }

                    let ent = &cache.entries[ei];
                    if !ent.in_use || ent.block_idx != block_idx {
                        return Err(CacheError::InternalInconsistent);
                    }

                    let block_base_sector = block_idx
                        .checked_mul(cache.sectors_per_block as u64)
                        .ok_or(CacheError::RangeOverflow)?;

                    let mut s = 0usize;
                    while s < cache.sectors_per_block {
                        while s < cache.sectors_per_block && !mask_test_bit(&ent.dirty, s) {
                            s += 1;
                        }
                        if s == cache.sectors_per_block {
                            break;
                        }

                        let run_start_in_block = s;

                        while s < cache.sectors_per_block && mask_test_bit(&ent.dirty, s) {
                            s += 1;
                        }

                        let run_end_in_block = s;

                        let seg_start = block_base_sector
                            .checked_add(run_start_in_block as u64)
                            .ok_or(CacheError::RangeOverflow)?;
                        let seg_end = block_base_sector
                            .checked_add(run_end_in_block as u64)
                            .ok_or(CacheError::RangeOverflow)?;

                        if !cur_active {
                            cur_start = seg_start;
                            cur_end = seg_end;
                            cur_active = true;
                        } else if cur_end == seg_start {
                            cur_end = seg_end;
                        } else {
                            if (cur_end - cur_start) > (best_end - best_start) {
                                best_start = cur_start;
                                best_end = cur_end;
                            }
                            cur_start = seg_start;
                            cur_end = seg_end;
                        }
                    }

                    i += 1;
                }

                if cur_active && (cur_end - cur_start) > (best_end - best_start) {
                    best_start = cur_start;
                    best_end = cur_end;
                }

                if best_end <= best_start {
                    return Err(CacheError::InternalInconsistent);
                }

                (
                    best_start,
                    (best_end - best_start) as usize,
                    cache.sector_size,
                    cache.sectors_per_block,
                    cache.block_size,
                )
            };

            let write_len_bytes = run_sector_count
                .checked_mul(sector_size)
                .ok_or(CacheError::RangeOverflow)?;

            if io_buf.len() < write_len_bytes {
                io_buf = alloc::vec![0u8; write_len_bytes].into_boxed_slice();
            }

            {
                let cache = cache_lock.read();

                let mut dst_byte = 0usize;
                let mut remaining_sectors = run_sector_count;
                let mut sector_cursor = run_start_sector;

                while remaining_sectors != 0 {
                    let block_idx = sector_cursor / (sectors_per_block as u64);
                    let sector_in_block = (sector_cursor % (sectors_per_block as u64)) as usize;

                    let sectors_left_in_block = sectors_per_block - sector_in_block;
                    let sectors_to_copy = if remaining_sectors < sectors_left_in_block {
                        remaining_sectors
                    } else {
                        sectors_left_in_block
                    };

                    let entry_idx = *cache
                        .map
                        .get(&block_idx)
                        .ok_or(CacheError::InternalInconsistent)?;
                    let ei = entry_idx as usize;
                    if ei >= cache.entries.len() {
                        return Err(CacheError::InternalInconsistent);
                    }

                    let block_base_byte = ei
                        .checked_mul(block_size)
                        .ok_or(CacheError::RangeOverflow)?;

                    let src_byte = block_base_byte
                        .checked_add(
                            sector_in_block
                                .checked_mul(sector_size)
                                .ok_or(CacheError::RangeOverflow)?,
                        )
                        .ok_or(CacheError::RangeOverflow)?;

                    let bytes_to_copy = sectors_to_copy
                        .checked_mul(sector_size)
                        .ok_or(CacheError::RangeOverflow)?;

                    let src_end = src_byte
                        .checked_add(bytes_to_copy)
                        .ok_or(CacheError::RangeOverflow)?;

                    if src_end > cache.backing.len() || dst_byte + bytes_to_copy > io_buf.len() {
                        return Err(CacheError::InternalInconsistent);
                    }

                    io_buf[dst_byte..dst_byte + bytes_to_copy]
                        .copy_from_slice(&cache.backing[src_byte..src_end]);

                    dst_byte += bytes_to_copy;
                    remaining_sectors -= sectors_to_copy;
                    sector_cursor = sector_cursor
                        .checked_add(sectors_to_copy as u64)
                        .ok_or(CacheError::RangeOverflow)?;
                }
            }

            let write_offset_bytes = (run_start_sector as u128)
                .checked_mul(sector_size as u128)
                .ok_or(CacheError::RangeOverflow)? as u64;

            let mut write_req = RequestHandle::new(
                RequestType::Write {
                    offset: write_offset_bytes,
                    len: write_len_bytes,
                    flush_write_through: true,
                },
                RequestData::from_boxed_bytes(io_buf),
            );

            let status = pnp_send_request(tgt.clone(), &mut write_req).await;

            io_buf = {
                let mut w = write_req.write();
                w.take_data_bytes()
            };

            if status != DriverStatus::Success {
                return Err(CacheError::IoFailed(status));
            }

            {
                let mut cache = cache_lock.write();

                let mut remaining_sectors = run_sector_count;
                let mut sector_cursor = run_start_sector;

                while remaining_sectors != 0 {
                    let block_idx = sector_cursor / (cache.sectors_per_block as u64);
                    let sector_in_block =
                        (sector_cursor % (cache.sectors_per_block as u64)) as usize;

                    let sectors_left_in_block = cache.sectors_per_block - sector_in_block;
                    let sectors_to_clear = if remaining_sectors < sectors_left_in_block {
                        remaining_sectors
                    } else {
                        sectors_left_in_block
                    };

                    let entry_idx = match cache.map.get(&block_idx) {
                        Some(x) => *x,
                        None => {
                            remaining_sectors -= sectors_to_clear;
                            sector_cursor = sector_cursor
                                .checked_add(sectors_to_clear as u64)
                                .ok_or(CacheError::RangeOverflow)?;
                            continue;
                        }
                    };

                    let ei = entry_idx as usize;
                    if ei >= cache.entries.len() {
                        return Err(CacheError::InternalInconsistent);
                    }

                    let should_evict = {
                        let ent = &mut cache.entries[ei];
                        if !ent.in_use || ent.block_idx != block_idx {
                            return Err(CacheError::InternalInconsistent);
                        }

                        mask_clear_range(
                            &mut ent.dirty,
                            sector_in_block,
                            sector_in_block + sectors_to_clear,
                        );

                        let mut still_dirty = false;
                        let mut w = 0usize;
                        while w < MASK_WORDS {
                            if ent.dirty[w] != 0 {
                                still_dirty = true;
                                break;
                            }
                            w += 1;
                        }

                        !still_dirty
                    };

                    if should_evict && let Some(removed_entry_idx) = cache.map.remove(&block_idx) {
                        let removed_ei = removed_entry_idx as usize;
                        if removed_ei >= cache.entries.len() {
                            return Err(CacheError::InternalInconsistent);
                        }
                        cache.entries[removed_ei].reset();
                        cache.free.push(removed_entry_idx);
                    }

                    remaining_sectors -= sectors_to_clear;
                    sector_cursor = sector_cursor
                        .checked_add(sectors_to_clear as u64)
                        .ok_or(CacheError::RangeOverflow)?;
                }
            }
        }
    }
    // TODO: this function should be changed to ensure that the read data will fit in the cashe by evicting the oldest entries
    pub async fn flush_dirty_for_new(
        cache_lock: &RwLock<Self>,
        tgt: IoTarget,
        new_offset: u64,
        new_data: Box<[u8]>,
    ) -> Result<(), CacheError> {
        if new_data.is_empty() {
            return Ok(());
        }

        {
            let mut cache = cache_lock.write();
            match cache.fill_clean(new_offset, &new_data) {
                Ok(()) => return Ok(()),
                Err(CacheError::CacheFull) => {}
                Err(CacheError::UnalignedRange) => {
                    // TODO
                    return Ok(());
                }
                Err(_) => {
                    // TODO
                    return Ok(());
                }
            }
        }

        Self::flush_dirty(cache_lock, tgt).await?;

        {
            let mut cache = cache_lock.write();
            match cache.fill_clean(new_offset, &new_data) {
                Ok(()) => Ok(()),
                Err(CacheError::CacheFull) => {
                    // TODO
                    Err(CacheError::CacheFull)
                }
                Err(CacheError::UnalignedRange) => {
                    // TODO
                    Ok(())
                }
                Err(_) => {
                    // TODO
                    Ok(())
                }
            }
        }
    }
}
fn mask_test_bit(mask: &[u64; MASK_WORDS], bit: usize) -> bool {
    let w = bit / 64;
    let b = bit % 64;
    if w >= MASK_WORDS {
        return false;
    }
    (mask[w] & (1u64 << b)) != 0
}

fn mask_set_range(mask: &mut [u64; MASK_WORDS], start: usize, end: usize) {
    if start >= end {
        return;
    }

    let mut s = start;
    while s < end {
        let w = s / 64;
        let b = s % 64;
        mask[w] |= 1u64 << b;
        s += 1;
    }
}

fn mask_clear_range(mask: &mut [u64; MASK_WORDS], start: usize, end: usize) {
    if start >= end {
        return;
    }

    let mut s = start;
    while s < end {
        let w = s / 64;
        let b = s % 64;
        mask[w] &= !(1u64 << b);
        s += 1;
    }
}

fn mask_all_set(mask: &[u64; MASK_WORDS], start: usize, end: usize) -> bool {
    if start >= end {
        return true;
    }

    let mut s = start;
    while s < end {
        let w = s / 64;
        let b = s % 64;
        if (mask[w] & (1u64 << b)) == 0 {
            return false;
        }
        s += 1;
    }

    true
}
