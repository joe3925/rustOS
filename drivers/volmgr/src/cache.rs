extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{boxed::Box, vec};
use core::cmp::{max, min};
use core::sync::atomic::{AtomicBool, Ordering};
use heapless::index_map::FnvIndexMap;
use kernel_api::irq::apic_cpu_ids;
use kernel_api::kernel_types::async_types::AsyncRwLock;
use kernel_api::kernel_types::io::IoTarget;
use kernel_api::pnp::pnp_send_request;
use kernel_api::request::{RequestData, RequestHandle, RequestType};
use kernel_api::runtime::{spawn, spawn_detached};
use kernel_api::status::DriverStatus;

const MAX_CACHE_BYTES: usize = 20 * 1024 * 1024;
const MIN_BLOCK_SIZE: usize = 4096;

// heapless::IndexMap capacity must be a power of 2.
const MAX_ENTRIES: usize = 8192;

const MAX_SECTORS_PER_BLOCK: usize = 256;
const MASK_WORDS: usize = MAX_SECTORS_PER_BLOCK.div_ceil(64);

const FLUSH_LIMIT_BYTES: usize = 50 * 1024 * 1024;

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
    generation: u64,
    flushing: bool,
    flushing_gen: u64,
    ref_bit: bool,  // CLOCK reference bit
    evicting: bool, // staged for eviction; slot not reusable until finalized
}

impl Default for CacheEntry {
    fn default() -> Self {
        CacheEntry {
            block_idx: 0,
            valid: [0u64; MASK_WORDS],
            dirty: [0u64; MASK_WORDS],
            in_use: false,
            generation: 0,
            flushing: false,
            flushing_gen: 0,
            ref_bit: false,
            evicting: false,
        }
    }
}

impl CacheEntry {
    fn reset(&mut self) {
        *self = CacheEntry::default();
    }
}

/// A dirty cache entry that has been evicted to make room for new data.
/// The caller must write this to disk via `flush_evicted`.
#[derive(Clone)]
pub struct EvictedEntry {
    pub block_idx: u64,
    pub data: Box<[u8]>,     // copy of the dirty sector range from backing
    pub start_sector: usize, // byte offset within block where dirty data starts (in sectors)
    pub sector_count: usize,
    pub sector_size: usize,
    pub block_size: usize,
}

/// Internal staging record used to defer expensive copy work until after the
/// cache write lock is released.
#[derive(Clone)]
struct StagedEviction {
    entry_idx: u32,
    block_idx: u64,
    byte_start: usize,
    byte_len: usize,
    start_sector: usize,
    sector_count: usize,
    sector_size: usize,
    block_size: usize,
    entry_gen: u64,
}

/// Coalesced run of evicted dirty entries, ready to be written to disk.
#[derive(Clone)]
pub struct EvictedRun {
    pub start_offset: u64,
    pub data: Vec<u8>,
    pub sector_size: usize,
    pub block_size: usize,
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

    // CLOCK eviction hand (index into entries)
    clock_hand: usize,

    // Scratch buffers reused by flush paths to avoid per-iteration allocations.
    dirty_block_scratch: Vec<u64>,
    staged_copy_scratch: Vec<(StagedEviction, Box<[u8]>)>,
    evicted_run_scratch: Vec<EvictedRun>,
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
            clock_hand: 0,
            dirty_block_scratch: Vec::new(),
            staged_copy_scratch: Vec::new(),
            evicted_run_scratch: Vec::new(),
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

    pub fn fill_clean_no_evict(&mut self, offset: u64, data: &[u8]) -> Result<(), CacheError> {
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
                self.entries[ei].ref_bit = true;
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
            ent.ref_bit = true;

            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        Ok(())
    }

    pub fn upsert_dirty_no_evict(&mut self, offset: u64, data: &[u8]) -> Result<(), CacheError> {
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
                self.entries[ei].ref_bit = true;

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
            ent.generation = ent.generation.wrapping_add(1);
            ent.ref_bit = true;

            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        Ok(())
    }

    /// Async wrapper that stages evictions, copies evicted bytes, finalizes,
    /// and performs the clean fill — all under a single write lock to prevent
    /// TOCTOU races with concurrent dirty writes.
    pub async fn fill_clean_async(
        cache_lock: &AsyncRwLock<Self>,
        offset: u64,
        data: &[u8],
    ) -> Result<Vec<EvictedEntry>, CacheError> {
        let mut cache = cache_lock.write().await;

        if cache.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }
        if data.is_empty() {
            return Ok(Vec::new());
        }
        if !offset.is_multiple_of(cache.sector_size as u64)
            || !data.len().is_multiple_of(cache.sector_size)
        {
            return Err(CacheError::UnalignedRange);
        }

        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(CacheError::RangeOverflow)?;

        let bs_u64 = cache.block_size as u64;
        let first = offset / bs_u64;
        let last = (end - 1) / bs_u64;

        let mut needed_new = 0usize;
        let mut b = first;
        while b <= last {
            if !cache.map.contains_key(&b) {
                needed_new += 1;
            }
            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        let free_len = cache.free.len();
        if needed_new > free_len {
            let missing = needed_new - free_len;
            let staged = cache.stage_evictions(missing);
            if staged.len() < missing {
                return Err(CacheError::CacheFull);
            }
            let copied = cache.copy_staged_data(&staged);
            let evicted = cache.finalize_evictions(copied);
            cache.fill_clean_no_evict(offset, data)?;
            return Ok(evicted);
        }

        cache.fill_clean_no_evict(offset, data)?;
        Ok(Vec::new())
    }

    /// Async wrapper that stages evictions, copies dirty bytes, finalizes,
    /// and performs the dirty upsert — all under a single write lock to prevent
    /// TOCTOU races with concurrent operations.
    pub async fn upsert_dirty_async(
        cache_lock: &AsyncRwLock<Self>,
        offset: u64,
        data: &[u8],
    ) -> Result<Vec<EvictedEntry>, CacheError> {
        let mut cache = cache_lock.write().await;

        if cache.block_size == 0 {
            return Err(CacheError::NotConfigured);
        }
        if data.is_empty() {
            return Ok(Vec::new());
        }
        if !offset.is_multiple_of(cache.sector_size as u64)
            || !data.len().is_multiple_of(cache.sector_size)
        {
            return Err(CacheError::UnalignedRange);
        }

        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(CacheError::RangeOverflow)?;

        let bs_u64 = cache.block_size as u64;
        let first = offset / bs_u64;
        let last = (end - 1) / bs_u64;

        let mut needed_new = 0usize;
        let mut b = first;
        while b <= last {
            if !cache.map.contains_key(&b) {
                needed_new += 1;
            }
            b = b.wrapping_add(1);
            if b == 0 {
                return Err(CacheError::RangeOverflow);
            }
        }

        let free_len = cache.free.len();
        if needed_new > free_len {
            let missing = needed_new - free_len;
            let staged = cache.stage_evictions(missing);
            if staged.len() < missing {
                return Err(CacheError::CacheFull);
            }
            let copied = cache.copy_staged_data(&staged);
            let evicted = cache.finalize_evictions(copied);
            cache.upsert_dirty_no_evict(offset, data)?;
            return Ok(evicted);
        }

        cache.upsert_dirty_no_evict(offset, data)?;
        Ok(Vec::new())
    }

    pub fn dirty_bytes(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.in_use)
            .flat_map(|e| e.dirty.iter())
            .map(|w| w.count_ones() as usize)
            .sum::<usize>()
            * self.sector_size
    }

    /// Approximate count of dirty runs (contiguous dirty block spans).
    pub fn dirty_run_hint(&self) -> usize {
        let mut dirty_blocks: Vec<u64> = self
            .map
            .iter()
            .filter_map(|(block_idx, entry_idx)| {
                let ei = *entry_idx as usize;
                let ent = self.entries.get(ei)?;
                if ent.in_use && !ent.flushing && ent.dirty.iter().any(|&w| w != 0) {
                    Some(*block_idx)
                } else {
                    None
                }
            })
            .collect();

        if dirty_blocks.is_empty() {
            return 0;
        }

        dirty_blocks.sort_unstable();
        let mut runs = 1usize;
        let mut prev = dirty_blocks[0];
        for &b in dirty_blocks.iter().skip(1) {
            if b != prev + 1 {
                runs += 1;
            }
            prev = b;
        }
        runs
    }

    /// Ensure at least `needed` free slots are available by staging evictions.
    /// Returns the staged evictions; caller is expected to copy and finalize
    /// outside the write lock.
    pub fn make_room(&mut self, needed: usize) -> Vec<StagedEviction> {
        let have = self.free.len();
        if have >= needed {
            return Vec::new();
        }
        self.stage_evictions(needed - have)
    }

    /// CLOCK-based staged eviction. Marks selected entries as `evicting` and
    /// removes them from the map but does NOT free their slots or copy data.
    /// Caller must later call `copy_and_finalize_evictions` before reuse.
    fn stage_evictions(&mut self, needed: usize) -> Vec<StagedEviction> {
        if self.block_size == 0 || needed == 0 || self.entries.is_empty() {
            return Vec::new();
        }

        let mut staged: Vec<StagedEviction> = Vec::new();
        let mut scanned = 0usize;
        let total = self.entries.len();

        while staged.len() < needed && scanned < total * 2 {
            let idx = self.clock_hand % total;
            self.clock_hand = (self.clock_hand + 1) % total;
            scanned += 1;

            let ent = &mut self.entries[idx];

            if !ent.in_use || ent.flushing || ent.evicting {
                ent.ref_bit = false;
                continue;
            }

            if ent.ref_bit {
                ent.ref_bit = false;
                continue;
            }

            // Candidate chosen.
            let block_idx = ent.block_idx;
            let entry_idx_u32 = self.map.remove(&block_idx).unwrap_or(idx as u32);

            let (start_sector, sector_count, byte_start, byte_len) = {
                if ent.dirty.iter().any(|&w| w != 0) {
                    let first_dirty = (0..self.sectors_per_block)
                        .find(|&s| mask_test_bit(&ent.dirty, s))
                        .unwrap_or(0);
                    let last_dirty_excl = (0..self.sectors_per_block)
                        .rev()
                        .find(|&s| mask_test_bit(&ent.dirty, s))
                        .map(|s| s + 1)
                        .unwrap_or(0);

                    let byte_start = idx * self.block_size + first_dirty * self.sector_size;
                    let byte_end = idx * self.block_size + last_dirty_excl * self.sector_size;
                    (
                        first_dirty,
                        last_dirty_excl.saturating_sub(first_dirty),
                        byte_start,
                        byte_end.saturating_sub(byte_start),
                    )
                } else {
                    (0, 0, idx * self.block_size, 0)
                }
            };

            ent.evicting = true;
            ent.in_use = false;

            staged.push(StagedEviction {
                entry_idx: entry_idx_u32,
                block_idx,
                byte_start,
                byte_len,
                start_sector,
                sector_count,
                sector_size: self.sector_size,
                block_size: self.block_size,
                entry_gen: ent.generation,
            });
        }

        staged
    }

    /// Copy staged eviction data using the reusable scratch buffer.
    /// Takes the scratch Vec, fills it, and returns it. Caller must return
    /// the Vec via `recycle_staged_scratch` after consuming entries.
    fn copy_staged_data(&mut self, staged: &[StagedEviction]) -> Vec<(StagedEviction, Box<[u8]>)> {
        let mut scratch = core::mem::take(&mut self.staged_copy_scratch);
        scratch.clear();
        scratch.reserve(staged.len());
        for ev in staged.iter().cloned() {
            let data = if ev.byte_len == 0 {
                Box::<[u8]>::default()
            } else if ev.byte_start + ev.byte_len <= self.backing.len() {
                self.backing[ev.byte_start..ev.byte_start + ev.byte_len]
                    .to_vec()
                    .into_boxed_slice()
            } else {
                Box::<[u8]>::default()
            };
            scratch.push((ev, data));
        }
        scratch
    }

    /// Return the staged-copy scratch Vec after use so its capacity is recycled.
    fn recycle_staged_scratch(&mut self, mut v: Vec<(StagedEviction, Box<[u8]>)>) {
        v.clear();
        self.staged_copy_scratch = v;
    }

    /// Finalize staged evictions after data has been copied.
    fn finalize_evictions(
        &mut self,
        mut copied: Vec<(StagedEviction, Box<[u8]>)>,
    ) -> Vec<EvictedEntry> {
        let mut evicted: Vec<EvictedEntry> = Vec::new();

        for (ev, data) in copied.drain(..) {
            let ei = ev.entry_idx as usize;
            if ei >= self.entries.len() {
                continue;
            }

            let ent = &mut self.entries[ei];

            // Skip if entry was reused since staging.
            if ent.generation != ev.entry_gen || !ent.evicting {
                continue;
            }

            ent.reset();
            ent.evicting = false;
            self.free.push(ev.entry_idx);

            if ev.sector_count > 0 && !data.is_empty() {
                evicted.push(EvictedEntry {
                    block_idx: ev.block_idx,
                    data,
                    start_sector: ev.start_sector,
                    sector_count: ev.sector_count,
                    sector_size: ev.sector_size,
                    block_size: ev.block_size,
                });
            }
        }

        self.recycle_staged_scratch(copied);
        evicted
    }

    /// Coalesce evicted dirty entries into contiguous runs using a scratch buffer.
    /// Returns the runs; caller should drop the lock and pass them to
    /// `spawn_evicted_writes`.
    pub fn coalesce_evicted(&mut self, mut evicted: Vec<EvictedEntry>) -> Vec<EvictedRun> {
        if evicted.is_empty() {
            return Vec::new();
        }

        fn entry_offset(e: &EvictedEntry) -> Option<u64> {
            let block_off = e.block_idx.checked_mul(e.block_size as u64)?;
            let sector_off = (e.start_sector as u64).checked_mul(e.sector_size as u64)?;
            block_off.checked_add(sector_off)
        }

        evicted.sort_by_key(|e| (e.block_idx, e.start_sector));

        let runs = &mut self.evicted_run_scratch;
        runs.clear();

        for entry in evicted {
            if entry.data.is_empty() {
                continue;
            }

            let offset = match entry_offset(&entry) {
                Some(o) => o,
                None => continue,
            };

            // Try to append to the last run if it is immediately contiguous.
            if let Some(last) = runs.last_mut() {
                let last_end = last
                    .start_offset
                    .checked_add(u64::try_from(last.data.len()).unwrap_or(u64::MAX));
                if last_end == Some(offset)
                    && last.sector_size == entry.sector_size
                    && last.block_size == entry.block_size
                {
                    last.data.extend_from_slice(&entry.data);
                    continue;
                }
            }

            runs.push(EvictedRun {
                start_offset: offset,
                data: entry.data.into_vec(),
                sector_size: entry.sector_size,
                block_size: entry.block_size,
            });
        }

        core::mem::take(runs)
    }

    /// Recycle the evicted-run scratch Vec after the runs have been consumed.
    pub fn recycle_evicted_scratch(&mut self, mut v: Vec<EvictedRun>) {
        v.clear();
        self.evicted_run_scratch = v;
    }

    /// Write all coalesced evicted runs to disk, awaiting completion.
    /// Must be called **after** releasing the cache write lock.
    /// Returns the drained Vec shell for recycling via `recycle_evicted_scratch`.
    pub async fn write_evicted_runs(mut runs: Vec<EvictedRun>, tgt: IoTarget) -> Vec<EvictedRun> {
        let mut handles = Vec::new();
        for run in runs.drain(..) {
            if run.data.is_empty() {
                continue;
            }
            let tgt_clone = tgt.clone();
            let start = run.start_offset;
            let data = run.data;
            handles.push(spawn(async move {
                let write_len = data.len();

                let mut write_req = RequestHandle::new(
                    RequestType::Write {
                        offset: start,
                        len: write_len,
                        flush_write_through: true,
                    },
                    RequestData::from_boxed_bytes(data.into_boxed_slice()),
                );

                let _ = pnp_send_request(tgt_clone, &mut write_req).await;
            }));
        }
        for handle in handles {
            handle.await;
        }
        runs
    }

    /// Spawn the flush coordinator if one is not already running.
    /// The `flush_running` flag is an AtomicBool owned by the caller (VolPdoExt).
    /// This is the only entry point for background flushing.
    ///
    /// # Safety
    /// Both `cache_lock` and `flush_running` must remain valid for the lifetime
    /// of the spawned task (i.e., they must be stored in the device extension,
    /// which is Arc-refcounted and lives as long as the device).
    /// Both addresses are raw pointers smuggled as `usize` for `Send + 'static`.
    pub fn try_spawn_flush(
        cache_addr: usize,
        tgt: IoTarget,
        flush_addr: usize,
        max_inflight: usize,
    ) {
        let flag = unsafe { &*(flush_addr as *const AtomicBool) };
        if flag
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            spawn_detached(async move {
                let _ =
                    Self::flush_dirty(cache_addr, tgt, Some(FLUSH_LIMIT_BYTES), max_inflight).await;
                let flag = unsafe { &*(flush_addr as *const AtomicBool) };
                flag.store(false, Ordering::Release);
            });
        }
    }

    /// Flush dirty cache entries to the backing device.
    ///
    /// Collects ALL dirty runs under one write lock, divides them evenly
    /// across `max_inflight` spawned worker tasks, awaits all workers,
    /// then applies results under a final write lock. Only one
    /// spawn-and-wait cycle per call.
    ///
    /// Write tasks borrow directly from the cache backing slab (zero-copy).
    /// Blocks marked `flushing` are safe to read concurrently because only
    /// `upsert_dirty` can overwrite them, and if it does the generation
    /// mismatch will prevent stale dirty-bit clearing.
    ///
    /// # Safety
    /// `cache_lock` must remain valid for the duration of this future.
    /// The backing slab must not be reallocated while write tasks are in
    /// flight (guaranteed because `set_block_size` is only called once at
    /// init and the slab never grows).
    pub async fn flush_dirty(
        cache_lock: usize, // raw pointer smuggled as usize to satisfy Send + 'static
        tgt: IoTarget,
        limit_bytes: Option<usize>,
        max_inflight: usize,
    ) -> Result<(), CacheError> {
        // SAFETY: caller guarantees the pointed-to AsyncRwLock outlives this future.
        let cache_lock_ref = unsafe { &*(cache_lock as *const AsyncRwLock<Self>) };

        // --- Phase 1: Collect ALL dirty jobs under one write lock ---
        let (all_runs, backing_ptr, block_size, sector_size, sectors_per_block) = {
            let mut cache = cache_lock_ref.write().await;
            let backing_ptr = cache.backing.as_ptr() as usize;
            let mut all_runs: Vec<RunInfo> = Vec::new();
            let mut total_bytes = 0usize;
            let block_size = cache.block_size;
            let sector_size = cache.sector_size;
            let sectors_per_block = cache.sectors_per_block;

            loop {
                let run = find_next_dirty_run(&mut cache);
                match run {
                    None => break,
                    Some(run_info) => {
                        total_bytes += run_info.byte_len;
                        all_runs.push(run_info);
                        if let Some(limit) = limit_bytes {
                            if total_bytes >= limit {
                                break;
                            }
                        }
                    }
                }
            }

            (
                all_runs,
                backing_ptr,
                block_size,
                sector_size,
                sectors_per_block,
            )
        };

        if all_runs.is_empty() {
            return Ok(());
        }

        // --- Phase 2: Split jobs across max_inflight workers, spawn, await ---
        let num_workers = max_inflight.min(all_runs.len());
        let results = Arc::new(spin::Mutex::new(vec![false; all_runs.len()]));
        let runs = Arc::new(all_runs);

        // Divide jobs into `num_workers` roughly-equal chunks.
        let chunk_size = (runs.len() + num_workers - 1) / num_workers;
        let mut handles = Vec::with_capacity(num_workers);
        let mut start = 0;

        while start < runs.len() {
            let end = (start + chunk_size).min(runs.len());
            let tgt_clone = tgt.clone();
            let bp = backing_ptr;
            let results_clone = results.clone();
            let runs_clone = runs.clone();
            let base_idx = start;
            let end_idx = end;
            let block_size = block_size;
            let sector_size = sector_size;
            let sectors_per_block = sectors_per_block;
            let cache_lock_ref = cache_lock_ref;

            let handle = spawn(async move {
                for run_idx in base_idx..end_idx {
                    let run = &runs_clone[run_idx];
                    let mut run_ok = true;

                    for i in 0..run.block_count {
                        let block_idx = run.start_block + i as u64;
                        let (entry_idx, start_sector, end_sector) = {
                            let cache = cache_lock_ref.read().await;
                            let entry_idx = match cache.map.get(&block_idx) {
                                Some(v) => *v as usize,
                                None => {
                                    run_ok = false;
                                    break;
                                }
                            };
                            if entry_idx >= cache.entries.len() {
                                run_ok = false;
                                break;
                            }
                            let ent = &cache.entries[entry_idx];
                            if !ent.flushing {
                                run_ok = false;
                                break;
                            }
                            let start_sector = if i == 0 { run.first_start_sector } else { 0 };
                            let end_sector = if i + 1 == run.block_count {
                                run.last_end_sector
                            } else {
                                sectors_per_block
                            };
                            (entry_idx, start_sector, end_sector)
                        };

                        // SAFETY: backing slab is stable (never reallocated after init).
                        // Flushing blocks won't be evicted. If re-dirtied, generation
                        // mismatch handles it.
                        let entry_idx_usize = entry_idx as usize;
                        let backing_offset =
                            entry_idx_usize * block_size + start_sector * sector_size;
                        let data_len = (end_sector - start_sector) * sector_size;
                        let disk_offset =
                            block_idx * block_size as u64 + (start_sector * sector_size) as u64;

                        let data_ptr = unsafe { (bp as *const u8).add(backing_offset) };
                        let req_data =
                            unsafe { RequestData::from_borrowed_bytes(data_ptr, data_len) };

                        let mut write_req = RequestHandle::new(
                            RequestType::Write {
                                offset: disk_offset,
                                len: data_len,
                                flush_write_through: true,
                            },
                            req_data,
                        );

                        let status = pnp_send_request(tgt_clone.clone(), &mut write_req).await;
                        if status != DriverStatus::Success {
                            run_ok = false;
                            break;
                        }
                    }

                    if run_ok {
                        results_clone.lock()[run_idx] = true;
                    }
                }
            });

            handles.push(handle);
            start = end;
        }

        // Await all worker handles.
        for handle in handles {
            handle.await;
        }

        let ok = Arc::try_unwrap(results)
            .map(|m| m.into_inner())
            .unwrap_or_else(|arc| arc.lock().clone());
        let all_runs = Arc::try_unwrap(runs).expect("all_runs Arc still has references");

        // --- Phase 3: Update cache state under write lock ---
        {
            let mut cache = cache_lock_ref.write().await;
            let sectors_per_block = cache.sectors_per_block;

            for (idx, run) in all_runs.iter().enumerate() {
                let run_ok = ok[idx];
                for i in 0..run.block_count {
                    let block_idx = run.start_block + i as u64;
                    let entry_idx = match cache.map.get(&block_idx) {
                        Some(v) => *v as usize,
                        None => continue,
                    };
                    if entry_idx >= cache.entries.len() {
                        continue;
                    }

                    let start_sector = if i == 0 { run.first_start_sector } else { 0 };
                    let end_sector = if i + 1 == run.block_count {
                        run.last_end_sector
                    } else {
                        sectors_per_block
                    };

                    {
                        let ent = &mut cache.entries[entry_idx];

                        if run_ok && ent.generation == ent.flushing_gen {
                            mask_clear_range(&mut ent.dirty, start_sector, end_sector);
                        }

                        ent.flushing = false;
                        ent.flushing_gen = 0;
                        // Keep fully-clean entries in the cache — they are
                        // still valuable for read hits. The CLOCK eviction
                        // policy will reclaim them when space is needed.
                    }
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal flush helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct RunInfo {
    start_block: u64,
    block_count: usize,
    first_start_sector: usize,
    last_end_sector: usize,
    byte_len: usize,
}

/// Scan the cache map in iteration order and find the first contiguous run of
/// dirty sectors. Marks all blocks in the run as `flushing = true` and stores
/// the generation to detect re-dirty during flush.
/// Returns `None` if no unflushed dirty blocks exist.
fn find_next_dirty_run(cache: &mut VolumeCache) -> Option<RunInfo> {
    if cache.block_size == 0 || cache.sector_size == 0 {
        return None;
    }

    let sectors_per_block = cache.sectors_per_block;
    let sector_size = cache.sector_size;

    // Collect dirty, non-flushing block indices in sorted order.
    let dirty_blocks = &mut cache.dirty_block_scratch;
    dirty_blocks.clear();
    dirty_blocks.reserve(cache.map.len());
    for (block_idx, entry_idx) in cache.map.iter() {
        let ei = *entry_idx as usize;
        let ent = match cache.entries.get(ei) {
            Some(e) => e,
            None => continue,
        };
        if ent.in_use && !ent.flushing && ent.dirty.iter().any(|&w| w != 0) {
            dirty_blocks.push(*block_idx);
        }
    }

    if dirty_blocks.is_empty() {
        return None;
    }

    dirty_blocks.sort_unstable();

    let mut start_block = 0u64;
    let mut block_count: usize = 0;
    let mut first_start_sector: usize = 0;
    let mut last_end_sector: usize = 0;
    let mut total_sectors: usize = 0;
    let mut prev_block: Option<u64> = None;

    for &block_idx in dirty_blocks.iter() {
        let entry_idx = match cache.map.get(&block_idx) {
            Some(&ei) => ei as usize,
            None => break,
        };
        let ent = &mut cache.entries[entry_idx];

        if !ent.in_use || ent.block_idx != block_idx || ent.flushing {
            break;
        }

        let first_dirty = (0..sectors_per_block).find(|&s| mask_test_bit(&ent.dirty, s));
        let first_dirty = match first_dirty {
            Some(s) => s,
            None => break,
        };

        if let Some(prev) = prev_block {
            if block_idx != prev + 1 || first_dirty != 0 {
                break;
            }
        } else {
            start_block = block_idx;
            first_start_sector = first_dirty;
        }

        let last_dirty_exclusive = {
            let mut end = first_dirty + 1;
            while end < sectors_per_block && mask_test_bit(&ent.dirty, end) {
                end += 1;
            }
            end
        };

        ent.flushing = true;
        ent.flushing_gen = ent.generation;

        total_sectors += last_dirty_exclusive - first_dirty;
        block_count += 1;
        last_end_sector = last_dirty_exclusive;

        if last_dirty_exclusive < sectors_per_block {
            break;
        }

        prev_block = Some(block_idx);
    }

    if block_count == 0 {
        return None;
    }

    Some(RunInfo {
        start_block,
        block_count,
        first_start_sector,
        last_end_sector,
        byte_len: total_sectors * sector_size,
    })
}

// ---------------------------------------------------------------------------
// Bit-mask helpers (word-at-a-time)
// ---------------------------------------------------------------------------

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
    let first_word = start / 64;
    let last_word = (end - 1) / 64;

    if first_word == last_word {
        // Both ends in same word
        let lo = start % 64;
        let hi = end % 64; // exclusive bit within word; 0 means full word
        let hi_bit = if hi == 0 { 64 } else { hi };
        let bits = if hi_bit - lo == 64 {
            !0u64
        } else {
            ((1u64 << (hi_bit - lo)) - 1) << lo
        };
        mask[first_word] |= bits;
    } else {
        // Partial first word
        let lo = start % 64;
        mask[first_word] |= !0u64 << lo;
        // Full middle words
        for w in (first_word + 1)..last_word {
            mask[w] = !0u64;
        }
        // Partial last word
        let hi = end % 64;
        if hi == 0 {
            mask[last_word] = !0u64;
        } else {
            mask[last_word] |= (1u64 << hi) - 1;
        }
    }
}

fn mask_clear_range(mask: &mut [u64; MASK_WORDS], start: usize, end: usize) {
    if start >= end {
        return;
    }
    let first_word = start / 64;
    let last_word = (end - 1) / 64;

    if first_word == last_word {
        let lo = start % 64;
        let hi = end % 64;
        let hi_bit = if hi == 0 { 64 } else { hi };
        let bits = if hi_bit - lo == 64 {
            !0u64
        } else {
            ((1u64 << (hi_bit - lo)) - 1) << lo
        };
        mask[first_word] &= !bits;
    } else {
        let lo = start % 64;
        mask[first_word] &= !((!0u64) << lo);
        for w in (first_word + 1)..last_word {
            mask[w] = 0u64;
        }
        let hi = end % 64;
        if hi == 0 {
            mask[last_word] = 0u64;
        } else {
            mask[last_word] &= !((1u64 << hi) - 1);
        }
    }
}

fn mask_all_set(mask: &[u64; MASK_WORDS], start: usize, end: usize) -> bool {
    if start >= end {
        return true;
    }
    let first_word = start / 64;
    let last_word = (end - 1) / 64;

    if first_word == last_word {
        let lo = start % 64;
        let hi = end % 64;
        let hi_bit = if hi == 0 { 64 } else { hi };
        let bits = if hi_bit - lo == 64 {
            !0u64
        } else {
            ((1u64 << (hi_bit - lo)) - 1) << lo
        };
        return (mask[first_word] & bits) == bits;
    }

    // Partial first word
    let lo = start % 64;
    if (mask[first_word] & (!0u64 << lo)) != (!0u64 << lo) {
        return false;
    }
    // Full middle words
    for w in (first_word + 1)..last_word {
        if mask[w] != !0u64 {
            return false;
        }
    }
    // Partial last word
    let hi = end % 64;
    if hi == 0 {
        mask[last_word] == !0u64
    } else {
        let bits = (1u64 << hi) - 1;
        (mask[last_word] & bits) == bits
    }
}
