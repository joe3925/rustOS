#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::collections::VecDeque;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    mem::size_of,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use hashbrown::HashMap;
use kernel_api::pnp::DriverStep;
use spin::Mutex;

use kernel_api::{
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        io::{DiskInfo, IoType, Synchronization},
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
        driver_set_evt_device_add, pnp_forward_request_to_next_lower,
    },
    request::{Request, RequestHandle, RequestType, TraversalPolicy},
    request_handler,
    status::DriverStatus,
};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[panic_handler]
#[cfg(not(test))]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    panic_common(MOD_NAME, info)
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;
const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;

const CACHE_BYTES: usize = 20 * 1024 * 1024usize;
const MAX_CHUNK_BYTES: usize = 256 * 1024usize;

/// Cache block size is derived from the disk logical sector: 16 * sector_size capped at 4KiB.
const CACHE_BLOCK_SIZE: usize = 4096;

#[derive(Clone)]
struct CacheEntry {
    data: Box<[u8]>,
    dirty_mask: u16, // bit-per-sector within the block
    valid_mask: u16, // bit-per-sector within the block
}

impl CacheEntry {
    fn new(block_len: usize) -> Self {
        Self {
            data: vec![0u8; block_len].into_boxed_slice(),
            dirty_mask: 0,
            valid_mask: 0,
        }
    }
}

/// Per-disk cache keyed by block index.
struct SectorCache {
    sector_size: usize,
    block_len: usize,
    sectors_per_block: usize,
    max_blocks: usize,
    map: HashMap<u64, CacheEntry>,
    order: VecDeque<u64>,
}

impl Default for SectorCache {
    fn default() -> Self {
        Self {
            sector_size: 0,
            block_len: 0,
            sectors_per_block: 0,
            max_blocks: 0,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl SectorCache {
    /// Initialize derived block sizing from the device sector size.
    fn ensure_init(&mut self, sector_size: u32) -> bool {
        if self.block_len != 0 {
            return true;
        }
        let bs = sector_size as usize;
        if bs == 0 {
            return false;
        }
        // Always choose a multiple of the sector size, capped at 4KiB and at most 16 sectors.
        let max_mult = CACHE_BLOCK_SIZE / bs;
        let mult = max_mult.max(1).min(16);
        self.block_len = bs * mult;
        self.sector_size = bs;
        self.sectors_per_block = mult;
        self.max_blocks = (CACHE_BYTES / self.block_len).max(1);
        true
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    #[inline]
    fn block_base(&self, block_idx: u64) -> u64 {
        block_idx * self.block_len as u64
    }

    #[inline]
    fn sector_mask(&self, start: usize, count: usize) -> u16 {
        debug_assert!(start + count <= 16);
        if count == 0 {
            0
        } else {
            (((1u32 << count) - 1) << start) as u16
        }
    }

    fn touch_order(&mut self, block_idx: u64) {
        if let Some(pos) = self.order.iter().position(|&b| b == block_idx) {
            self.order.remove(pos);
        }
        self.order.push_back(block_idx);
    }

    fn evict_if_needed(&mut self) {
        if self.max_blocks == 0 || self.map.len() < self.max_blocks {
            return;
        }
        while self.map.len() >= self.max_blocks {
            let Some(old_idx) = self.order.pop_front() else {
                break;
            };
            if let Some(entry) = self.map.get(&old_idx) {
                if entry.dirty_mask != 0 {
                    // Keep dirty entries; move to back and give up eviction to avoid data loss.
                    self.order.push_back(old_idx);
                    break;
                }
            }
            self.map.remove(&old_idx);
        }
    }

    fn get_or_insert(&mut self, block_idx: u64) -> &mut CacheEntry {
        self.evict_if_needed();
        self.touch_order(block_idx);
        self.map
            .entry(block_idx)
            .or_insert_with(|| CacheEntry::new(self.block_len))
    }

    /// Attempt to satisfy the read entirely from cache; returns false if any portion is missing.
    fn try_read(&mut self, offset: u64, dst: &mut [u8]) -> bool {
        if self.block_len == 0 || dst.is_empty() {
            return false;
        }

        let mut remaining = dst.len();
        let mut cur_off = offset;
        let mut dst_off = 0usize;
        while remaining != 0 {
            let block_idx = cur_off / self.block_len as u64;
            let block_base = self.block_base(block_idx);
            let offset_in_block = (cur_off - block_base) as usize;
            let copy_len = remaining.min(self.block_len - offset_in_block);

            let start_sector = offset_in_block / self.sector_size;
            let sector_count = (copy_len + self.sector_size - 1) / self.sector_size;
            let mask = self.sector_mask(start_sector, sector_count);

            let Some(entry) = self.map.get(&block_idx) else {
                return false;
            };
            if (entry.valid_mask & mask) != mask {
                return false;
            }

            dst[dst_off..dst_off + copy_len]
                .copy_from_slice(&entry.data[offset_in_block..offset_in_block + copy_len]);

            self.touch_order(block_idx);

            cur_off += copy_len as u64;
            dst_off += copy_len;
            remaining -= copy_len;
        }

        true
    }

    /// Write data into the cache, optionally marking touched sectors dirty or clean.
    fn store_range(&mut self, offset: u64, data: &[u8], mark_dirty: bool, clear_dirty: bool) {
        if self.block_len == 0 || data.is_empty() {
            return;
        }

        let mut remaining = data.len();
        let mut cur_off = offset;
        let mut src_off = 0usize;

        while remaining != 0 {
            let block_idx = cur_off / self.block_len as u64;
            let block_base = self.block_base(block_idx);
            let offset_in_block = (cur_off - block_base) as usize;
            let copy_len = remaining.min(self.block_len - offset_in_block);

            let start_sector = offset_in_block / self.sector_size;
            let sector_count = (copy_len + self.sector_size - 1) / self.sector_size;
            let mask = self.sector_mask(start_sector, sector_count);

            let entry = self.get_or_insert(block_idx);

            // Decide which sectors to overwrite: skip dirty ones when we are just populating clean data.
            let write_mask = if !mark_dirty && !clear_dirty {
                mask & !entry.dirty_mask
            } else {
                mask
            };
            if write_mask != 0 {
                // Copy per-byte for the sectors we own; this slice always covers all sectors in mask.
                entry.data[offset_in_block..offset_in_block + copy_len]
                    .copy_from_slice(&data[src_off..src_off + copy_len]);
                entry.valid_mask |= write_mask;
            }

            if mark_dirty {
                entry.dirty_mask |= mask;
            } else if clear_dirty {
                entry.dirty_mask &= !mask;
                entry.valid_mask |= mask;
            }

            self.touch_order(block_idx);

            cur_off += copy_len as u64;
            src_off += copy_len;
            remaining -= copy_len;
        }
    }

    fn take_dirty_segments(&self) -> Vec<(u64, u16, usize, Vec<(u64, Vec<u8>)>)> {
        if self.block_len == 0 || self.sector_size == 0 {
            return Vec::new();
        }

        let mut out = Vec::new();
        for (&block_idx, entry) in self.map.iter() {
            let mut mask = entry.dirty_mask;
            if mask == 0 {
                continue;
            }
            let mut segments: Vec<(u64, Vec<u8>)> = Vec::new();
            let base = self.block_base(block_idx);

            while mask != 0 {
                let first = mask.trailing_zeros() as usize;
                let mut count = 1usize;
                while first + count < self.sectors_per_block
                    && (mask & (1u16 << (first + count))) != 0
                {
                    count += 1;
                }
                let byte_off = first * self.sector_size;
                let byte_len = count * self.sector_size;
                let mut buf = vec![0u8; byte_len];
                buf.copy_from_slice(&entry.data[byte_off..byte_off + byte_len]);
                segments.push((base + byte_off as u64, buf));

                let clear_mask = self.sector_mask(first, count);
                mask &= !clear_mask;
            }

            out.push((block_idx, entry.dirty_mask, self.block_len, segments));
        }

        out
    }

    fn clear_dirty_mask(&mut self, block_idx: u64, expected_mask: u16) {
        if let Some(entry) = self.map.get_mut(&block_idx) {
            if entry.dirty_mask == expected_mask {
                entry.dirty_mask = 0;
                // Mark the flushed sectors as valid.
                entry.valid_mask |= expected_mask;
            }
        }
    }
}

#[repr(C)]
struct DiskExt {
    block_size: AtomicU32,
    props_ready: AtomicBool,
    cache: Mutex<SectorCache>,
    rmw_lock: Mutex<()>,
}

impl Default for DiskExt {
    fn default() -> Self {
        Self {
            block_size: AtomicU32::new(0),
            props_ready: AtomicBool::new(false),
            cache: Mutex::new(SectorCache::default()),
            rmw_lock: Mutex::new(()),
        }
    }
}

#[inline]
fn cache_try_read(dx: &DiskExt, off: u64, _total: usize, dst: &mut [u8]) -> bool {
    let bs = dx.block_size.load(Ordering::Acquire);
    if bs == 0 {
        return false;
    }

    let mut cache = dx.cache.lock();
    if !cache.ensure_init(bs) {
        return false;
    }
    cache.try_read(off, dst)
}

#[inline]
fn cache_store_read(dx: &DiskExt, off: u64, data: &[u8]) {
    let bs = dx.block_size.load(Ordering::Acquire);
    if bs == 0 {
        return;
    }

    let mut cache = dx.cache.lock();
    if !cache.ensure_init(bs) {
        return;
    }
    cache.store_range(off, data, false, false);
}

#[inline]
fn cache_update_write(dx: &DiskExt, off: u64, data: &[u8], mark_dirty: bool) {
    let bs = dx.block_size.load(Ordering::Acquire);
    if bs == 0 {
        return;
    }

    let mut cache = dx.cache.lock();
    if !cache.ensure_init(bs) {
        return;
    }
    cache.store_range(off, data, mark_dirty, !mark_dirty);
}

#[inline]
fn cache_clear(dx: &DiskExt) {
    let mut cache = dx.cache.lock();
    cache.clear();
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, disk_device_add);
    DriverStatus::Success
}

pub extern "win64" fn disk_device_add(
    _driver: Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    dev_init
        .io_vtable
        .set(IoType::Read(disk_read), Synchronization::Sync, 0);
    dev_init
        .io_vtable
        .set(IoType::Write(disk_write), Synchronization::Sync, 0);
    dev_init
        .io_vtable
        .set(IoType::DeviceControl(disk_ioctl), Synchronization::Sync, 0);

    let mut pnp_vt = PnpVtable::new();
    pnp_vt.set(PnpMinorFunction::RemoveDevice, disk_pnp_remove);
    dev_init.pnp_vtable = Some(pnp_vt);

    dev_init.set_dev_ext_default::<DiskExt>();
    DriverStep::complete(DriverStatus::Success)
}

#[repr(C)]
struct DiskReadCtx {
    dev: Arc<DeviceObject>,
    offset: u64,
    len: usize,
}

#[repr(C)]
struct DiskWriteCtx {
    dev: Arc<DeviceObject>,
    offset: u64,
    len: usize,
    write_through: bool,
}

#[request_handler]
async fn disk_pnp_remove<'a, 'b>(
    dev: Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let _ = flush_dirty_blocks(&dev).await;
    DriverStep::Continue
}

extern "win64" fn disk_read_complete(req: &mut Request, ctx: usize) -> DriverStatus {
    let boxed = unsafe { Box::from_raw(ctx as *mut DiskReadCtx) };
    let st = req.status;
    if st == DriverStatus::Success {
        let dx = disk_ext(&boxed.dev);
        let n = core::cmp::min(boxed.len, req.data_len());
        if n != 0 {
            let bs = dx.block_size.load(Ordering::Acquire);
            if bs != 0 {
                let mut cache = dx.cache.lock();
                if cache.ensure_init(bs) {
                    // Overlay any dirty cached sectors so the caller sees the latest data.
                    let sector_size = cache.sector_size;
                    let buf = req.data_slice_mut();
                    let mut processed = 0usize;
                    while processed < n {
                        let global_off = boxed.offset + processed as u64;
                        let block_idx = global_off / cache.block_len as u64;
                        let block_base = cache.block_base(block_idx);
                        let offset_in_block = (global_off - block_base) as usize;
                        let copy_len = (n - processed).min(cache.block_len - offset_in_block);

                        if let Some(entry) = cache.map.get(&block_idx) {
                            let start_sector = offset_in_block / sector_size;
                            let sector_count = (copy_len + sector_size - 1) / sector_size;
                            let mask = cache.sector_mask(start_sector, sector_count);
                            let mut dirty = entry.dirty_mask & mask;
                            while dirty != 0 {
                                let first = dirty.trailing_zeros() as usize;
                                let mut count = 1usize;
                                while first + count < cache.sectors_per_block
                                    && (dirty & (1u16 << (first + count))) != 0
                                {
                                    count += 1;
                                }
                                let byte_off = first * sector_size;
                                let byte_len = count * sector_size;
                                let global_start = block_base + byte_off as u64;
                                let dst_off = (global_start - boxed.offset) as usize;
                                if dst_off + byte_len <= buf.len() {
                                    buf[dst_off..dst_off + byte_len].copy_from_slice(
                                        &entry.data[byte_off..byte_off + byte_len],
                                    );
                                }
                                dirty &= !cache.sector_mask(first, count);
                            }
                        }

                        processed += copy_len;
                    }

                    // Populate cache with freshly read clean data (skip dirty portions).
                    cache.store_range(boxed.offset, &buf[..n], false, false);
                }
            }
        }
    }
    st
}

extern "win64" fn disk_write_complete(req: &mut Request, ctx: usize) -> DriverStatus {
    let boxed = unsafe { Box::from_raw(ctx as *mut DiskWriteCtx) };
    let st = req.status;
    if st == DriverStatus::Success {
        let dx = disk_ext(&boxed.dev);
        let n = core::cmp::min(boxed.len, req.data_len());
        if n != 0 {
            cache_update_write(
                &dx,
                boxed.offset,
                &req.data_slice()[..n],
                !boxed.write_through,
            );
        }
    }
    st
}

#[request_handler]
pub async fn disk_read<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let (off, total) = match {
        let g = req.read();
        g.kind
    } {
        RequestType::Read { offset, len } => (offset, len),
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    if total == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let dx = disk_ext(&dev);
    if !dx.props_ready.load(Ordering::Acquire) {
        if let Err(st) = query_props_sync(&dev).await {
            return DriverStep::complete(st);
        }
    }

    let bs = dx.block_size.load(Ordering::Acquire) as u64;
    if bs == 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let data_too_small = {
        let p = req.read();
        p.data_len() < total
    };
    if data_too_small {
        return DriverStep::complete(DriverStatus::InsufficientResources);
    }

    let aligned = (off % bs == 0) && ((total as u64) % bs == 0);
    if !aligned {
        {
            let mut p = req.write();
            p.status = DriverStatus::InvalidParameter;
        }
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let hit_cache = {
        let mut p = req.write();
        let n = core::cmp::min(total, p.data_len());
        if n != 0 && cache_try_read(&dx, off, n, &mut p.data_slice_mut()[..n]) {
            p.status = DriverStatus::Success;
            true
        } else {
            let ctx = Box::new(DiskReadCtx {
                dev: dev.clone(),
                offset: off,
                len: total,
            });
            p.add_completion(disk_read_complete, Box::into_raw(ctx) as usize);
            p.traversal_policy = TraversalPolicy::ForwardLower;
            false
        }
    };

    if hit_cache {
        return DriverStep::complete(DriverStatus::Success);
    }
    DriverStep::Continue
}

#[request_handler]
pub async fn disk_write<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let (off, total, write_through) = match {
        let g = req.read();
        g.kind
    } {
        RequestType::Write {
            offset,
            len,
            flush_write_through,
        } => (offset, len, flush_write_through),
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };
    if total == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let dx = disk_ext(&dev);
    if !dx.props_ready.load(Ordering::Acquire) {
        if let Err(st) = query_props_sync(&dev).await {
            return DriverStep::complete(st);
        }
    }

    let bs = dx.block_size.load(Ordering::Acquire) as u64;
    if bs == 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let data_too_small = {
        let p = req.read();
        p.data_len() < total
    };
    if data_too_small {
        return DriverStep::complete(DriverStatus::InsufficientResources);
    }

    let aligned = (off % bs == 0) && ((total as u64) % bs == 0);
    if !aligned {
        {
            let mut p = req.write();
            p.status = DriverStatus::InvalidParameter;
        }
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    if !write_through {
        // Write-back: update cache immediately and complete without hitting the disk.
        {
            let p = req.read();
            let data = &p.data_slice()[..total];
            cache_update_write(&dx, off, data, true);
        }

        {
            let mut p = req.write();
            p.status = DriverStatus::Success;
        }
        return DriverStep::complete(DriverStatus::Success);
    }

    {
        let mut p = req.write();
        let ctx = Box::new(DiskWriteCtx {
            dev: dev.clone(),
            offset: off,
            len: total,
            write_through,
        });
        p.add_completion(disk_write_complete, Box::into_raw(ctx) as usize);
        p.traversal_policy = TraversalPolicy::ForwardLower;
    }
    DriverStep::Continue
}

#[request_handler]
pub async fn disk_ioctl<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let code = match {
        let g = req.read();
        g.kind
    } {
        RequestType::DeviceControl(c) => c,
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    match code {
        IOCTL_DRIVE_IDENTIFY => {
            let mut ch = RequestHandle::new_pnp(
                PnpRequest {
                    minor_function: PnpMinorFunction::QueryResources,
                    relation: DeviceRelationType::TargetDeviceRelation,
                    id_type: QueryIdType::CompatibleIds,
                    ids_out: alloc::vec::Vec::new(),
                    data_out: RequestData::empty(),
                },
                RequestData::empty(),
            );

            let st = pnp_forward_request_to_next_lower(dev, &mut ch).await;
            if st != DriverStatus::Success {
                return DriverStep::complete(st);
            }
            // todo: properly handle the none case
            let info = if let Some(di) = ch
                .read()
                .pnp
                .as_ref()
                .and_then(|p| p.data_out.view::<DiskInfo>())
            {
                *di
            } else {
                return DriverStep::complete(DriverStatus::Unsuccessful);
            };

            let status = {
                let mut w = req.write();
                w.set_data_t::<DiskInfo>(info);
                DriverStatus::Success
            };
            DriverStep::complete(status)
        }
        IOCTL_BLOCK_FLUSH => {
            let dx = disk_ext(&dev);

            let mut handle = RequestHandle::new(
                RequestType::DeviceControl(IOCTL_BLOCK_FLUSH),
                RequestData::empty(),
            );
            handle.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_forward_request_to_next_lower(dev.clone(), &mut handle).await;
            if status == DriverStatus::Success {
                cache_clear(&dx);
            }
            DriverStep::complete(status)
        }
        _ => DriverStep::complete(DriverStatus::NotImplemented),
    }
}

#[inline]
pub fn disk_ext<'a>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, DiskExt> {
    dev.try_devext::<DiskExt>().expect("disk dev ext missing")
}

async fn read_from_lower(
    dev: &Arc<DeviceObject>,
    offset: u64,
    len: usize,
) -> Result<Box<[u8]>, DriverStatus> {
    let mut child = RequestHandle::new(
        RequestType::Read { offset, len },
        RequestData::from_boxed_bytes(vec![0u8; len].into_boxed_slice()),
    );
    child.set_traversal_policy(TraversalPolicy::ForwardLower);

    let st = pnp_forward_request_to_next_lower(dev.clone(), &mut child).await;
    if st != DriverStatus::Success {
        return Err(st);
    }
    {
        let status = child.read().status;
        if status != DriverStatus::Success {
            return Err(status);
        }
    }
    Ok(child.write().take_data_bytes())
}

/// Flush all dirty cached blocks to the lower device. Not invoked automatically.
pub async fn flush_dirty_blocks(dev: &Arc<DeviceObject>) -> DriverStatus {
    let dx = disk_ext(dev);
    if !dx.props_ready.load(Ordering::Acquire) {
        if let Err(st) = query_props_sync(dev).await {
            return st;
        }
    }

    let bs = dx.block_size.load(Ordering::Acquire);
    if bs == 0 {
        return DriverStatus::InvalidParameter;
    }

    let dirty = {
        let mut cache = dx.cache.lock();
        if !cache.ensure_init(bs) {
            return DriverStatus::InvalidParameter;
        }
        cache.take_dirty_segments()
    };

    if dirty.is_empty() {
        return DriverStatus::Success;
    }

    for (_block_idx, _mask, _block_len, segments) in dirty.iter() {
        for (offset, data) in segments {
            let st = write_to_lower(dev, *offset, data, true).await;
            if st != DriverStatus::Success {
                return st;
            }
        }
    }

    {
        let mut cache = dx.cache.lock();
        if cache.ensure_init(bs) {
            for (block_idx, mask, _block_len, _segments) in dirty {
                cache.clear_dirty_mask(block_idx, mask);
            }
        }
    }

    DriverStatus::Success
}

async fn write_to_lower(
    dev: &Arc<DeviceObject>,
    offset: u64,
    data: &[u8],
    flush_write_through: bool,
) -> DriverStatus {
    let mut child = RequestHandle::new(
        RequestType::Write {
            offset,
            len: data.len(),
            flush_write_through,
        },
        RequestData::from_boxed_bytes(data.to_vec().into_boxed_slice()),
    );
    child.set_traversal_policy(TraversalPolicy::ForwardLower);
    let st = pnp_forward_request_to_next_lower(dev.clone(), &mut child).await;
    if st != DriverStatus::Success {
        return st;
    }
    child.read().status
}

async fn query_props_sync(dev: &Arc<DeviceObject>) -> Result<(), DriverStatus> {
    let mut ch = RequestHandle::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
        RequestData::empty(),
    );
    let st = pnp_forward_request_to_next_lower(dev.clone(), &mut ch).await;

    if st != DriverStatus::Success {
        return Err(st);
    }
    {
        let status = ch.read().status;
        if status != DriverStatus::Success {
            return Err(status);
        }
    }

    let di = {
        let req = ch.read();
        if let Some(di) = req.pnp.as_ref().and_then(|p| p.data_out.view::<DiskInfo>()) {
            *di
        } else {
            let Some(pnp) = req.pnp.as_ref() else {
                return Err(DriverStatus::Unsuccessful);
            };
            let blob = pnp.data_out.as_slice();
            if blob.len() < size_of::<DiskInfo>() {
                return Err(DriverStatus::Unsuccessful);
            }
            unsafe { *(blob.as_ptr() as *const DiskInfo) }
        }
    };

    let dx = disk_ext(dev);
    dx.block_size
        .store(di.logical_block_size.max(1), Ordering::Release);
    dx.props_ready.store(true, Ordering::Release);

    {
        let mut cache = dx.cache.lock();
        cache.ensure_init(di.logical_block_size.max(1));
    }

    Ok(())
}
