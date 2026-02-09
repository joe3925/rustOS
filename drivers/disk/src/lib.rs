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
use kernel_api::println;
use spin::{Mutex, RwLock};

use kernel_api::{
    RequestExt,
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        io::{DiskInfo, IoType, Synchronization},
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, PnpMinorFunction, PnpRequest, QueryIdType, driver_set_evt_device_add,
        pnp_forward_request_to_next_lower,
    },
    request::{Request, RequestType, TraversalPolicy},
    request_handler,
    status::DriverStatus,
};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[panic_handler]
#[cfg(not(test))]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        use kernel_api::util::panic_common;
        panic_common(MOD_NAME, info)
    }
}

#[inline]
fn take_req(r: &Arc<RwLock<Request>>) -> Request {
    let mut g = r.write();
    core::mem::replace(&mut *g, Request::empty())
}

#[inline]
fn put_req(r: &Arc<RwLock<Request>>, req: Request) {
    let mut g = r.write();
    *g = req;
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;
const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;

const CACHE_BYTES: usize = 20 * 1024 * 1024usize;
const MAX_CHUNK_BYTES: usize = 256 * 1024usize;

/// Cache block size - cache in 4KB chunks instead of individual sectors
const CACHE_BLOCK_SIZE: usize = 4096;
/// Number of cache blocks we can hold
const CACHE_BLOCK_COUNT: usize = CACHE_BYTES / CACHE_BLOCK_SIZE;

/// Per-disk sector cache using 4KB blocks for efficiency.
/// Uses HashMap for O(1) lookups and buffer reuse to avoid allocations.
struct SectorCache {
    sector_size: usize,
    /// Map from cache-block-aligned offset to cached data
    map: HashMap<u64, Box<[u8; CACHE_BLOCK_SIZE]>>,
    /// FIFO eviction order (stores cache block offsets)
    order: VecDeque<u64>,
    /// Pool of reusable buffers from evicted entries
    free_buffers: Vec<Box<[u8; CACHE_BLOCK_SIZE]>>,
}

impl Default for SectorCache {
    fn default() -> Self {
        Self {
            sector_size: 0,
            map: HashMap::with_capacity(CACHE_BLOCK_COUNT),
            order: VecDeque::with_capacity(CACHE_BLOCK_COUNT),
            free_buffers: Vec::with_capacity(64),
        }
    }
}

impl SectorCache {
    fn ensure_init(&mut self, block_size: u32) {
        if self.sector_size != 0 {
            return;
        }
        let bs = block_size as usize;
        if bs == 0 {
            return;
        }
        self.sector_size = bs;
    }

    fn clear(&mut self) {
        // Move all buffers to free pool for reuse
        for (_, buf) in self.map.drain() {
            if self.free_buffers.len() < 128 {
                self.free_buffers.push(buf);
            }
        }
        self.order.clear();
    }

    /// Get or allocate a cache buffer, reusing from pool when possible
    #[inline]
    fn get_buffer(&mut self) -> Box<[u8; CACHE_BLOCK_SIZE]> {
        self.free_buffers
            .pop()
            .unwrap_or_else(|| Box::new([0u8; CACHE_BLOCK_SIZE]))
    }

    /// Align offset down to cache block boundary
    #[inline]
    const fn align_down(offset: u64) -> u64 {
        offset & !(CACHE_BLOCK_SIZE as u64 - 1)
    }

    /// Insert or update a cache block
    fn insert_block(&mut self, block_offset: u64, src: &[u8]) {
        debug_assert_eq!(block_offset % CACHE_BLOCK_SIZE as u64, 0);
        debug_assert!(src.len() <= CACHE_BLOCK_SIZE);

        // Update existing block in-place
        if let Some(existing) = self.map.get_mut(&block_offset) {
            existing[..src.len()].copy_from_slice(src);
            return;
        }

        // Evict oldest if at capacity, reusing its buffer
        let buf = if self.map.len() >= CACHE_BLOCK_COUNT {
            if let Some(old_offset) = self.order.pop_front() {
                self.map
                    .remove(&old_offset)
                    .unwrap_or_else(|| self.get_buffer())
            } else {
                self.get_buffer()
            }
        } else {
            self.get_buffer()
        };

        let mut buf = buf;
        buf[..src.len()].copy_from_slice(src);
        if src.len() < CACHE_BLOCK_SIZE {
            buf[src.len()..].fill(0);
        }
        self.map.insert(block_offset, buf);
        self.order.push_back(block_offset);
    }

    fn try_read_full(
        &mut self,
        offset: u64,
        total: usize,
        dst: &mut [u8],
        block_size: u32,
    ) -> bool {
        if self.sector_size == 0 || block_size == 0 || total == 0 {
            return false;
        }

        let bs = block_size as u64;
        if (total as u64) % bs != 0 || offset % bs != 0 {
            return false;
        }

        // Check all required cache blocks are present
        let end = offset + total as u64;
        let mut check_off = Self::align_down(offset);
        while check_off < end {
            if !self.map.contains_key(&check_off) {
                return false;
            }
            check_off += CACHE_BLOCK_SIZE as u64;
        }

        // Copy data from cache blocks
        let mut dst_off = 0usize;
        let mut cur_off = offset;
        while dst_off < total {
            let block_off = Self::align_down(cur_off);
            let block = match self.map.get(&block_off) {
                Some(b) => b,
                None => return false,
            };

            let offset_in_block = (cur_off - block_off) as usize;
            let remaining_in_block = CACHE_BLOCK_SIZE - offset_in_block;
            let remaining_to_read = total - dst_off;
            let copy_len = remaining_in_block.min(remaining_to_read);

            dst[dst_off..dst_off + copy_len]
                .copy_from_slice(&block[offset_in_block..offset_in_block + copy_len]);

            dst_off += copy_len;
            cur_off += copy_len as u64;
        }

        true
    }

    fn store_range(&mut self, offset: u64, data: &[u8], block_size: u32) {
        if block_size == 0 || self.sector_size == 0 || data.is_empty() {
            return;
        }

        let bs = block_size as u64;
        if (data.len() as u64) % bs != 0 || offset % bs != 0 {
            return;
        }

        let mut src_off = 0usize;
        let mut cur_off = offset;
        let end = offset + data.len() as u64;

        while cur_off < end {
            let block_off = Self::align_down(cur_off);
            let offset_in_block = (cur_off - block_off) as usize;
            let remaining_in_block = CACHE_BLOCK_SIZE - offset_in_block;
            let remaining_data = data.len() - src_off;
            let copy_len = remaining_in_block.min(remaining_data);

            // Only cache complete blocks to avoid partial data issues
            if offset_in_block == 0 && copy_len == CACHE_BLOCK_SIZE {
                // Full block - insert directly
                self.insert_block(block_off, &data[src_off..src_off + CACHE_BLOCK_SIZE]);
            } else if let Some(existing) = self.map.get_mut(&block_off) {
                // Partial update to existing block
                existing[offset_in_block..offset_in_block + copy_len]
                    .copy_from_slice(&data[src_off..src_off + copy_len]);
            }
            // Skip partial blocks that aren't already cached

            src_off += copy_len;
            cur_off += copy_len as u64;
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
fn cache_try_read(dx: &DiskExt, off: u64, total: usize, dst: &mut [u8]) -> bool {
    let bs = dx.block_size.load(Ordering::Acquire);
    if bs == 0 {
        return false;
    }

    let mut cache = dx.cache.lock();
    cache.ensure_init(bs);
    cache.try_read_full(off, total, dst, bs)
}

#[inline]
fn cache_store_read(dx: &DiskExt, off: u64, data: &[u8]) {
    let bs = dx.block_size.load(Ordering::Acquire);
    if bs == 0 {
        return;
    }

    let mut cache = dx.cache.lock();
    cache.ensure_init(bs);
    cache.store_range(off, data, bs);
}

#[inline]
fn cache_update_write(dx: &DiskExt, off: u64, data: &[u8]) {
    cache_store_read(dx, off, data);
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
}

extern "win64" fn disk_read_complete(req: &mut Request, ctx: usize) -> DriverStatus {
    let boxed = unsafe { Box::from_raw(ctx as *mut DiskReadCtx) };
    let st = req.status;
    if st == DriverStatus::Success {
        let dx = disk_ext(&boxed.dev);
        let n = core::cmp::min(boxed.len, req.data_len());
        if n != 0 {
            cache_store_read(&dx, boxed.offset, &req.data_slice()[..n]);
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
            cache_update_write(&dx, boxed.offset, &req.data_slice()[..n]);
        }
    }
    st
}

#[request_handler]
pub async fn disk_read(
    dev: Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let (off, total) = {
        let g = parent.read();
        match g.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
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

    {
        let p = parent.read();
        if p.data_len() < total {
            return DriverStep::complete(DriverStatus::InsufficientResources);
        }
    }

    let aligned = (off % bs == 0) && ((total as u64) % bs == 0);
    if !aligned {
        let mut p = parent.write();
        p.status = DriverStatus::InvalidParameter;
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let mut p = parent.write();
    let n = core::cmp::min(total, p.data_len());
    if n != 0 && cache_try_read(&dx, off, n, &mut p.data_slice_mut()[..n]) {
        p.status = DriverStatus::Success;
        return DriverStep::complete(DriverStatus::Success);
    }

    let ctx = Box::new(DiskReadCtx {
        dev: dev.clone(),
        offset: off,
        len: total,
    });
    p.add_completion(disk_read_complete, Box::into_raw(ctx) as usize);
    p.traversal_policy = TraversalPolicy::ForwardLower;
    DriverStep::Continue
}

#[request_handler]
pub async fn disk_write(
    dev: Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let (off, total) = {
        let g = parent.read();
        match g.kind {
            RequestType::Write { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
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

    {
        let p = parent.read();
        if p.data_len() < total {
            return DriverStep::complete(DriverStatus::InsufficientResources);
        }
    }

    let aligned = (off % bs == 0) && ((total as u64) % bs == 0);
    if !aligned {
        let mut p = parent.write();
        p.status = DriverStatus::InvalidParameter;
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let mut p = parent.write();
    let ctx = Box::new(DiskWriteCtx {
        dev: dev.clone(),
        offset: off,
        len: total,
    });
    p.add_completion(disk_write_complete, Box::into_raw(ctx) as usize);
    p.traversal_policy = TraversalPolicy::ForwardLower;
    DriverStep::Continue
}

#[request_handler]
pub async fn disk_ioctl(dev: Arc<DeviceObject>, parent: Arc<RwLock<Request>>) -> DriverStep {
    let code = match parent.read().kind {
        RequestType::DeviceControl(c) => c,
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    match code {
        IOCTL_DRIVE_IDENTIFY => {
            let mut ch = Request::new_pnp(
                PnpRequest {
                    minor_function: PnpMinorFunction::QueryResources,
                    relation: DeviceRelationType::TargetDeviceRelation,
                    id_type: QueryIdType::CompatibleIds,
                    ids_out: alloc::vec::Vec::new(),
                    blob_out: alloc::vec::Vec::new(),
                },
                RequestData::empty(),
            );

            if let Some(pnp) = ch.pnp.as_mut() {
                pnp.relation = DeviceRelationType::TargetDeviceRelation;
                pnp.id_type = QueryIdType::CompatibleIds;
            }

            let ch = Arc::new(RwLock::new(ch));

            pnp_forward_request_to_next_lower(dev, ch.clone()).await;

            let blob = {
                let r = ch.read();
                r.pnp
                    .as_ref()
                    .map(|p| p.blob_out.clone())
                    .unwrap_or_default()
            };

            let mut w = parent.write();
            w.set_data_bytes(blob.into_boxed_slice());
            DriverStep::complete(DriverStatus::Success)
        }
        IOCTL_BLOCK_FLUSH => {
            let dx = disk_ext(&dev);

            let mut req_child = Request::new(
                RequestType::DeviceControl(IOCTL_BLOCK_FLUSH),
                RequestData::empty(),
            );
            req_child.traversal_policy = TraversalPolicy::ForwardLower;
            let child = Arc::new(RwLock::new(req_child));

            let status = pnp_forward_request_to_next_lower(dev.clone(), child.clone()).await;
            if status != DriverStatus::Success {
                return DriverStep::complete(status);
            }
            let st = child.read().status;
            if st == DriverStatus::Success {
                cache_clear(&dx);
            }
            DriverStep::complete(st)
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
    let child = Arc::new(RwLock::new(
        Request::new(
            RequestType::Read { offset, len },
            RequestData::from_boxed_bytes(vec![0u8; len].into_boxed_slice()),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower),
    ));
    let st = pnp_forward_request_to_next_lower(dev.clone(), child.clone()).await;
    if st != DriverStatus::Success {
        return Err(st);
    }
    let mut g = child.write();
    if g.status != DriverStatus::Success {
        return Err(g.status);
    }
    Ok(g.take_data_bytes())
}

async fn write_to_lower(dev: &Arc<DeviceObject>, offset: u64, data: &[u8]) -> DriverStatus {
    let child = Arc::new(RwLock::new(
        Request::new(
            RequestType::Write {
                offset,
                len: data.len(),
            },
            RequestData::from_boxed_bytes(data.to_vec().into_boxed_slice()),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower),
    ));
    let st = pnp_forward_request_to_next_lower(dev.clone(), child.clone()).await;
    if st != DriverStatus::Success {
        return st;
    }
    child.read().status
}

async fn query_props_sync(dev: &Arc<DeviceObject>) -> Result<(), DriverStatus> {
    let mut ch = Request::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        },
        RequestData::empty(),
    );
    let ch = Arc::new(RwLock::new(ch));

    pnp_forward_request_to_next_lower(dev.clone(), ch.clone()).await;

    let c = ch.read();
    if c.status != DriverStatus::Success {
        return Err(c.status);
    }

    let pnp = match c.pnp.as_ref() {
        Some(p) => p,
        None => return Err(DriverStatus::Unsuccessful),
    };

    if pnp.blob_out.len() < size_of::<DiskInfo>() {
        return Err(DriverStatus::Unsuccessful);
    }

    let di = unsafe { *(pnp.blob_out.as_ptr() as *const DiskInfo) };

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
