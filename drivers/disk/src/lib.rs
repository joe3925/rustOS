#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    mem::size_of,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, AtomicU32},
};
use kernel_api::pnp::DriverStep;
use spin::{Mutex, RwLock};

use kernel_api::{
    RequestExt,
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::io::{DiskInfo, IoType, Synchronization},
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

/// Simple per-disk sector cache (~20 MiB worth of sectors).
struct SectorCache {
    sector_size: usize,
    capacity_sectors: usize,
    map: BTreeMap<u64, Box<[u8]>>,
    order: Vec<u64>, // FIFO approximate eviction
}

impl Default for SectorCache {
    fn default() -> Self {
        Self {
            sector_size: 0,
            capacity_sectors: 0,
            map: BTreeMap::new(),
            order: Vec::new(),
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

        let bytes = 20 * 1024 * 1024usize;
        let cap = (bytes / bs).max(1);
        self.capacity_sectors = cap;
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    fn insert_sector(&mut self, lba: u64, src: &[u8]) {
        if self.sector_size == 0 {
            return;
        }
        if src.len() < self.sector_size {
            return;
        }

        if !self.map.contains_key(&lba)
            && self.capacity_sectors != 0
            && self.map.len() == self.capacity_sectors
        {
            if let Some(old_lba) = self.order.first().cloned() {
                self.map.remove(&old_lba);
                self.order.remove(0);
            }
        }

        let mut buf = vec![0u8; self.sector_size].into_boxed_slice();
        buf.copy_from_slice(&src[..self.sector_size]);

        if !self.map.contains_key(&lba) {
            self.order.push(lba);
        }
        self.map.insert(lba, buf);
    }

    fn try_read_full(
        &mut self,
        offset: u64,
        total: usize,
        dst: &mut [u8],
        block_size: u32,
    ) -> bool {
        if self.sector_size == 0 || block_size == 0 {
            return false;
        }

        let bs = block_size as u64;
        if (total as u64) % bs != 0 {
            return false;
        }
        if self.sector_size != block_size as usize {
            self.clear();
            self.sector_size = block_size as usize;
            let bytes = 20 * 1024 * 1024usize;
            self.capacity_sectors = (bytes / self.sector_size).max(1);
        }

        let start_sector = offset / bs;
        let num_sectors = (total as u64) / bs;

        for i in 0..num_sectors {
            if !self.map.contains_key(&(start_sector + i)) {
                return false;
            }
        }

        let mut out_off = 0usize;
        for i in 0..num_sectors {
            let lba = start_sector + i;
            let buf = match self.map.get(&lba) {
                Some(b) => b,
                None => return false,
            };
            let remaining = dst.len().saturating_sub(out_off);
            if remaining < buf.len() {
                return false;
            }
            dst[out_off..out_off + buf.len()].copy_from_slice(buf);
            out_off += buf.len();
        }

        true
    }

    fn store_range(&mut self, offset: u64, data: &[u8], block_size: u32) {
        if block_size == 0 || self.sector_size == 0 {
            return;
        }

        let bs = block_size as u64;
        if (data.len() as u64) % bs != 0 {
            return;
        }

        let start_sector = offset / bs;
        let num_sectors = (data.len() as u64) / bs;
        let mut src_off = 0usize;

        for i in 0..num_sectors {
            let lba = start_sector + i;
            if src_off + self.sector_size > data.len() {
                break;
            }
            self.insert_sector(lba, &data[src_off..src_off + self.sector_size]);
            src_off += self.sector_size;
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct DiskExt {
    block_size: AtomicU32,
    props_ready: AtomicBool,
    cache: Mutex<SectorCache>,
}

#[inline]
fn cache_try_read(dx: &DiskExt, off: u64, total: usize, dst: &mut [u8]) -> bool {
    let bs = dx.block_size.load(core::sync::atomic::Ordering::Acquire);
    if bs == 0 {
        return false;
    }

    let mut cache = dx.cache.lock();
    cache.ensure_init(bs);
    cache.try_read_full(off, total, dst, bs)
}

#[inline]
fn cache_store_read(dx: &DiskExt, off: u64, data: &[u8]) {
    let bs = dx.block_size.load(core::sync::atomic::Ordering::Acquire);
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
        let n = core::cmp::min(boxed.len, req.data.len());
        if n != 0 {
            cache_store_read(&dx, boxed.offset, &req.data[..n]);
        }
    }
    st
}

extern "win64" fn disk_write_complete(req: &mut Request, ctx: usize) -> DriverStatus {
    let boxed = unsafe { Box::from_raw(ctx as *mut DiskWriteCtx) };
    let st = req.status;
    if st == DriverStatus::Success {
        let dx = disk_ext(&boxed.dev);
        let n = core::cmp::min(boxed.len, req.data.len());
        if n != 0 {
            cache_update_write(&dx, boxed.offset, &req.data[..n]);
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
            _ => {
                drop(g);
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        }
    };

    if total == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let dx = disk_ext(&dev);
    if !dx.props_ready.load(core::sync::atomic::Ordering::Acquire) {
        if let Err(st) = query_props_sync(&dev).await {
            return DriverStep::complete(st);
        }
    }

    if !rw_validate(&dx, off, total) {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    {
        let mut p = parent.write();
        let n = core::cmp::min(total, p.data.len());
        if n != 0 && cache_try_read(&dx, off, n, &mut p.data[..n]) {
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
    }

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
            _ => {
                drop(g);
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        }
    };

    if total == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let dx = disk_ext(&dev);
    if !dx.props_ready.load(core::sync::atomic::Ordering::Acquire) {
        if let Err(st) = query_props_sync(&dev).await {
            return DriverStep::complete(st);
        }
    }

    if !rw_validate(&dx, off, total) {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    {
        let mut p = parent.write();
        let ctx = Box::new(DiskWriteCtx {
            dev: dev.clone(),
            offset: off,
            len: total,
        });
        p.add_completion(disk_write_complete, Box::into_raw(ctx) as usize);
        p.traversal_policy = TraversalPolicy::ForwardLower;
    }

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
                Box::new([]),
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
            w.data = blob.into_boxed_slice();
            DriverStep::complete(DriverStatus::Success)
        }
        IOCTL_BLOCK_FLUSH => {
            let dx = disk_ext(&dev);

            let mut req_child =
                Request::new(RequestType::DeviceControl(IOCTL_BLOCK_FLUSH), Box::new([]));
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

#[inline]
fn rw_validate(dx: &DiskExt, off: u64, total: usize) -> bool {
    let bs = dx.block_size.load(core::sync::atomic::Ordering::Acquire) as u64;
    if bs == 0 {
        return false;
    }
    if off % bs != 0 {
        return false;
    }
    if (total as u64) % bs != 0 {
        return false;
    }
    true
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
        Box::new([]),
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
    dx.block_size.store(
        di.logical_block_size.max(1),
        core::sync::atomic::Ordering::Release,
    );
    dx.props_ready
        .store(true, core::sync::atomic::Ordering::Release);

    {
        let mut cache = dx.cache.lock();
        cache.ensure_init(di.logical_block_size.max(1));
    }

    Ok(())
}
