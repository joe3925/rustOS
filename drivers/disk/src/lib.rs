#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    mem::size_of,
    panic::PanicInfo,
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64},
};
use spin::RwLock;

use kernel_api::{
    DevExtRef, DevExtRefMut, DeviceObject, DeviceRelationType, DiskInfo, DriverObject,
    DriverStatus, KernelAllocator, PnpMinorFunction, QueryIdType, Request, RequestType,
    TraversalPolicy,
    alloc_api::{
        DeviceInit, IoType, Synchronization,
        ffi::{
            driver_set_evt_device_add, pnp_complete_request, pnp_forward_request_to_next_lower,
            pnp_wait_for_request,
        },
    },
    println,
};

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
mod msvc_shims;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());
#[panic_handler]
#[cfg(not(test))]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::alloc_api::ffi::panic_common;

    unsafe { panic_common(MOD_NAME, info) }
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

const IOCTL_BLOCK_QUERY: u32 = 0xB000_0001;
const IOCTL_BLOCK_RW: u32 = 0xB000_0002;
const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;

const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;

const BLOCK_RW_READ: u32 = 0;
const BLOCK_RW_WRITE: u32 = 1;

bitflags::bitflags! {
    #[repr(transparent)]
    struct BlockFeat: u64 {
        const FLUSH   = 1 << 0;
        const DISCARD = 1 << 1;
        const FUA     = 1 << 2;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BlockQueryOut {
    block_size: u32,
    max_blocks: u32,
    alignment_mask: u32,
    features: u64,
}

#[repr(C)]
struct BlockRwIn {
    op: u32,
    _rsvd: u32,
    lba: u64,
    blocks: u32,
    buf_off: u32,
}

#[repr(C)]
#[derive(Default)]
struct DiskExt {
    block_size: AtomicU32,
    max_blocks: AtomicU32,
    alignment_mask: AtomicU32,
    features: AtomicU64,
    props_ready: AtomicBool,
}

#[repr(C)]
struct RwChainCtx {
    dev: Arc<DeviceObject>,
    parent_req: Arc<RwLock<Request>>,
    lba: u64,
    remaining_bytes: usize,
    parent_buf_off: usize,
    is_write: bool,
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, disk_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn disk_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
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
    DriverStatus::Success
}

pub extern "win64" fn disk_read(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStatus {
    let (off, total) = {
        let g = parent.read();
        match g.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => {
                drop(g);
                return DriverStatus::InvalidParameter;
            }
        }
    };
    if total == 0 {
        return DriverStatus::Success;
    }

    let dx = disk_ext(dev);
    if !dx.props_ready.load(core::sync::atomic::Ordering::Acquire) {
        if let Err(st) = query_props_sync(dev) {
            return st;
        }
    }
    if !rw_validate(&dx, off, total) {
        return DriverStatus::InvalidParameter;
    }

    let bs_u32 = dx.block_size.load(core::sync::atomic::Ordering::Acquire);
    let bs = bs_u32 as usize;
    let mut remaining = total;
    let mut lba = (off / bs_u32 as u64) as u64;
    let mut parent_off = 0usize;

    while remaining > 0 {
        let max_blocks = dx
            .max_blocks
            .load(core::sync::atomic::Ordering::Acquire)
            .max(1);
        let max_bytes = (max_blocks as usize).saturating_mul(bs).max(bs);
        let this_bytes = core::cmp::min(remaining, max_bytes);
        let this_blocks = (this_bytes / bs) as u32;

        let hdr_len = core::mem::size_of::<BlockRwIn>();
        let mut buf = alloc::vec![0u8; hdr_len + this_bytes].into_boxed_slice();

        let hdr = BlockRwIn {
            op: BLOCK_RW_READ,
            _rsvd: 0,
            lba,
            blocks: this_blocks,
            buf_off: hdr_len as u32,
        };
        unsafe { core::ptr::write_unaligned(buf.as_mut_ptr() as *mut BlockRwIn, hdr) }
        let mut req_child = Request::new(RequestType::DeviceControl(IOCTL_BLOCK_RW), buf);
        req_child.traversal_policy = TraversalPolicy::ForwardLower;
        let child = Arc::new(RwLock::new(req_child));
        let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
        if st == DriverStatus::NoSuchDevice {
            return st;
        }
        unsafe { pnp_wait_for_request(&child) };

        let c = child.read();
        if c.status != DriverStatus::Success {
            return c.status;
        }
        let data = &c.data;
        if data.len() < hdr_len {
            return DriverStatus::Unsuccessful;
        }
        let payload = &data[hdr_len..];
        if payload.is_empty() {
            return DriverStatus::Unsuccessful;
        }

        let moved = core::cmp::min(payload.len(), remaining);
        {
            let mut p = parent.write();
            let dst = &mut p.data[parent_off..parent_off + moved];
            let src = &payload[..moved];
            dst.copy_from_slice(src);
        }

        remaining -= moved;
        parent_off += moved;
        lba += (moved / bs) as u64;
    }

    return DriverStatus::Success;
}

pub extern "win64" fn disk_write(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStatus {
    let (off, total) = {
        let g = parent.read();
        match g.kind {
            RequestType::Write { offset, len } => (offset, len),
            _ => {
                drop(g);
                return DriverStatus::InvalidParameter;
            }
        }
    };
    if total == 0 {
        return DriverStatus::Success;
    }

    let dx = disk_ext(dev);
    if !dx.props_ready.load(core::sync::atomic::Ordering::Acquire) {
        if let Err(st) = query_props_sync(dev) {
            return st;
        }
    }
    if !rw_validate(&dx, off, total) {
        return DriverStatus::InvalidParameter;
    }

    let bs_u32 = dx.block_size.load(core::sync::atomic::Ordering::Acquire);
    let bs = bs_u32 as usize;
    let mut remaining = total;
    let mut lba = (off / bs_u32 as u64) as u64;
    let mut parent_off = 0usize;

    while remaining > 0 {
        let max_blocks = dx
            .max_blocks
            .load(core::sync::atomic::Ordering::Acquire)
            .max(1);
        let max_bytes = (max_blocks as usize).saturating_mul(bs).max(bs);
        let this_bytes = core::cmp::min(remaining, max_bytes);
        let this_blocks = (this_bytes / bs) as u32;

        let hdr_len = core::mem::size_of::<BlockRwIn>();
        let mut buf = alloc::vec![0u8; hdr_len + this_bytes].into_boxed_slice();

        let hdr = BlockRwIn {
            op: BLOCK_RW_WRITE,
            _rsvd: 0,
            lba,
            blocks: this_blocks,
            buf_off: hdr_len as u32,
        };
        unsafe { core::ptr::write_unaligned(buf.as_mut_ptr() as *mut BlockRwIn, hdr) }

        {
            let p = parent.read();
            let src = &p.data[parent_off..parent_off + this_bytes];
            buf[hdr_len..hdr_len + this_bytes].copy_from_slice(src);
        }
        let mut req_child = Request::new(RequestType::DeviceControl(IOCTL_BLOCK_RW), buf);
        req_child.traversal_policy = TraversalPolicy::ForwardLower;
        let child = Arc::new(RwLock::new(req_child));

        let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
        if st == DriverStatus::NoSuchDevice {
            return st;
        }
        unsafe { pnp_wait_for_request(&child) };

        let c = child.read();
        if c.status != DriverStatus::Success {
            return c.status;
        }

        remaining -= this_bytes;
        parent_off += this_bytes;
        lba += (this_bytes / bs) as u64;
    }

    return DriverStatus::Success;
}

pub extern "win64" fn disk_ioctl(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
) -> DriverStatus {
    let code = match parent.read().kind {
        RequestType::DeviceControl(c) => c,
        _ => return DriverStatus::InvalidParameter,
    };

    match code {
        IOCTL_DRIVE_IDENTIFY => {
            let mut ch = Request::new_pnp(
                kernel_api::alloc_api::PnpRequest {
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

            unsafe { pnp_forward_request_to_next_lower(dev, ch.clone()) };
            unsafe { pnp_wait_for_request(&ch) };

            let blob = {
                let r = ch.read();
                r.pnp
                    .as_ref()
                    .map(|p| p.blob_out.clone())
                    .unwrap_or_default()
            };
            let mut w = parent.write();
            w.data = blob.into_boxed_slice();
            DriverStatus::Success
        }
        IOCTL_BLOCK_FLUSH => {
            let mut req_child =
                Request::new(RequestType::DeviceControl(IOCTL_BLOCK_FLUSH), Box::new([]));
            req_child.traversal_policy = TraversalPolicy::ForwardLower;
            let child = Arc::new(RwLock::new(req_child));

            let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
            if st == DriverStatus::NoSuchDevice {
                return DriverStatus::NoSuchDevice;
            }

            unsafe { pnp_wait_for_request(&child) };
            child.read().status
        }
        _ => DriverStatus::NotImplemented,
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
fn query_props_sync(dev: &Arc<DeviceObject>) -> Result<(), DriverStatus> {
    let out_len = core::mem::size_of::<BlockQueryOut>();
    let buf = alloc::vec![0u8; out_len].into_boxed_slice();

    let child = Arc::new(RwLock::new(
        Request::new(RequestType::DeviceControl(IOCTL_BLOCK_QUERY), buf)
            .set_traversal_policy(TraversalPolicy::ForwardLower),
    ));
    let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
    if st == DriverStatus::NoSuchDevice {
        return Err(DriverStatus::NoSuchDevice);
    }
    unsafe { pnp_wait_for_request(&child) };

    let c = child.read();
    if c.status != DriverStatus::Success || c.data.len() < core::mem::size_of::<BlockQueryOut>() {
        return Err(if c.status == DriverStatus::Success {
            DriverStatus::Unsuccessful
        } else {
            c.status
        });
    }

    let qo = unsafe { *(c.data.as_ptr() as *const BlockQueryOut) };
    let dx = disk_ext(dev);
    dx.block_size
        .store(qo.block_size.max(1), core::sync::atomic::Ordering::Release);
    dx.max_blocks
        .store(qo.max_blocks.max(1), core::sync::atomic::Ordering::Release);
    dx.alignment_mask
        .store(qo.alignment_mask, core::sync::atomic::Ordering::Release);
    dx.features
        .store(qo.features, core::sync::atomic::Ordering::Release);
    dx.props_ready
        .store(true, core::sync::atomic::Ordering::Release);
    Ok(())
}

extern "win64" fn disk_on_flush_done(child: &mut Request, ctx: usize) {
    let parent_arc: Arc<RwLock<Request>> =
        *unsafe { Box::from_raw(ctx as *mut Arc<RwLock<Request>>) };
    parent_arc.write().status = child.status;
    unsafe { pnp_complete_request(&parent_arc) };
}
