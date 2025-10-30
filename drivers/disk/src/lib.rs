#![no_std]
#![no_main]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{mem::size_of, panic::PanicInfo, ptr};
use spin::RwLock;

use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request, RequestType,
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

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
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
struct DiskExt {
    block_size: u32,
    max_blocks: u32,
    alignment_mask: u32,
    features: u64,
    props_ready: bool,
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
    dev_init.dev_ext_size = size_of::<DiskExt>();
    DriverStatus::Success
}

pub extern "win64" fn disk_read(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    let (off, total) = {
        let g = parent.read();
        match g.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => {
                drop(g);
                parent.write().status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };
    if total == 0 {
        parent.write().status = DriverStatus::Success;
        return;
    }

    let dx = disk_ext_mut(dev);
    if !dx.props_ready {
        if let Err(st) = query_props_sync(dev) {
            parent.write().status = st;
            return;
        }
    }
    if !rw_validate(dx, off, total) {
        parent.write().status = DriverStatus::InvalidParameter;
        return;
    }

    let bs = dx.block_size as usize;
    let mut remaining = total;
    let mut lba = (off / dx.block_size as u64) as u64;
    let mut parent_off = 0usize;

    while remaining > 0 {
        let max_bytes = (dx.max_blocks as usize).saturating_mul(bs).max(bs);
        let this_bytes = core::cmp::min(remaining, max_bytes);
        let this_blocks = (this_bytes / bs) as u32;

        let hdr_len = core::mem::size_of::<BlockRwIn>();
        let mut buf = vec![0u8; hdr_len + this_bytes].into_boxed_slice();

        let hdr = BlockRwIn {
            op: BLOCK_RW_READ,
            _rsvd: 0,
            lba,
            blocks: this_blocks,
            buf_off: hdr_len as u32,
        };
        unsafe { core::ptr::write(buf.as_mut_ptr() as *mut BlockRwIn, hdr) };

        let child = Arc::new(RwLock::new(Request::new(
            RequestType::DeviceControl(IOCTL_BLOCK_RW),
            buf,
        )));
        let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
        if st == DriverStatus::NoSuchDevice {
            parent.write().status = DriverStatus::NoSuchDevice;
            return;
        }
        unsafe { pnp_wait_for_request(&child) };

        let c = child.read();
        if c.status != DriverStatus::Success {
            parent.write().status = c.status;
            return;
        }

        let data = &c.data;
        if data.len() < hdr_len {
            parent.write().status = DriverStatus::Unsuccessful;
            return;
        }
        let payload = &data[hdr_len..];
        if payload.is_empty() {
            parent.write().status = DriverStatus::Unsuccessful;
            return;
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

    parent.write().status = DriverStatus::Success;
}

pub extern "win64" fn disk_write(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    let (off, total) = {
        let g = parent.read();
        match g.kind {
            RequestType::Write { offset, len } => (offset, len),
            _ => {
                drop(g);
                parent.write().status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };
    if total == 0 {
        parent.write().status = DriverStatus::Success;
        return;
    }

    let dx = disk_ext_mut(dev);
    if !dx.props_ready {
        match query_props_sync(dev) {
            Ok(_) => {}
            Err(st) => {
                parent.write().status = st;
                return;
            }
        }
    }
    if !rw_validate(dx, off, total) {
        parent.write().status = DriverStatus::InvalidParameter;
        return;
    }

    let bs = dx.block_size as usize;
    let mut remaining = total;
    let mut lba = (off / dx.block_size as u64) as u64;
    let mut parent_off = 0usize;

    while remaining > 0 {
        let max_bytes = (dx.max_blocks as usize).saturating_mul(bs).max(bs);
        let this_bytes = core::cmp::min(remaining, max_bytes);
        let this_blocks = (this_bytes / bs) as u32;

        let hdr_len = size_of::<BlockRwIn>();
        let mut buf = vec![0u8; hdr_len + this_bytes].into_boxed_slice();

        let hdr = BlockRwIn {
            op: BLOCK_RW_WRITE,
            _rsvd: 0,
            lba,
            blocks: this_blocks,
            buf_off: hdr_len as u32,
        };
        unsafe { ptr::write(buf.as_mut_ptr() as *mut BlockRwIn, hdr) };

        {
            let p = parent.read();
            let src = &p.data[parent_off..parent_off + this_bytes];
            buf[hdr_len..hdr_len + this_bytes].copy_from_slice(src);
        }

        let child = Arc::new(RwLock::new(Request::new(
            RequestType::DeviceControl(IOCTL_BLOCK_RW),
            buf,
        )));
        let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
        if st == DriverStatus::NoSuchDevice {
            parent.write().status = DriverStatus::NoSuchDevice;
            return;
        }
        unsafe { pnp_wait_for_request(&child) };

        let c = child.read();
        if c.status != DriverStatus::Success {
            parent.write().status = c.status;
            return;
        }

        remaining -= this_bytes;
        parent_off += this_bytes;
        lba += (this_bytes / bs) as u64;
    }

    parent.write().status = DriverStatus::Success;
}

pub extern "win64" fn disk_ioctl(dev: &Arc<DeviceObject>, parent: Arc<RwLock<Request>>) {
    let code = match parent.read().kind {
        RequestType::DeviceControl(c) => c,
        _ => {
            parent.write().status = DriverStatus::InvalidParameter;
            return;
        }
    };

    if code == IOCTL_BLOCK_FLUSH {
        let child = Arc::new(RwLock::new(Request::new(
            RequestType::DeviceControl(IOCTL_BLOCK_FLUSH),
            Box::new([]),
        )));
        let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
        if st == DriverStatus::NoSuchDevice {
            parent.write().status = DriverStatus::NoSuchDevice;
            return;
        }
        unsafe { pnp_wait_for_request(&child) };
        let c = child.read();
        parent.write().status = c.status;
    } else {
        parent.write().status = DriverStatus::NotImplemented;
    }
}

// ---------- Helpers ----------
fn disk_ext_mut(dev: &Arc<DeviceObject>) -> &mut DiskExt {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const DiskExt as *mut DiskExt) }
}

fn rw_validate(dx: &mut DiskExt, off: u64, total: usize) -> bool {
    if dx.block_size == 0 {
        return false;
    }
    let bs = dx.block_size as u64;
    if (off % bs) != 0 {
        return false;
    }
    if (total as u64 % bs) != 0 {
        return false;
    }
    true
}

fn query_props_sync(dev: &Arc<DeviceObject>) -> Result<(), DriverStatus> {
    let out_len = size_of::<BlockQueryOut>();
    let buf = vec![0u8; out_len].into_boxed_slice();
    let child = Arc::new(RwLock::new(Request::new(
        RequestType::DeviceControl(IOCTL_BLOCK_QUERY),
        buf,
    )));
    let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
    if st == DriverStatus::NoSuchDevice {
        return Err(DriverStatus::NoSuchDevice);
    }
    unsafe { pnp_wait_for_request(&child) };

    let c = child.read();
    if c.status != DriverStatus::Success || c.data.len() < size_of::<BlockQueryOut>() {
        return Err(if c.status == DriverStatus::Success {
            DriverStatus::Unsuccessful
        } else {
            c.status
        });
    }

    let qo = unsafe { *(c.data.as_ptr() as *const BlockQueryOut) };
    let dx = disk_ext_mut(dev);
    dx.block_size = qo.block_size.max(1);
    dx.max_blocks = qo.max_blocks.max(1);
    dx.alignment_mask = qo.alignment_mask;
    dx.features = qo.features;
    dx.props_ready = true;
    Ok(())
}

extern "win64" fn disk_on_flush_done(child: &mut Request, ctx: usize) {
    let parent_arc: Arc<RwLock<Request>> =
        *unsafe { Box::from_raw(ctx as *mut Arc<RwLock<Request>>) };
    parent_arc.write().status = child.status;
    unsafe { pnp_complete_request(&parent_arc) };
}
