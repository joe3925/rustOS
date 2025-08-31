#![no_std]
#![no_main]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{mem::size_of, panic::PanicInfo, ptr};
use spin::RwLock;

use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceInit,
        ffi::{driver_set_evt_device_add, pnp_complete_request, pnp_forward_request_to_next_lower},
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

// ---------- helpers for Arc<RwLock<Request>> ----------
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

// ---------- Block Port ABI ----------
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

// ---------- Disk class FDO private state ----------
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

// ---------- Driver entry / add ----------
#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, disk_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn disk_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = size_of::<DiskExt>();
    dev_init.io_read = Some(disk_read);
    dev_init.io_write = Some(disk_write);
    dev_init.io_device_control = Some(disk_ioctl);
    DriverStatus::Success
}

// ---------- I/O paths (Arc<RwLock<Request>>) ----------
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
        issue_query_and_resume(dev, parent, off, total, false);
        return;
    }
    if !rw_validate(dx, off, total) {
        parent.write().status = DriverStatus::InvalidParameter;
        return;
    }

    parent.write().status = DriverStatus::Waiting;
    start_chunked_rw(dev, parent, off, total, false);
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
        issue_query_and_resume(dev, parent, off, total, true);
        return;
    }
    if !rw_validate(dx, off, total) {
        parent.write().status = DriverStatus::InvalidParameter;
        return;
    }

    parent.write().status = DriverStatus::Waiting;
    start_chunked_rw(dev, parent, off, total, true);
}

// optional: flush
pub extern "win64" fn disk_ioctl(dev: &Arc<DeviceObject>, parent: Arc<RwLock<Request>>) {
    let code_opt = {
        if let RequestType::DeviceControl(c) = parent.read().kind {
            Some(c)
        } else {
            None
        }
    };
    match code_opt {
        Some(c) if c == IOCTL_BLOCK_FLUSH => {
            let mut child =
                Request::new(RequestType::DeviceControl(IOCTL_BLOCK_FLUSH), Box::new([]));
            // pass parent Arc in context
            let ctx_ptr = Box::into_raw(Box::new(parent.clone())) as usize;
            child.set_completion(disk_on_flush_done, ctx_ptr);
            parent.write().status = DriverStatus::Waiting;

            let st =
                unsafe { pnp_forward_request_to_next_lower(dev, Arc::new(RwLock::new(child))) };
            if st == DriverStatus::NoSuchDevice {
                let mut r = take_req(&parent);
                r.status = DriverStatus::NoSuchDevice;
                unsafe { pnp_complete_request(&mut r) };
                put_req(&parent, r);
            }
        }
        _ => {
            parent.write().status = DriverStatus::NotImplemented;
        }
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

fn issue_query_and_resume(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    off: u64,
    total: usize,
    is_write: bool,
) {
    let out_len = size_of::<BlockQueryOut>();
    let buf = vec![0u8; out_len].into_boxed_slice();
    let mut child = Request::new(RequestType::DeviceControl(IOCTL_BLOCK_QUERY), buf);

    let ctx = Box::new(QueryResumeCtx {
        dev: Arc::clone(dev),
        parent_req: parent.clone(),
        off,
        total,
        is_write,
    });
    let ctx_ptr = Box::into_raw(ctx) as usize;
    child.set_completion(disk_on_query_done, ctx_ptr);

    parent.write().status = DriverStatus::Waiting;
    let st = unsafe { pnp_forward_request_to_next_lower(dev, Arc::new(RwLock::new(child))) };
    if st == DriverStatus::NoSuchDevice {
        unsafe { drop(Box::from_raw(ctx_ptr as *mut QueryResumeCtx)) };
        let mut r = take_req(&parent);
        r.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(&mut r) };
        put_req(&parent, r);
    }
}

#[repr(C)]
struct QueryResumeCtx {
    dev: Arc<DeviceObject>,
    parent_req: Arc<RwLock<Request>>,
    off: u64,
    total: usize,
    is_write: bool,
}

extern "win64" fn disk_on_query_done(child: &mut Request, ctx: usize) {
    let boxed = unsafe { Box::from_raw(ctx as *mut QueryResumeCtx) };
    let dev = boxed.dev;
    let parent = boxed.parent_req;

    #[inline]
    fn finish(parent: &Arc<RwLock<Request>>, st: DriverStatus) {
        let mut r = take_req(parent);
        r.status = st;
        unsafe { pnp_complete_request(&mut r) };
        put_req(parent, r);
    }

    if child.status != DriverStatus::Success
        || child.data.len() < core::mem::size_of::<BlockQueryOut>()
    {
        let st = if child.status == DriverStatus::Success {
            DriverStatus::Unsuccessful
        } else {
            child.status
        };
        return finish(&parent, st);
    }

    let qo = unsafe { *(child.data.as_ptr() as *const BlockQueryOut) };
    let dx = disk_ext_mut(&dev);
    dx.block_size = qo.block_size.max(1);
    dx.max_blocks = qo.max_blocks.max(1);
    dx.alignment_mask = qo.alignment_mask;
    dx.features = qo.features;
    dx.props_ready = true;

    if !rw_validate(dx, boxed.off, boxed.total) {
        return finish(&parent, DriverStatus::InvalidParameter);
    }

    parent.write().status = DriverStatus::Waiting;
    start_chunked_rw(&dev, parent, boxed.off, boxed.total, boxed.is_write);
}

fn start_chunked_rw(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    off: u64,
    total: usize,
    is_write: bool,
) {
    let dx = disk_ext_mut(dev);
    let bs = dx.block_size as u64;
    let lba = off / bs;
    let ctx = Box::new(RwChainCtx {
        dev: Arc::clone(dev),
        parent_req: parent,
        lba,
        remaining_bytes: total,
        parent_buf_off: 0,
        is_write,
    });
    submit_next_chunk(Box::into_raw(ctx));
}

fn submit_next_chunk(ctx_ptr: *mut RwChainCtx) {
    let ctx = unsafe { &mut *ctx_ptr };
    let dx = disk_ext_mut(&ctx.dev);

    if ctx.remaining_bytes == 0 {
        let parent = &ctx.parent_req;
        let mut r = take_req(parent);
        r.status = DriverStatus::Success;
        unsafe { pnp_complete_request(&mut r) };
        put_req(parent, r);
        unsafe {
            drop(Box::from_raw(ctx_ptr));
        }
        return;
    }

    let bs = dx.block_size as usize;
    let max_bytes = (dx.max_blocks as usize).saturating_mul(bs).max(bs);
    let this_bytes = core::cmp::min(ctx.remaining_bytes, max_bytes);
    let this_blocks = (this_bytes / bs) as u32;

    let hdr_len = size_of::<BlockRwIn>();
    let mut buf = vec![0u8; hdr_len + this_bytes].into_boxed_slice();

    let op = if ctx.is_write {
        BLOCK_RW_WRITE
    } else {
        BLOCK_RW_READ
    };
    let hdr = BlockRwIn {
        op,
        _rsvd: 0,
        lba: ctx.lba,
        blocks: this_blocks,
        buf_off: hdr_len as u32,
    };
    unsafe { ptr::write(buf.as_mut_ptr() as *mut BlockRwIn, hdr) };

    if ctx.is_write {
        let p = ctx.parent_req.read();
        let src = &p.data[ctx.parent_buf_off..ctx.parent_buf_off + this_bytes];
        buf[hdr_len..hdr_len + this_bytes].copy_from_slice(src);
    }

    let mut child = Request::new(RequestType::DeviceControl(IOCTL_BLOCK_RW), buf);
    child.set_completion(disk_on_rw_chunk_done, ctx_ptr as usize);

    let st = unsafe { pnp_forward_request_to_next_lower(&ctx.dev, Arc::new(RwLock::new(child))) };
    if st == DriverStatus::NoSuchDevice {
        let parent = &ctx.parent_req;
        let mut r = take_req(parent);
        r.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(&mut r) };
        put_req(parent, r);
        unsafe {
            drop(Box::from_raw(ctx_ptr));
        }
    }
}

extern "win64" fn disk_on_rw_chunk_done(child: &mut Request, ctx: usize) {
    let ctx_ptr = ctx as *mut RwChainCtx;
    let ctx = unsafe { &mut *ctx_ptr };

    if child.status != DriverStatus::Success {
        let parent = &ctx.parent_req;
        let mut r = take_req(parent);
        r.status = child.status;
        unsafe { pnp_complete_request(&mut r) };
        put_req(parent, r);
        unsafe {
            drop(Box::from_raw(ctx_ptr));
        }
        return;
    }

    let hdr_len = size_of::<BlockRwIn>();
    let moved = child.data.len().saturating_sub(hdr_len);

    if !ctx.is_write {
        let mut p = ctx.parent_req.write();
        let dst = &mut p.data[ctx.parent_buf_off..ctx.parent_buf_off + moved];
        let src = &child.data[hdr_len..hdr_len + moved];
        dst.copy_from_slice(src);
    }

    let dx = disk_ext_mut(&ctx.dev);
    let bs = dx.block_size as usize;
    ctx.remaining_bytes -= moved;
    ctx.parent_buf_off += moved;
    ctx.lba += (moved / bs) as u64;

    submit_next_chunk(ctx_ptr);
}

extern "win64" fn disk_on_flush_done(child: &mut Request, ctx: usize) {
    let parent_arc: Arc<RwLock<Request>> =
        *unsafe { Box::from_raw(ctx as *mut Arc<RwLock<Request>>) };
    let mut r = take_req(&parent_arc);
    r.status = child.status;
    unsafe { pnp_complete_request(&mut r) };
    put_req(&parent_arc, r);
}
