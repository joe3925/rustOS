#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use crate::alloc::vec;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::mem;
use core::mem::take;
use core::sync::atomic::Ordering::Acquire;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::Ordering::Release;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{mem::size_of, panic::PanicInfo};
use kernel_api::DevExtRefMut;
use kernel_api::PartitionInfo;
use kernel_api::alloc_api::ffi::{pnp_get_device_target, pnp_send_request, pnp_wait_for_request};
use kernel_api::alloc_api::{IoType, IoVtable, PnpVtable, Synchronization};
use kernel_api::bytes_to_box;
use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceIds, DeviceInit, PnpRequest,
        ffi::{
            driver_set_evt_device_add, pnp_complete_request,
            pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
        },
    },
    println,
};
use kernel_api::{GptHeader, GptPartitionEntry, IoTarget, PnpMinorFunction};
use spin::RwLock;
#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
mod msvc_shims;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::alloc_api::ffi::panic_common;

    unsafe { panic_common(MOD_NAME, info) }
}
#[repr(C)]
#[derive(Default)]
struct VolExt {
    part: Option<PartitionInfo>,
    enumerated: AtomicBool,
}

#[inline]
pub fn ext_mut<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRefMut<'a, T> {
    dev.try_devext_mut().expect("Failed to get partmgr dev ext")
}
#[repr(C)]
#[derive(Default)]
struct VolPdoExt {
    backing: Option<Arc<IoTarget>>,
    part: Option<PartitionInfo>,
}

#[inline]
fn guid_to_string(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    alloc::format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, vol_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn vol_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, vol_prepare_hardware);
    pnp_vtable.set(
        PnpMinorFunction::QueryDeviceRelations,
        vol_enumerate_devices,
    );

    dev_init.set_dev_ext_default::<VolExt>();
    dev_init.pnp_vtable = Some(pnp_vtable);
    DriverStatus::Success
}

extern "win64" fn vol_prepare_hardware(
    dev: &Arc<DeviceObject>,
    _req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let mut req = Request::new(RequestType::Pnp, Box::new([]));
    req.pnp = Some(PnpRequest {
        minor_function: kernel_api::PnpMinorFunction::QueryResources,
        relation: kernel_api::DeviceRelationType::TargetDeviceRelation,
        id_type: kernel_api::QueryIdType::DeviceId,
        ids_out: Vec::new(),
        blob_out: Vec::new(),
    });

    let req_lock = Arc::new(RwLock::new(req));
    let st = unsafe { pnp_forward_request_to_next_lower(dev, req_lock.clone()) };
    if st == DriverStatus::NoSuchDevice {
        return DriverStatus::Success;
    }

    unsafe { pnp_wait_for_request(&req_lock) };

    let mut g = req_lock.write();
    let mut dx = ext_mut::<VolExt>(dev);

    if g.status != DriverStatus::Success {
        return DriverStatus::Success;
    }

    let pi_opt: Option<PartitionInfo> = {
        let pnp = g.pnp.as_mut().unwrap();
        let buf = take(&mut pnp.blob_out);
        if buf.len() == core::mem::size_of::<PartitionInfo>() {
            let boxed_bytes: Box<[u8]> = buf.into_boxed_slice();
            let boxed_pi: Box<PartitionInfo> = unsafe { bytes_to_box(boxed_bytes) };
            Some(*boxed_pi)
        } else {
            None
        }
    };
    dx.part = pi_opt;

    DriverStatus::Success
}
pub extern "win64" fn vol_enumerate_devices(
    device: &Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
) -> DriverStatus {
    let dx = ext_mut::<VolExt>(device);

    let pi = if let Some(ref pi) = dx.part {
        pi
    } else {
        request.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    };

    let binding = (pi.gpt_header, pi.gpt_entry);
    let (_hdr, ent) = if let (Some(ref hdr), Some(ref ent)) = binding {
        (hdr, ent)
    } else {
        request.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    };

    if dx
        .enumerated
        .swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        request.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let parent_dn = if let Some(dn) = device.dev_node.upgrade() {
        dn
    } else {
        request.write().status = DriverStatus::Unsuccessful;
        return DriverStatus::Unsuccessful;
    };

    let zero = [0u8; 16];
    const EFI_SYSTEM: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];
    const BIOS_BOOT: [u8; 16] = [
        0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x66, 0x64, 0x45, 0x46,
        0x49,
    ];

    let ptype = ent.partition_type_guid;
    if ptype == zero || ptype == EFI_SYSTEM || ptype == BIOS_BOOT {
        request.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let part_guid_s = guid_to_string(&ent.unique_partition_guid);
    let name = alloc::format!("Volume{}", &part_guid_s[..8]);
    let inst = alloc::format!("STOR\\VOLUME\\{}\\0000", part_guid_s);

    let ids = DeviceIds {
        hardware: vec!["STOR\\Volume".into(), "STOR\\Volume\\GPT".into()],
        compatible: vec!["STOR\\Volume".into()],
    };

    let mut io_table = IoVtable::new();
    io_table.set(IoType::Read(vol_pdo_read), Synchronization::Sync, 0);
    io_table.set(IoType::Write(vol_pdo_write), Synchronization::Sync, 0);

    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::QueryResources, vol_pdo_query_resources);
    let mut init = DeviceInit::new(io_table, Some(pnp_vtable));
    init.set_dev_ext_default::<VolPdoExt>();
    let (_dn, pdo) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(
            &parent_dn,
            name,
            inst,
            ids,
            Some("volume".into()),
            init,
        )
    };

    if let Some(tgt) = unsafe { pnp_get_device_target(&parent_dn.instance_path) } {
        ext_mut::<VolPdoExt>(&pdo).backing = Some(Arc::new(tgt));
        ext_mut::<VolPdoExt>(&pdo).part = Some(dx.part.clone().unwrap());
    }

    request.write().status = DriverStatus::Success;
    DriverStatus::Success
}
#[repr(C)]
struct BridgeCtx {
    parent: Arc<RwLock<Request>>,
}

extern "win64" fn bridge_complete(child: &mut Request, ctx: usize) {
    let boxed = unsafe { Box::from_raw(ctx as *mut BridgeCtx) };
    let parent = boxed.parent;
    {
        let mut g = parent.write();
        g.status = child.status;
        if g.status == DriverStatus::Success {
            let n = core::cmp::min(g.data.len(), child.data.len());
            g.data[..n].copy_from_slice(&child.data[..n]);
        }
    }
    unsafe { pnp_complete_request(&parent) };
}

pub extern "win64" fn vol_pdo_read(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    let (off, len) = {
        let r = parent.read();
        match r.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => {
                drop(r);
                parent.write().status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };

    let tgt = match &ext_mut::<VolPdoExt>(dev).backing {
        Some(t) => t.clone(),
        None => {
            parent.write().status = DriverStatus::NoSuchDevice;
            return;
        }
    };

    let mut child = Request::new(
        RequestType::Read { offset: off, len },
        vec![0u8; len].into_boxed_slice(),
    );
    let ctx = Box::into_raw(Box::new(BridgeCtx {
        parent: parent.clone(),
    })) as usize;
    child.set_completion(bridge_complete, ctx);
    let req = Arc::new(RwLock::new(child));
    unsafe { pnp_send_request(&*tgt, req.clone()) };
    unsafe { pnp_wait_for_request(&req) };
}

pub extern "win64" fn vol_pdo_write(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    let (off, len, moved) = {
        let mut w = parent.write();
        match w.kind {
            RequestType::Write { offset, len } => {
                let data = mem::take(&mut w.data);
                (offset, len, data)
            }
            _ => {
                w.status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };

    let tgt = match &ext_mut::<VolPdoExt>(dev).backing {
        Some(t) => t.clone(),
        None => {
            parent.write().status = DriverStatus::NoSuchDevice;
            return;
        }
    };

    let mut child = Request::new(RequestType::Write { offset: off, len }, moved);
    let ctx = Box::into_raw(Box::new(BridgeCtx {
        parent: parent.clone(),
    })) as usize;
    child.set_completion(bridge_complete, ctx);

    let req = Arc::new(RwLock::new(child));
    unsafe { pnp_send_request(&*tgt, req.clone()) };
    unsafe { pnp_wait_for_request(&req) };
}
extern "win64" fn vol_pdo_query_resources(
    pdo: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let mut w = req.write();
    let pnp = match w.pnp.as_mut() {
        Some(p) => p,
        None => {
            w.status = DriverStatus::InvalidParameter;
            return DriverStatus::InvalidParameter;
        }
    };

    if let Some(pi) = ext_mut::<VolPdoExt>(pdo).part.as_ref() {
        let mut out = vec![0u8; core::mem::size_of::<PartitionInfo>()];
        unsafe {
            core::ptr::copy_nonoverlapping(
                (pi as *const PartitionInfo) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
        pnp.blob_out = out;
    } else {
        pnp.blob_out.clear();
    }

    w.status = DriverStatus::Success;
    DriverStatus::Success
}
