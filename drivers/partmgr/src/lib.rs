#![no_std]
#![no_main]

extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::mem;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_api::alloc_api::{IoType, IoVtable};
use spin::RwLock;

use kernel_api::alloc_api::ffi::{
    pnp_complete_request, pnp_forward_request_to_next_lower, pnp_get_device_target,
    pnp_send_request, pnp_wait_for_request,
};
use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, PnpMinorFunction, Request, RequestType,
    alloc_api::ffi::{driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init},
    alloc_api::{DeviceIds, DeviceInit, PnpVtable},
};
use kernel_api::{GptHeader, GptPartitionEntry, KernelAllocator};

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::println;
    println!("{}", info);
    loop {}
}

mod msvc_shims;

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, partmgr_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn partmgr_device_add(
    _driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStatus {
    init.dev_ext_size = core::mem::size_of::<PartMgrExt>();

    // PnP vtable: handle BusRelations enumeration here.
    let mut vt = PnpVtable::new();
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        partmgr_pnp_query_devrels,
    );
    init.pnp_vtable = Some(vt);

    DriverStatus::Success
}

#[repr(C)]
struct PartMgrExt {
    enumerated: AtomicBool,
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

#[repr(C)]
struct PartDevExt {
    start_lba: u64,
    end_lba: u64,
    gpt_header: Option<GptHeader>,
    gpt_entry: Option<GptPartitionEntry>,
}

extern "win64" fn partition_pdo_query_resources(
    device: &Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
) -> DriverStatus {
    let mut w = request.write();
    let Some(pnp) = w.pnp.as_mut() else {
        w.status = DriverStatus::NotImplemented;
        return DriverStatus::Success;
    };

    let dx = ext_mut::<PartDevExt>(device);
    match (&dx.gpt_header, &dx.gpt_entry) {
        (Some(h), Some(e)) => {
            let hb = unsafe { core::slice::from_raw_parts(h as *const _ as *const u8, 512) };
            let eb = unsafe { core::slice::from_raw_parts(e as *const _ as *const u8, 128) };
            pnp.blob_out.clear();
            pnp.blob_out.extend_from_slice(hb);
            pnp.blob_out.extend_from_slice(eb);
            w.status = DriverStatus::Success;
        }
        _ => {
            w.status = DriverStatus::NotImplemented;
        }
    }
    DriverStatus::Success
}

#[repr(C)]
struct ChildCtxCopyback {
    parent_req: *mut Request,
}

extern "win64" fn child_complete_copyback(child: &mut Request, ctx: usize) {
    let boxed = unsafe { Box::from_raw(ctx as *mut ChildCtxCopyback) };
    let parent = unsafe { &mut *boxed.parent_req };
    parent.status = child.status;
    if parent.status == DriverStatus::Success {
        let n = core::cmp::min(parent.data.len(), child.data.len());
        parent.data[..n].copy_from_slice(&child.data[..n]);
    }
    unsafe { pnp_complete_request(parent) };
}

fn send_down_async_copyback(
    from: &Arc<DeviceObject>,
    parent: &mut Request,
    new_kind: RequestType,
    buf: Box<[u8]>,
) -> DriverStatus {
    let parent_inst = match from
        .dev_node
        .upgrade()
        .and_then(|dn| dn.parent.read().as_ref().and_then(|w| w.upgrade()))
    {
        Some(p) => p.instance_path.clone(),
        None => {
            parent.status = DriverStatus::NoSuchDevice;
            unsafe { pnp_complete_request(parent) };
            return DriverStatus::Waiting;
        }
    };

    let target = match unsafe { pnp_get_device_target(&parent_inst) } {
        Some(t) => Arc::new(t),
        None => {
            parent.status = DriverStatus::NoSuchDevice;
            unsafe { pnp_complete_request(parent) };
            return DriverStatus::Waiting;
        }
    };

    let mut child = Request::new(new_kind, buf);
    let ctx = Box::into_raw(Box::new(ChildCtxCopyback {
        parent_req: parent as *mut _,
    })) as usize;
    child.set_completion(child_complete_copyback, ctx);

    parent.status = DriverStatus::Waiting;
    unsafe { pnp_send_request(&*target, Arc::new(RwLock::new(child))) };
    DriverStatus::Waiting
}

pub extern "win64" fn partition_pdo_read(
    device: &Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
    len: usize,
) {
    let dx = ext_mut::<PartDevExt>(device);

    let (off, want) = {
        let r = request.read();
        match r.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => {
                drop(r);
                request.write().status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };

    if len != want || (off & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }
    let part_bytes = ((dx.end_lba - dx.start_lba + 1) << 9) as u64;
    if off as u64 + len as u64 > part_bytes {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }

    let phys_off = off + ((dx.start_lba as u64) << 9);
    let buf = vec![0u8; len].into_boxed_slice();

    let mut w = request.write();
    let _ = send_down_async_copyback(
        device,
        &mut *w,
        RequestType::Read {
            offset: phys_off,
            len,
        },
        buf,
    );
}

pub extern "win64" fn partition_pdo_write(
    device: &Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
    len: usize,
) {
    let dx = ext_mut::<PartDevExt>(device);

    let (off, want) = {
        let r = request.read();
        match r.kind {
            RequestType::Write { offset, len } => (offset, len),
            _ => {
                drop(r);
                request.write().status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };

    if len != want || (off & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }
    let part_bytes = ((dx.end_lba - dx.start_lba + 1) << 9) as u64;
    if off as u64 + len as u64 > part_bytes {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }

    let phys_off = off + ((dx.start_lba as u64) << 9);

    let moved = {
        let mut w = request.write();
        mem::take(&mut w.data)
    };

    let mut w = request.write();
    let _ = send_down_async_copyback(
        device,
        &mut *w,
        RequestType::Write {
            offset: phys_off,
            len,
        },
        moved,
    );
}

#[inline]
fn gpt_header_from(bytes: &[u8]) -> Option<GptHeader> {
    if bytes.len() < 512 {
        return None;
    }
    let mut hdr: GptHeader = unsafe { core::ptr::read(bytes.as_ptr() as *const _) };
    if &hdr.signature != b"EFI PART" {
        return None;
    }
    if hdr.header_size < core::mem::size_of::<GptHeader>() as u32 && hdr.header_size >= 92 {
        hdr.header_size = 92;
    }
    Some(hdr)
}

#[inline]
fn gpt_entry_from(bytes: &[u8]) -> Option<GptPartitionEntry> {
    if bytes.len() != 128 {
        return None;
    }
    let e: GptPartitionEntry = unsafe { core::ptr::read(bytes.as_ptr() as *const _) };
    if e.first_lba == 0 && e.last_lba == 0 {
        return None;
    }
    Some(e)
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

extern "win64" fn partmgr_pnp_query_devrels(
    device: &Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
) -> DriverStatus {
    let relation = { request.read().pnp.as_ref().unwrap().relation };
    if relation != kernel_api::DeviceRelationType::BusRelations {
        request.write().status = DriverStatus::Pending; // manager will forward to next lower
        return DriverStatus::Pending;
    }

    let pmx = ext_mut::<PartMgrExt>(device);
    if pmx.enumerated.swap(true, Ordering::AcqRel) {
        request.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    fn read_from_lower_sync(
        dev: &Arc<DeviceObject>,
        offset: u64,
        len: usize,
    ) -> Result<Box<[u8]>, DriverStatus> {
        let child = Arc::new(RwLock::new(Request::new(
            RequestType::Read { offset, len },
            vec![0u8; len].into_boxed_slice(),
        )));
        let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
        if st == DriverStatus::NoSuchDevice {
            return Err(DriverStatus::NoSuchDevice);
        }
        unsafe { pnp_wait_for_request(&child) };
        let g = child.read();
        if g.status == DriverStatus::Success {
            Ok(g.data.clone())
        } else {
            Err(g.status)
        }
    }

    let hdr_bytes = match read_from_lower_sync(device, 1u64 << 9, 512) {
        Ok(b) => b,
        Err(_) => {
            request.write().status = DriverStatus::Success;
            return DriverStatus::Success;
        }
    };

    let Some(h) = gpt_header_from(&hdr_bytes) else {
        request.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    };

    if h.partition_entry_size != 128 || h.num_partition_entries == 0 {
        request.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let total = (h.num_partition_entries as usize) * (h.partition_entry_size as usize);
    let bytes = ((total + 511) / 512) * 512;

    let entries = match read_from_lower_sync(device, h.partition_entry_lba << 9, bytes) {
        Ok(b) => b,
        Err(_) => {
            request.write().status = DriverStatus::Success;
            return DriverStatus::Success;
        }
    };

    let parent_dn = match device.dev_node.upgrade() {
        Some(dn) => dn,
        None => {
            request.write().status = DriverStatus::Unsuccessful;
            return DriverStatus::Success;
        }
    };

    let disk_guid_s = guid_to_string(&h.disk_guid);
    let mut idx: u32 = 0;

    for ch in entries.chunks_exact(128) {
        if let Some(e) = gpt_entry_from(ch) {
            idx += 1;
            if e.first_lba < h.first_usable_lba
                || e.last_lba > h.last_usable_lba
                || e.first_lba > e.last_lba
            {
                continue;
            }
            let mut io_vtable = IoVtable::new();
            io_vtable.set(IoType::Read(partition_pdo_read));
            io_vtable.set(IoType::Write(partition_pdo_write));
            let mut child_init = DeviceInit {
                dev_ext_size: core::mem::size_of::<PartDevExt>(),
                io_vtable,
                pnp_vtable: None,
            };
            let mut vt = PnpVtable::new();
            vt.set(
                PnpMinorFunction::QueryResources,
                partition_pdo_query_resources,
            );
            child_init.pnp_vtable = Some(vt);

            let name = alloc::format!("Partition{}", idx);
            let inst = alloc::format!("STOR\\PARTITION\\{}\\{:04}", disk_guid_s, idx);
            let ids = DeviceIds {
                hardware: vec!["STOR\\Partition".into(), "STOR\\Partition\\GPT".into()],
                compatible: vec!["STOR\\Partition".into()],
            };

            let (_dn_child, pdo) = unsafe {
                pnp_create_child_devnode_and_pdo_with_init(
                    &parent_dn,
                    name,
                    inst,
                    ids,
                    Some("DiskPartition".into()),
                    child_init,
                )
            };

            let pext = ext_mut::<PartDevExt>(&pdo);
            pext.start_lba = e.first_lba;
            pext.end_lba = e.last_lba;
            pext.gpt_header = Some(h);
            pext.gpt_entry = Some(e);
        }
    }

    request.write().status = DriverStatus::Success;
    DriverStatus::Success
}
