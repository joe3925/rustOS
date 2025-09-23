#![no_std]
#![no_main]

extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{mem, ptr};
use spin::RwLock;

use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, GptHeader, GptPartitionEntry, IoTarget,
    KernelAllocator, PnpMinorFunction, Request, RequestType,
    alloc_api::{
        DeviceIds, DeviceInit, IoType, IoVtable, PnpVtable, Synchronization,
        ffi::{
            driver_set_evt_device_add, pnp_complete_request,
            pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
            pnp_get_device_target, pnp_send_request, pnp_wait_for_request,
        },
    },
    print, println,
};

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

mod msvc_shims;

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, partmgr_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn partmgr_device_add(
    _driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStatus {
    init.dev_ext_size = core::mem::size_of::<PartMgrExt>();

    let mut pnp = PnpVtable::new();
    pnp.set(
        PnpMinorFunction::QueryDeviceRelations,
        partmgr_pnp_query_devrels,
    );
    init.pnp_vtable = Some(pnp);

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
    gpt_header_bytes: Option<[u8; 512]>,
    gpt_entry_bytes: Option<[u8; 128]>,
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
    match (&dx.gpt_header_bytes, &dx.gpt_entry_bytes) {
        (Some(hb), Some(eb)) => {
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

fn parent_target_of(from: &Arc<DeviceObject>) -> Result<IoTarget, DriverStatus> {
    let parent_inst = from
        .dev_node
        .upgrade()
        .and_then(|dn| dn.parent.read().as_ref().and_then(|w| w.upgrade()))
        .map(|p| p.instance_path.clone())
        .ok_or(DriverStatus::NoSuchDevice)?;

    unsafe { pnp_get_device_target(&parent_inst) }.ok_or(DriverStatus::NoSuchDevice)
}

fn send_child_sync(tgt: &IoTarget, mut req: Request) -> Result<Box<[u8]>, DriverStatus> {
    let child = Arc::new(RwLock::new(req));
    unsafe { pnp_send_request(tgt, child.clone()) };
    unsafe { pnp_wait_for_request(&child) };

    let g = child.read();
    if g.status == DriverStatus::Success {
        Ok(g.data.clone())
    } else {
        Err(g.status)
    }
}

pub extern "win64" fn partition_pdo_read(
    device: &Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
    buf_len: usize,
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

    if buf_len != want || (off & 0x1FF) != 0 || (buf_len & 0x1FF) != 0 {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }
    let part_bytes = ((dx.end_lba - dx.start_lba + 1) << 9) as u64;
    if (off as u64) + (buf_len as u64) > part_bytes {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }

    let phys_off = off + ((dx.start_lba as u64) << 9);

    let tgt = match parent_target_of(device) {
        Ok(t) => t,
        Err(st) => {
            request.write().status = st;
            return;
        }
    };

    let child_req = Request::new(
        RequestType::Read {
            offset: phys_off,
            len: buf_len,
        },
        vec![0u8; buf_len].into_boxed_slice(),
    );

    match send_child_sync(&tgt, child_req) {
        Ok(data) => {
            let mut w = request.write();
            let n = core::cmp::min(w.data.len(), data.len());
            if n != 0 {
                w.data[..n].copy_from_slice(&data[..n]);
            }
            w.status = DriverStatus::Success;
        }
        Err(st) => {
            request.write().status = st;
        }
    }
}

pub extern "win64" fn partition_pdo_write(
    device: &Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
    buf_len: usize,
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

    if buf_len != want || (off & 0x1FF) != 0 || (buf_len & 0x1FF) != 0 {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }
    let part_bytes = ((dx.end_lba - dx.start_lba + 1) << 9) as u64;
    if (off as u64) + (buf_len as u64) > part_bytes {
        request.write().status = DriverStatus::InvalidParameter;
        return;
    }

    let phys_off = off + ((dx.start_lba as u64) << 9);

    let moved = {
        let mut w = request.write();
        mem::take(&mut w.data)
    };

    let tgt = match parent_target_of(device) {
        Ok(t) => t,
        Err(st) => {
            request.write().status = st;
            return;
        }
    };

    let child_req = Request::new(
        RequestType::Write {
            offset: phys_off,
            len: buf_len,
        },
        moved,
    );

    match send_child_sync(&tgt, child_req) {
        Ok(_ignored) => {
            request.write().status = DriverStatus::Success;
        }
        Err(st) => {
            request.write().status = st;
        }
    }
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
        request.write().status = DriverStatus::Pending;
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

            let mut io_vt = IoVtable::new();
            io_vt.set(IoType::Read(partition_pdo_read), Synchronization::Sync, 0);
            io_vt.set(IoType::Write(partition_pdo_write), Synchronization::Sync, 0);

            let mut child_init = DeviceInit {
                dev_ext_size: core::mem::size_of::<PartDevExt>(),
                io_vtable: io_vt,
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
            pext.gpt_header_bytes = Some(hdr_bytes.as_ref().try_into().unwrap());
            pext.gpt_entry_bytes = Some(ch.try_into().unwrap());
        }
    }

    request.write().status = DriverStatus::Success;
    DriverStatus::Success
}
