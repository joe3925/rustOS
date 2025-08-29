#![no_std]
#![no_main]

extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::mem;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_api::alloc_api::ffi::{pnp_complete_request, pnp_forward_request_to_next_lower};
use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, Request, RequestType,
    alloc_api::ffi::{driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init},
    alloc_api::{DeviceIds, DeviceInit},
};
use kernel_api::{GptHeader, GptPartitionEntry, KernelAllocator, println};

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
    init.evt_bus_enumerate_devices = Some(partmgr_enumerate_devices);
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

pub extern "win64" fn partition_pdo_pnp(device: &Arc<DeviceObject>, request: &mut Request) {
    let Some(pnp) = request.pnp.as_mut() else {
        request.status = DriverStatus::Pending;
        return;
    };
    match pnp.minor_function {
        kernel_api::PnpMinorFunction::QueryResources => {
            let dx = ext_mut::<PartDevExt>(device);
            match (&dx.gpt_header, &dx.gpt_entry) {
                (Some(h), Some(e)) => {
                    let hb =
                        unsafe { core::slice::from_raw_parts(h as *const _ as *const u8, 512) };
                    let eb =
                        unsafe { core::slice::from_raw_parts(e as *const _ as *const u8, 128) };
                    pnp.blob_out.clear();
                    pnp.blob_out.extend_from_slice(hb);
                    pnp.blob_out.extend_from_slice(eb);
                    request.status = DriverStatus::Success;
                    unsafe { pnp_complete_request(request) };
                }
                _ => {
                    request.status = DriverStatus::NotImplemented;
                    unsafe { pnp_complete_request(request) };
                }
            }
        }
        _ => {
            request.status = DriverStatus::Pending;
        }
    }
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
    let mut child = Request::new(new_kind, buf);
    let ctx = Box::into_raw(Box::new(ChildCtxCopyback {
        parent_req: parent as *mut _,
    })) as usize;

    child.set_completion(child_complete_copyback, ctx);

    parent.status = DriverStatus::Waiting;
    let st = unsafe { pnp_forward_request_to_next_lower(from, &mut child) };
    if st == DriverStatus::NoSuchDevice {
        parent.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(parent) };
    }
    DriverStatus::Waiting
}

pub extern "win64" fn partition_pdo_read(
    device: &Arc<DeviceObject>,
    request: &mut Request,
    len: usize,
) {
    let dx = ext_mut::<PartDevExt>(device);
    let (off, want) = match request.kind {
        RequestType::Read { offset, len } => (offset, len),
        _ => {
            request.status = DriverStatus::InvalidParameter;
            return;
        }
    };
    if len != want || (off & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        request.status = DriverStatus::InvalidParameter;
        return;
    }
    let part_bytes = ((dx.end_lba - dx.start_lba + 1) << 9) as u64;
    if off as u64 + len as u64 > part_bytes {
        request.status = DriverStatus::InvalidParameter;
        return;
    }

    let phys_off = off + ((dx.start_lba as u64) << 9);
    let buf = vec![0u8; len].into_boxed_slice();

    let _ = send_down_async_copyback(
        device,
        request,
        RequestType::Read {
            offset: phys_off,
            len,
        },
        buf,
    );
}

pub extern "win64" fn partition_pdo_write(
    device: &Arc<DeviceObject>,
    request: &mut Request,
    len: usize,
) {
    let dx = ext_mut::<PartDevExt>(device);
    let (off, want) = match request.kind {
        RequestType::Write { offset, len } => (offset, len),
        _ => {
            request.status = DriverStatus::InvalidParameter;
            return;
        }
    };
    if len != want || (off & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        request.status = DriverStatus::InvalidParameter;
        return;
    }
    let part_bytes = ((dx.end_lba - dx.start_lba + 1) << 9) as u64;
    if off as u64 + len as u64 > part_bytes {
        request.status = DriverStatus::InvalidParameter;
        return;
    }

    let phys_off = off + ((dx.start_lba as u64) << 9);

    let moved = mem::take(&mut request.data);

    let _ = send_down_async_copyback(
        device,
        request,
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

#[repr(u32)]
enum PartEnumPhase {
    ReadHdr = 0,
    ReadEntries = 1,
}

#[repr(C)]
struct PartEnumCtx {
    device: Arc<DeviceObject>,
    parent: *mut Request,
    phase: PartEnumPhase,
    first_usable_lba: u64,
    last_usable_lba: u64,
    entry_lba: u64,
    num_entries: u32,
    entry_size: u32,
    disk_guid: [u8; 16],
    hdr_copy: GptHeader,
}

extern "win64" fn part_enum_complete(child: &mut Request, ctx_usize: usize) {
    let ctx = unsafe { &mut *(ctx_usize as *mut PartEnumCtx) };

    if child.status != DriverStatus::Success {
        let parent = unsafe { &mut *ctx.parent };
        parent.status = DriverStatus::Success;
        unsafe { pnp_complete_request(parent) };
        unsafe { drop(Box::from_raw(ctx_usize as *mut PartEnumCtx)) };
        return;
    }

    match ctx.phase {
        PartEnumPhase::ReadHdr => {
            if let Some(h) = gpt_header_from(&child.data) {
                ctx.first_usable_lba = h.first_usable_lba;
                ctx.last_usable_lba = h.last_usable_lba;
                ctx.entry_lba = h.partition_entry_lba;
                ctx.num_entries = h.num_partition_entries;
                ctx.entry_size = h.partition_entry_size;
                ctx.disk_guid = h.disk_guid;
                ctx.hdr_copy = h;

                let total = (ctx.num_entries as usize) * (ctx.entry_size as usize);
                if ctx.entry_size != 128 || total == 0 {
                    let parent = unsafe { &mut *ctx.parent };
                    parent.status = DriverStatus::Success;
                    unsafe { pnp_complete_request(parent) };
                    unsafe { drop(Box::from_raw(ctx_usize as *mut PartEnumCtx)) };
                    return;
                }
                let bytes = ((total + 511) / 512) * 512;

                let mut next = Request::new(
                    RequestType::Read {
                        offset: ctx.entry_lba << 9,
                        len: bytes,
                    },
                    vec![0u8; bytes].into_boxed_slice(),
                );
                ctx.phase = PartEnumPhase::ReadEntries;
                next.set_completion(part_enum_complete, ctx_usize);

                let st = unsafe { pnp_forward_request_to_next_lower(&ctx.device, &mut next) };
                if st == DriverStatus::NoSuchDevice {
                    let parent = unsafe { &mut *ctx.parent };
                    parent.status = DriverStatus::Success;
                    unsafe { pnp_complete_request(parent) };
                    unsafe { drop(Box::from_raw(ctx_usize as *mut PartEnumCtx)) };
                }
            } else {
                let parent = unsafe { &mut *ctx.parent };
                parent.status = DriverStatus::Success;
                unsafe { pnp_complete_request(parent) };
                unsafe { drop(Box::from_raw(ctx_usize as *mut PartEnumCtx)) };
            }
        }

        PartEnumPhase::ReadEntries => {
            let parent = unsafe { &mut *ctx.parent };

            let parent_dn = match ctx.device.dev_node.upgrade() {
                Some(dn) => dn,
                None => {
                    parent.status = DriverStatus::Unsuccessful;
                    unsafe { pnp_complete_request(parent) };
                    unsafe { drop(Box::from_raw(ctx_usize as *mut PartEnumCtx)) };
                    return;
                }
            };

            let disk_guid_s = guid_to_string(&ctx.disk_guid);
            let mut idx: u32 = 0;

            for ch in child.data.chunks_exact(128) {
                if let Some(e) = gpt_entry_from(ch) {
                    idx += 1;
                    if e.first_lba < ctx.first_usable_lba
                        || e.last_lba > ctx.last_usable_lba
                        || e.first_lba > e.last_lba
                    {
                        continue;
                    }

                    let mut init = DeviceInit {
                        dev_ext_size: core::mem::size_of::<PartDevExt>(),
                        io_read: Some(partition_pdo_read),
                        io_write: Some(partition_pdo_write),
                        io_device_control: None,
                        evt_device_prepare_hardware: None,
                        evt_bus_enumerate_devices: None,
                        evt_pnp: Some(partition_pdo_pnp),
                    };

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
                            init,
                        )
                    };

                    let pext = ext_mut::<PartDevExt>(&pdo);
                    pext.start_lba = e.first_lba;
                    pext.end_lba = e.last_lba;
                    pext.gpt_header = Some(ctx.hdr_copy);
                    pext.gpt_entry = Some(e);
                }
            }

            parent.status = DriverStatus::Success;
            unsafe { pnp_complete_request(parent) };
            unsafe { drop(Box::from_raw(ctx_usize as *mut PartEnumCtx)) };
        }
    }
}

pub extern "win64" fn partmgr_enumerate_devices(
    device: &Arc<DeviceObject>,
    request: &mut Request,
) -> DriverStatus {
    println!("enum");
    let pmx = ext_mut::<PartMgrExt>(device);
    if pmx.enumerated.swap(true, Ordering::AcqRel) {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let ctx = Box::into_raw(Box::new(PartEnumCtx {
        device: device.clone(),
        parent: request as *mut _,
        phase: PartEnumPhase::ReadHdr,
        first_usable_lba: 0,
        last_usable_lba: 0,
        entry_lba: 0,
        num_entries: 0,
        entry_size: 0,
        disk_guid: [0u8; 16],
        hdr_copy: unsafe { core::mem::zeroed() },
    })) as usize;

    let mut child = Request::new(
        RequestType::Read {
            offset: 1u64 << 9,
            len: 512,
        },
        vec![0u8; 512].into_boxed_slice(),
    );
    child.set_completion(part_enum_complete, ctx);

    request.status = DriverStatus::Waiting;

    let st = unsafe { pnp_forward_request_to_next_lower(device, &mut child) };
    if st == DriverStatus::NoSuchDevice {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    DriverStatus::Waiting
}
