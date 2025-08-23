#![no_std]
#![no_main]

extern crate alloc;
use crate::alloc::vec;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::{
    mem,
    sync::atomic::{AtomicBool, Ordering},
};
use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, Request, RequestType,
    alloc_api::ffi::{
        driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
        pnp_forward_request_to_next_lower,
    },
    alloc_api::{DeviceIds, DeviceInit},
};
use kernel_api::{DeviceRelationType, alloc_api::ffi::InvalidateDeviceRelations};
use kernel_api::{KernelAllocator, print};
use kernel_api::{ffi::pnp_queue_dpc, println};
mod msvc_shims;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::println;

    println!("{}", info);
    loop {}
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, partmgr_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn partmgr_device_add(
    _driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStatus {
    println!("filter add device");
    init.dev_ext_size = core::mem::size_of::<PartMgrExt>();
    init.evt_bus_enumerate_devices = Some(partmgr_enumerate_devices);
    DriverStatus::Success
}

// ---------- per-device extension for the filter DO ----------

#[repr(C)]
struct PartMgrExt {
    enumerated: AtomicBool,
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

// ---------- partition PDO devext and IO handlers ----------

#[repr(C)]
struct PartDevExt {
    start_lba: u64,
    end_lba: u64,
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
    request.kind = RequestType::Read {
        offset: phys_off,
        len,
    };
    let st = unsafe { pnp_forward_request_to_next_lower(device, request) };
    if st == DriverStatus::NoSuchDevice {
        request.status = DriverStatus::NoSuchDevice;
    }
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
    request.kind = RequestType::Write {
        offset: phys_off,
        len,
    };
    let st = unsafe { pnp_forward_request_to_next_lower(device, request) };
    if st == DriverStatus::NoSuchDevice {
        request.status = DriverStatus::NoSuchDevice;
    }
}

// ---------- GPT structures (read-only) ----------

#[repr(C)]
#[derive(Clone, Copy)]
struct GptHeader {
    signature: [u8; 8],
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    _reserved: u32,
    _current_lba: u64,
    _backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: [u8; 16],
    partition_entry_lba: u64,
    num_partition_entries: u32,
    partition_entry_size: u32,
    _partition_crc32: u32,
    _reserved_block: [u8; 420],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct GptPartitionEntry {
    partition_type_guid: [u8; 16],
    unique_partition_guid: [u8; 16],
    first_lba: u64,
    last_lba: u64,
    _attr: u64,
    name_utf16: [u16; 36],
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
    if hdr.header_size < mem::size_of::<GptHeader>() as u32 && hdr.header_size >= 92 {
        // accept canonical 92-byte size
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

// ---------- sync down-call helper ----------

fn read_sync(
    device: &Arc<DeviceObject>,
    lba: u64,
    bytes: usize,
) -> Result<Box<[u8]>, DriverStatus> {
    let aligned = (bytes + 511) & !511;
    let mut req = Request::new(
        RequestType::Read {
            offset: lba << 9,
            len: aligned,
        },
        vec![0u8; aligned].into_boxed_slice(),
    );
    let st = unsafe { pnp_forward_request_to_next_lower(device, &mut req) };
    if st == DriverStatus::NoSuchDevice {
        return Err(DriverStatus::NoSuchDevice);
    }
    if req.status != DriverStatus::Success {
        return Err(req.status);
    }
    Ok(req.data)
}

struct EnumCtx {
    dev: Arc<DeviceObject>,
}

fn enum_kickoff(ctx_usize: usize) {
    let dev = unsafe { (&*(ctx_usize as *const EnumCtx)).dev.clone() };

    let mut req = Request::new(
        RequestType::Read {
            offset: 1 << 9,
            len: 512,
        },
        alloc::vec![0u8; 512].into_boxed_slice(),
    );
    req.set_completion(partmgr_hdr_done, ctx_usize);

    let _ = unsafe { pnp_forward_request_to_next_lower(&dev, &mut req) };
}

extern "win64" fn partmgr_hdr_done(req: &mut Request, ctx: usize) {
    let mut state = unsafe { Box::from_raw(ctx as *mut EnumCtx) };
    if req.status != DriverStatus::Success {
        return;
    }

    let hdr = match gpt_header_from(&req.data) {
        Some(h) => h,
        None => return,
    };

    let total_bytes = (hdr.num_partition_entries as usize) * (hdr.partition_entry_size as usize);
    if hdr.partition_entry_size != 128 || total_bytes == 0 {
        return;
    }
    let sectors = (total_bytes + 511) / 512;

    let mut ent_req = Request::new(
        RequestType::Read {
            offset: hdr.partition_entry_lba << 9,
            len: sectors * 512,
        },
        alloc::vec![0u8; sectors * 512].into_boxed_slice(),
    );
    ent_req.set_completion(partmgr_entries_done, Box::into_raw(state) as usize);

    let dev = unsafe { (&*(ctx as *const EnumCtx)).dev.clone() };
    let _ = unsafe { pnp_forward_request_to_next_lower(&dev, &mut ent_req) };
}

extern "win64" fn partmgr_entries_done(req: &mut Request, ctx: usize) {
    let state = unsafe { Box::from_raw(ctx as *mut EnumCtx) };
    let dev = state.dev.clone();

    if req.status != DriverStatus::Success {
        return;
    }

    let hdr = match {
        let mut hdr_req = Request::new(
            RequestType::Read {
                offset: 1 << 9,
                len: 512,
            },
            alloc::vec![0u8; 512].into_boxed_slice(),
        );
        let _ = unsafe { pnp_forward_request_to_next_lower(&dev, &mut hdr_req) };
        if hdr_req.status == DriverStatus::Success {
            gpt_header_from(&hdr_req.data)
        } else {
            None
        }
    } {
        Some(h) => h,
        None => return,
    };

    let parent = match dev.dev_node.upgrade() {
        Some(dn) => dn,
        None => return,
    };

    let disk_guid_s = guid_to_string(&hdr.disk_guid);
    let mut idx: u32 = 0;
    let mut slot: u32 = 0;
    for ch in req.data.chunks_exact(128) {
        slot += 1;
        if let Some(e) = gpt_entry_from(ch) {
            if e.first_lba < hdr.first_usable_lba
                || e.last_lba > hdr.last_usable_lba
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
                evt_pnp: None,
            };

            idx += 1;
            let name = alloc::format!("Partition{}", idx);
            let inst = alloc::format!("STOR\\PARTITION\\{}\\{:04}", disk_guid_s, idx);
            let ids = DeviceIds {
                hardware: alloc::vec!["STOR\\Partition".into(), "STOR\\Partition\\GPT".into()],
                compatible: alloc::vec!["STOR\\Partition".into()],
            };

            let (_dn_child, pdo) = unsafe {
                pnp_create_child_devnode_and_pdo_with_init(
                    &parent,
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
        }
    }

    unsafe { InvalidateDeviceRelations(&dev, DeviceRelationType::BusRelations) };
}

pub extern "win64" fn partmgr_enumerate_devices(device: &Arc<DeviceObject>) -> DriverStatus {
    let pmx = ext_mut::<PartMgrExt>(device);
    if pmx.enumerated.swap(true, Ordering::AcqRel) {
        return DriverStatus::Success;
    }

    let ctx = Box::new(EnumCtx {
        dev: device.clone(),
    });
    unsafe { pnp_queue_dpc(enum_kickoff as _, Box::into_raw(ctx) as usize) };

    DriverStatus::Pending
}
