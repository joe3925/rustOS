#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::{mem, ptr};
use kernel_api::device::{DevExtRef, DeviceInit, DeviceObject, DriverObject};
use kernel_api::kernel_types::io::{
    DiskInfo, GptHeader, GptPartitionEntry, IoType, IoVtable, PartitionInfo, Synchronization,
};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::pnp::{
    DeviceRelationType, PnpMinorFunction, PnpVtable, driver_set_evt_device_add,
    pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
    pnp_send_request_to_stack_top,
};
use kernel_api::request::{Request, RequestType, TraversalPolicy};
use kernel_api::status::DriverStatus;
use kernel_api::util::box_to_bytes;
use kernel_api::{RequestExt, block_on, io_handler};
use spin::{Once, RwLock};

use kernel_api::println;

#[cfg(not(test))]
use core::panic::PanicInfo;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        use kernel_api::util::panic_common;
        panic_common(MOD_NAME, info)
    }
}
mod msvc_shims;

const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, partmgr_device_add);
    DriverStatus::Success
}

pub extern "win64" fn partmgr_device_add(
    _driver: Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStatus {
    init.set_dev_ext_default::<PartMgrExt>();

    let mut pnp = PnpVtable::new();
    pnp.set(PnpMinorFunction::StartDevice, partmgr_start);
    pnp.set(
        PnpMinorFunction::QueryDeviceRelations,
        partmgr_pnp_query_devrels,
    );
    init.pnp_vtable = Some(pnp);

    DriverStatus::Success
}

#[repr(C)]
#[derive(Default)]
struct PartMgrExt {
    enumerated: AtomicBool,
    disk_info: Once<Vec<u8>>, // raw bytes of DiskInfo (size_of::<DiskInfo>())
}

#[inline]
pub fn ext<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("Failed to get partmgr dev ext")
}

#[repr(C)]
#[derive(Default)]
struct PartDevExt {
    start_lba: Once<u64>,
    end_lba: Once<u64>,
    part: Once<PartitionInfo>,
}

extern "win64" fn partition_pdo_query_resources(
    device: Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
) -> DriverStatus {
    let mut w = request.write();
    let Some(pnp) = w.pnp.as_mut() else {
        return DriverStatus::Success;
    };

    let dx = ext::<PartDevExt>(&device);
    if let Some(pi) = dx.part.get() {
        let bytes: Box<[u8]> = box_to_bytes(Box::new((*pi).clone()));
        pnp.blob_out = bytes.into_vec();
    }

    DriverStatus::Success
}

async fn send_req_parent(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> Result<Box<[u8]>, DriverStatus> {
    unsafe {
        pnp_send_request_to_stack_top(
            dev.dev_node
                .get()
                .unwrap()
                .upgrade()
                .unwrap()
                .parent
                .get()
                .unwrap(),
            req.clone(),
        )
    }?
    .await;

    let g = req.read();
    if g.status == DriverStatus::Success {
        Ok(g.data.clone())
    } else {
        Err(g.status)
    }
}
#[io_handler]
pub async fn partition_pdo_read(
    device: Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
    buf_len: usize,
) -> DriverStatus {
    let dx = ext::<PartDevExt>(&device);
    let start_lba = *dx.start_lba.get().unwrap();
    let end_lba = *dx.end_lba.get().unwrap();
    let (off, want) = {
        let r = request.read();
        match r.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => {
                drop(r);
                return DriverStatus::InvalidParameter;
            }
        }
    };

    if buf_len != want || (off & 0x1FF) != 0 || (buf_len & 0x1FF) != 0 {
        return DriverStatus::InvalidParameter;
    }
    let part_bytes = ((end_lba - start_lba + 1) << 9) as u64;
    if (off as u64) + (buf_len as u64) > part_bytes {
        return DriverStatus::InvalidParameter;
    }

    let phys_off = off + ((start_lba as u64) << 9);

    let child_req = Request::new(
        RequestType::Read {
            offset: phys_off,
            len: buf_len,
        },
        vec![0u8; buf_len].into_boxed_slice(),
    )
    .set_traversal_policy(TraversalPolicy::ForwardLower);

    match send_req_parent(&device, Arc::new(RwLock::new(child_req))).await {
        Ok(data) => {
            let mut w = request.write();
            let n = core::cmp::min(w.data.len(), data.len());
            if n != 0 {
                w.data[..n].copy_from_slice(&data[..n]);
            }
            return DriverStatus::Success;
        }
        Err(st) => {
            return st;
        }
    }
}
#[io_handler]
pub async fn partition_pdo_write(
    device: Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
    buf_len: usize,
) -> DriverStatus {
    let dx = ext::<PartDevExt>(&device);
    let start_lba = *dx.start_lba.get().unwrap();
    let end_lba = *dx.end_lba.get().unwrap();
    let (off, want) = {
        let r = request.read();
        match r.kind {
            RequestType::Write { offset, len } => (offset, len),
            _ => {
                drop(r);
                return DriverStatus::InvalidParameter;
            }
        }
    };

    if buf_len != want || (off & 0x1FF) != 0 || (buf_len & 0x1FF) != 0 {
        return DriverStatus::InvalidParameter;
    }
    let part_bytes = ((end_lba - start_lba + 1) << 9) as u64;
    if (off as u64) + (buf_len as u64) > part_bytes {
        return DriverStatus::InvalidParameter;
    }

    let phys_off = off + ((start_lba as u64) << 9);

    let moved = {
        let mut w = request.write();
        mem::take(&mut w.data)
    };
    let child_req = Request::new(
        RequestType::Write {
            offset: phys_off,
            len: buf_len,
        },
        moved,
    )
    .set_traversal_policy(TraversalPolicy::ForwardLower);

    match send_req_parent(&device, Arc::new(RwLock::new(child_req))).await {
        Ok(_ignored) => {
            return DriverStatus::Success;
        }
        Err(st) => {
            return st;
        }
    }
}

extern "win64" fn partmgr_start(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStatus {
    let mut dx = ext::<PartMgrExt>(&dev);

    let parent = Arc::new(RwLock::new(
        Request::new(
            RequestType::DeviceControl(IOCTL_DRIVE_IDENTIFY),
            Box::new([]),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower),
    ));
    block_on(unsafe { pnp_forward_request_to_next_lower(&dev, parent.clone()) }?);

    let (st, data) = {
        let g = parent.read();
        (g.status, g.data.clone())
    };

    if st == DriverStatus::Success && data.len() == core::mem::size_of::<DiskInfo>() {
        dx.disk_info.call_once(|| data.into_vec());
    }

    DriverStatus::Continue
}

async fn read_from_lower_async(
    dev: &Arc<DeviceObject>,
    offset: u64,
    len: usize,
) -> Result<Box<[u8]>, DriverStatus> {
    let child = Arc::new(RwLock::new(
        Request::new(
            RequestType::Read { offset, len },
            vec![0u8; len].into_boxed_slice(),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower),
    ));
    unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) }?.await;
    let g = child.read();
    if g.status == DriverStatus::Success {
        Ok(g.data.clone())
    } else {
        Err(g.status)
    }
}

extern "win64" fn partmgr_pnp_query_devrels(
    device: Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
) -> DriverStatus {
    let relation = { request.read().pnp.as_ref().unwrap().relation };
    if relation != DeviceRelationType::BusRelations {
        return DriverStatus::NotImplemented;
    }

    let pmx = ext::<PartMgrExt>(&device);

    if pmx
        .enumerated
        .swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        return DriverStatus::Continue;
    }

    let di = if let Some(ref buf) = pmx.disk_info.get() {
        if buf.len() == core::mem::size_of::<DiskInfo>() {
            unsafe { ptr::read_unaligned(buf.as_ptr() as *const DiskInfo) }
        } else {
            return DriverStatus::Continue;
        }
    } else {
        return DriverStatus::Continue;
    };

    let sec_sz_u32 = di.logical_block_size;
    if sec_sz_u32 == 0 {
        return DriverStatus::Continue;
    }
    let sec_sz = sec_sz_u32 as usize;
    let hdr_bytes = match block_on(read_from_lower_async(&device, sec_sz as u64, sec_sz)) {
        Ok(b) => b,
        Err(st) => {
            return st;
        }
    };

    if hdr_bytes.len() < core::mem::size_of::<GptHeader>() {
        return DriverStatus::Continue;
    }

    let hdr: GptHeader = unsafe { ptr::read_unaligned(hdr_bytes.as_ptr() as *const GptHeader) };

    if &hdr.signature != b"EFI PART" {
        return DriverStatus::Continue;
    }
    if hdr.partition_entry_size != 128 || hdr.num_partition_entries == 0 {
        return DriverStatus::Continue;
    }

    let total_bytes = (hdr.num_partition_entries as usize) * (hdr.partition_entry_size as usize);
    let aligned_bytes = (total_bytes + (sec_sz - 1)) & !(sec_sz - 1);
    let entries = match block_on(read_from_lower_async(
        &device,
        hdr.partition_entry_lba.saturating_mul(sec_sz as u64),
        aligned_bytes,
    )) {
        Ok(b) => b,
        Err(st) => {
            return st;
        }
    };

    let parent_dn = match device.dev_node.get().unwrap().upgrade() {
        Some(dn) => dn,
        None => {
            return DriverStatus::DeviceNotReady;
        }
    };

    let disk_guid_s = guid_to_string(&hdr.disk_guid);

    let mut idx: u32 = 0;
    let mut found_count = 0;

    for ch in entries.chunks_exact(128) {
        let e: GptPartitionEntry =
            unsafe { ptr::read_unaligned(ch.as_ptr() as *const GptPartitionEntry) };

        if e.partition_type_guid == [0u8; 16] {
            continue;
        }
        idx += 1;

        if e.first_lba < hdr.first_usable_lba
            || e.last_lba > hdr.last_usable_lba
            || e.first_lba > e.last_lba
        {
            continue;
        }

        const ZERO: [u8; 16] = [0; 16];
        const EFI_SYSTEM: [u8; 16] = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ];
        const BIOS_BOOT: [u8; 16] = [
            0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x66, 0x64, 0x45,
            0x46, 0x49,
        ];
        let ptype = e.partition_type_guid;
        if ptype == ZERO || ptype == EFI_SYSTEM || ptype == BIOS_BOOT {
            continue;
        }

        let mut io_vt = IoVtable::new();
        io_vt.set(IoType::Read(partition_pdo_read), Synchronization::Sync, 0);
        io_vt.set(IoType::Write(partition_pdo_write), Synchronization::Sync, 0);

        let mut child_init = DeviceInit::new(io_vt, None);

        let mut vt = PnpVtable::new();
        vt.set(
            PnpMinorFunction::QueryResources,
            partition_pdo_query_resources,
        );
        child_init.pnp_vtable = Some(vt);
        child_init.set_dev_ext_default::<PartDevExt>();

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

        let pext = ext::<PartDevExt>(&pdo);
        pext.start_lba.call_once(|| e.first_lba);
        pext.end_lba.call_once(|| e.last_lba);

        let part_pi = PartitionInfo {
            disk: di,
            gpt_header: Some(hdr),
            gpt_entry: Some(e),
        };
        pext.part.call_once(|| part_pi);

        found_count += 1;
    }
    DriverStatus::Continue
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
