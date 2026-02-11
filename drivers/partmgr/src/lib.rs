#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec};
use core::ptr;
use core::sync::atomic::AtomicBool;
use kernel_api::device::{DevExtRef, DeviceInit, DeviceObject, DriverObject};
use kernel_api::kernel_types::io::{
    DiskInfo, GptHeader, GptPartitionEntry, IoType, IoVtable, PartitionInfo, Synchronization,
};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpVtable, driver_set_evt_device_add,
    pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
    pnp_send_request_to_stack_top,
};
use kernel_api::request::{Request, RequestHandle, RequestType, TraversalPolicy};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;
use spin::Once;

#[cfg(not(test))]
use core::panic::PanicInfo;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    panic_common(MOD_NAME, info)
}

const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, partmgr_device_add);
    DriverStatus::Success
}

pub extern "win64" fn partmgr_device_add(
    _driver: Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStep {
    init.set_dev_ext_default::<PartMgrExt>();

    let mut pnp = PnpVtable::new();
    pnp.set(PnpMinorFunction::StartDevice, partmgr_start);
    pnp.set(
        PnpMinorFunction::QueryDeviceRelations,
        partmgr_pnp_query_devrels,
    );
    init.pnp_vtable = Some(pnp);

    DriverStep::complete(DriverStatus::Success)
}

#[repr(C)]
#[derive(Default)]
struct PartMgrExt {
    enumerated: AtomicBool,
    disk_info: Once<DiskInfo>, // raw bytes of DiskInfo (size_of::<DiskInfo>())
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
    block_size: Once<u32>,
    part: Once<PartitionInfo>,
}

#[request_handler]
async fn partition_pdo_query_resources<'a, 'b>(
    device: Arc<DeviceObject>,
    request: &'b mut RequestHandle<'a>,
) -> DriverStep {
    {
        let mut w = request.write();
        if let Some(pnp) = w.pnp.as_mut() {
            let dx = ext::<PartDevExt>(&device);
            if let Some(pi) = dx.part.get() {
                pnp.data_out = RequestData::from_t((*pi).clone());
            }
        }
    }

    DriverStep::complete(DriverStatus::Success)
}

async fn send_req_parent<'h, 'd>(
    dev: &Arc<DeviceObject>,
    req: &'h mut RequestHandle<'d>,
) -> DriverStatus {
    let parent = dev
        .dev_node
        .get()
        .unwrap()
        .upgrade()
        .unwrap()
        .parent
        .get()
        .unwrap()
        .clone();

    pnp_send_request_to_stack_top(parent, req).await
}
#[request_handler]
pub async fn partition_pdo_read<'a, 'b>(
    device: Arc<DeviceObject>,
    request: &'b mut RequestHandle<'a>,
    buf_len: usize,
) -> DriverStep {
    let dx = ext::<PartDevExt>(&device);
    let start_lba = *dx.start_lba.get().unwrap();
    let end_lba = *dx.end_lba.get().unwrap();
    let block_size = match dx.block_size.get() {
        Some(v) if *v != 0 => *v as u64,
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    let off_res = {
        let r = request.read();
        match r.kind {
            RequestType::Read { offset, len } => {
                if buf_len != len {
                    Err(DriverStatus::InvalidParameter)
                } else {
                    let part_bytes = ((end_lba - start_lba + 1) << 9) as u64;
                    if (offset as u64) + (buf_len as u64) > part_bytes {
                        Err(DriverStatus::InvalidParameter)
                    } else if (offset as u64) % block_size != 0
                        || (buf_len as u64) % block_size != 0
                    {
                        Err(DriverStatus::InvalidParameter)
                    } else {
                        Ok(offset)
                    }
                }
            }
            _ => Err(DriverStatus::InvalidParameter),
        }
    };
    let off = match off_res {
        Ok(v) => v,
        Err(st) => return DriverStep::complete(st),
    };

    let phys_off = off + ((start_lba as u64) << 9);

    // Allocate buffer for child request
    let child_data = RequestData::from_boxed_bytes(vec![0u8; buf_len].into_boxed_slice());

    let mut child_req = RequestHandle::new(
        RequestType::Read {
            offset: phys_off,
            len: buf_len,
        },
        child_data,
    );
    child_req.set_traversal_policy(TraversalPolicy::ForwardLower);

    let status = send_req_parent(&device, &mut child_req).await;

    // Copy data back to original request on success
    if status == DriverStatus::Success {
        let binding = child_req.read();
        let src = binding.data.as_slice();
        let mut w = request.write();
        w.data_slice_mut()[..src.len()].copy_from_slice(&src);
    }

    DriverStep::complete(status)
}

#[request_handler]
pub async fn partition_pdo_write<'a, 'b>(
    device: Arc<DeviceObject>,
    request: &'b mut RequestHandle<'a>,
    buf_len: usize,
) -> DriverStep {
    let dx = ext::<PartDevExt>(&device);
    let start_lba = *dx.start_lba.get().unwrap();
    let end_lba = *dx.end_lba.get().unwrap();
    let block_size = match dx.block_size.get() {
        Some(v) if *v != 0 => *v as u64,
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    let off_res = {
        let r = request.read();
        match r.kind {
            RequestType::Write {
                offset,
                len,
                flush_write_through,
            } => {
                if buf_len != len {
                    Err(DriverStatus::InvalidParameter)
                } else {
                    let part_bytes = ((end_lba - start_lba + 1) << 9) as u64;
                    if (offset as u64) + (buf_len as u64) > part_bytes {
                        Err(DriverStatus::InvalidParameter)
                    } else if (offset as u64) % block_size != 0
                        || (buf_len as u64) % block_size != 0
                    {
                        Err(DriverStatus::InvalidParameter)
                    } else {
                        Ok((offset, flush_write_through))
                    }
                }
            }
            _ => Err(DriverStatus::InvalidParameter),
        }
    };
    let (off, flush_write_through) = match off_res {
        Ok(v) => v,
        Err(st) => return DriverStep::complete(st),
    };

    let phys_off = off + ((start_lba as u64) << 9);

    // Copy data to child request
    let child_data = {
        let r = request.read();
        RequestData::from_boxed_bytes(r.data_slice().to_vec().into_boxed_slice())
    };

    let mut child = RequestHandle::new(
        RequestType::Write {
            offset: phys_off,
            len: buf_len,
            flush_write_through,
        },
        child_data,
    );
    child.set_traversal_policy(TraversalPolicy::ForwardLower);

    let status = send_req_parent(&device, &mut child).await;

    DriverStep::complete(status)
}
#[request_handler]
pub async fn partmgr_start<'a, 'b>(
    dev: Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let dx = ext::<PartMgrExt>(&dev);

    let mut parent_req = RequestHandle::new(
        RequestType::DeviceControl(IOCTL_DRIVE_IDENTIFY),
        RequestData::empty(),
    );
    parent_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    let status = pnp_forward_request_to_next_lower(dev.clone(), &mut parent_req).await;
    if status != DriverStatus::Success {
        return DriverStep::complete(status);
    }

    if let Some(data) = parent_req.write().take_data::<DiskInfo>() {
        dx.disk_info.call_once(|| data);
    } else {
        return DriverStep::complete(status);
    }

    DriverStep::Continue
}

async fn read_from_lower_async(
    dev: &Arc<DeviceObject>,
    offset: u64,
    len: usize,
) -> Result<Box<[u8]>, DriverStatus> {
    let mut child_req = RequestHandle::new(
        RequestType::Read { offset, len },
        RequestData::from_boxed_bytes(vec![0u8; len].into_boxed_slice()),
    );
    child_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    let status = pnp_forward_request_to_next_lower(dev.clone(), &mut child_req).await;
    if status == DriverStatus::Success {
        Ok(child_req.write().take_data_bytes())
    } else {
        Err(status)
    }
}

#[request_handler]
pub async fn partmgr_pnp_query_devrels<'a, 'b>(
    device: Arc<DeviceObject>,
    request: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let relation = { request.read().pnp.as_ref().unwrap().relation };
    if relation != DeviceRelationType::BusRelations {
        return DriverStep::complete(DriverStatus::NotImplemented);
    }

    let pmx = ext::<PartMgrExt>(&device);

    if pmx
        .enumerated
        .swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        return DriverStep::Continue;
    }

    let di = if let Some(buf) = pmx.disk_info.get() {
        buf
    } else {
        return DriverStep::Continue;
    };

    let sec_sz_u32 = di.logical_block_size;
    if sec_sz_u32 == 0 {
        return DriverStep::Continue;
    }
    let sec_sz = sec_sz_u32 as usize;
    let hdr_bytes = match read_from_lower_async(&device, sec_sz as u64, sec_sz).await {
        Ok(b) => b,
        Err(st) => {
            return DriverStep::complete(st);
        }
    };

    if hdr_bytes.len() < core::mem::size_of::<GptHeader>() {
        return DriverStep::Continue;
    }

    let hdr: GptHeader = unsafe { ptr::read_unaligned(hdr_bytes.as_ptr() as *const GptHeader) };

    if &hdr.signature != b"EFI PART" {
        return DriverStep::Continue;
    }
    if hdr.partition_entry_size != 128 || hdr.num_partition_entries == 0 {
        return DriverStep::Continue;
    }

    let total_bytes = (hdr.num_partition_entries as usize) * (hdr.partition_entry_size as usize);
    let aligned_bytes = (total_bytes + (sec_sz - 1)) & !(sec_sz - 1);
    let entries = match read_from_lower_async(
        &device,
        hdr.partition_entry_lba.saturating_mul(sec_sz as u64),
        aligned_bytes,
    )
    .await
    {
        Ok(b) => b,
        Err(st) => {
            return DriverStep::complete(st);
        }
    };

    let parent_dn = match device.dev_node.get().unwrap().upgrade() {
        Some(dn) => dn,
        None => {
            return DriverStep::complete(DriverStatus::DeviceNotReady);
        }
    };

    let disk_guid_s = guid_to_string(&hdr.disk_guid);

    let mut idx: u32 = 0;
    let mut _found_count = 0;

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

        let (_dn_child, pdo) = pnp_create_child_devnode_and_pdo_with_init(
            &parent_dn,
            name,
            inst,
            ids,
            Some("DiskPartition".into()),
            child_init,
        );

        let pext = ext::<PartDevExt>(&pdo);
        pext.start_lba.call_once(|| e.first_lba);
        pext.end_lba.call_once(|| e.last_lba);
        pext.block_size.call_once(|| sec_sz_u32.max(1));

        let part_pi = PartitionInfo {
            disk: *di,
            gpt_header: Some(hdr),
            gpt_entry: Some(e),
        };
        pext.part.call_once(|| part_pi);

        _found_count += 1;
    }
    DriverStep::Continue
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
