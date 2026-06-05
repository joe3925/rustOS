#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![feature(likely_unlikely)]
extern crate alloc;

use alloc::sync::Weak;
use alloc::{boxed::Box, string::String, sync::Arc, vec};
use core::hint::{cold_path, likely, unlikely};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::AtomicBool;
use kernel_api::device::{DevExtRef, DevNode, DeviceInit, DeviceObject, DriverObject};
use kernel_api::kernel_types::dma::{Described, FromDevice, IoBuffer};
use kernel_api::kernel_types::io::{
    DeviceFlush, DeviceFlushDirty, DeviceRead, DeviceWrite, DiskInfo, GptHeader,
    GptPartitionEntry, PartitionInfo,
};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpVtable, driver_set_evt_device_add,
    pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
    pnp_send_request_to_stack_top,
};
use kernel_api::request::{
    DeviceControl, Flush, FlushDirty, Pnp, Read, RequestHandle, TraversalPolicy, Write,
};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;
use spin::Once;
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
    _driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStep {
    init.set_dev_ext_default::<PartMgrExt>();

    let pnp = PnpVtable::new();
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
    parent: Once<Weak<DevNode>>,
}

struct PartitionPdoIo;

impl DeviceRead for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        device: &Arc<DeviceObject>,
        request: &'b mut RequestHandle<'req, Read<'data>>,
        buf_len: usize,
    ) -> DriverStep {
        let dx = ext::<PartDevExt>(&device);
        let start_lba = *dx.start_lba.get().unwrap();
        let end_lba = *dx.end_lba.get().unwrap();
        let block_size = match dx.block_size.get() {
            Some(v) if *v != 0 => *v as u64,
            _ => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };

        let off_res = {
            let body = &request.read().body;
            let offset = body.offset;
            let len = body.len;
            if unlikely(buf_len != len) {
                cold_path();
                Err(DriverStatus::InvalidParameter)
            } else {
                let part_bytes = ((end_lba - start_lba + 1) << 9) as u64;
                if unlikely(offset + (buf_len as u64) > part_bytes) {
                    cold_path();
                    Err(DriverStatus::InvalidParameter)
                } else if unlikely(
                    offset % block_size != 0 || !(buf_len as u64).is_multiple_of(block_size),
                ) {
                    cold_path();
                    Err(DriverStatus::InvalidParameter)
                } else {
                    Ok(offset)
                }
            }
        };
        let off = match off_res {
            Ok(v) => v,
            Err(st) => {
                cold_path();
                return DriverStep::complete(st);
            }
        };

        let phys_off = off + ((start_lba as u64) << 9);
        request.set_traversal_policy(TraversalPolicy::ForwardLower);
        request.write().body.offset = phys_off;

        let status = pnp_send_request_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}

impl DeviceWrite for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        device: &Arc<DeviceObject>,
        request: &'b mut RequestHandle<'req, Write<'data>>,
        buf_len: usize,
    ) -> DriverStep {
        let dx = ext::<PartDevExt>(&device);
        let start_lba = *dx.start_lba.get().unwrap();
        let end_lba = *dx.end_lba.get().unwrap();
        let block_size = match dx.block_size.get() {
            Some(v) if *v != 0 => *v as u64,
            _ => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };

        let off_res = {
            let body = &request.read().body;
            let offset = body.offset;
            let len = body.len;
            if unlikely(buf_len != len) {
                cold_path();
                Err(DriverStatus::InvalidParameter)
            } else {
                let part_bytes = ((end_lba - start_lba + 1) << 9) as u64;
                if unlikely(offset + (buf_len as u64) > part_bytes) {
                    cold_path();
                    Err(DriverStatus::InvalidParameter)
                } else if unlikely(
                    offset % block_size != 0 || !(buf_len as u64).is_multiple_of(block_size),
                ) {
                    cold_path();
                    Err(DriverStatus::InvalidParameter)
                } else {
                    Ok(offset)
                }
            }
        };
        let off = match off_res {
            Ok(v) => v,
            Err(st) => {
                cold_path();
                return DriverStep::complete(st);
            }
        };

        let phys_off = off + ((start_lba as u64) << 9);

        // Move caller buffer into forwarded request to avoid copying
        request.set_traversal_policy(TraversalPolicy::ForwardLower);
        request.write().body.offset = phys_off;

        let status = pnp_send_request_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}

impl DeviceFlush for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        device: &Arc<DeviceObject>,
        request: &'b mut RequestHandle<'req, Flush>,
    ) -> DriverStep {
        let dx = ext::<PartDevExt>(&device);
        request.set_traversal_policy(TraversalPolicy::ForwardLower);
        let status = pnp_send_request_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}

impl DeviceFlushDirty for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        device: &Arc<DeviceObject>,
        request: &'b mut RequestHandle<'req, FlushDirty>,
    ) -> DriverStep {
        let dx = ext::<PartDevExt>(&device);
        request.set_traversal_policy(TraversalPolicy::ForwardLower);
        let status = pnp_send_request_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}

#[request_handler]
async fn partition_pdo_query_resources<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    request: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    {
        let w = request.write();
        let pnp = &mut w.body.request;
        let dx = ext::<PartDevExt>(&device);
        if let Some(pi) = dx.part.get() {
            pnp.data_out = RequestData::from_t((*pi).clone());
        }
    }

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn partmgr_start<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let dx = ext::<PartMgrExt>(&dev);

    let mut parent_req = RequestHandle::new(DeviceControl::new(
        IOCTL_DRIVE_IDENTIFY,
        RequestData::empty(),
    ));
    parent_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    let status = pnp_forward_request_to_next_lower(dev.clone(), &mut parent_req).await;
    if status != DriverStatus::Success {
        return DriverStep::complete(status);
    }

    if let Some(data) = parent_req.write().data().read_only().view::<DiskInfo>() {
        dx.disk_info.call_once(|| *data);
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
    let mut data = vec![0u8; len];
    let io_buf = IoBuffer::<Described, FromDevice>::from_slice_mut(&mut data[..]);
    let mut child_req = RequestHandle::new(Read {
        offset,
        len,
        no_buffer: false,
        buffer: io_buf,
    });
    child_req.set_traversal_policy(TraversalPolicy::ForwardLower);

    let status = pnp_forward_request_to_next_lower(dev.clone(), &mut child_req).await;

    drop(child_req);

    if likely(status == DriverStatus::Success) {
        Ok(data.into_boxed_slice())
    } else {
        cold_path();
        Err(status)
    }
}

#[request_handler]
pub async fn partmgr_pnp_query_devrels<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    request: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let relation = { request.read().body.request.relation };
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

        const EFI_SYSTEM: [u8; 16] = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ];
        const BIOS_BOOT: [u8; 16] = [
            0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x66, 0x64, 0x45,
            0x46, 0x49,
        ];
        let ptype = e.partition_type_guid;
        if ptype == EFI_SYSTEM || ptype == BIOS_BOOT {
            continue;
        }

        let mut child_init = DeviceInit::new();
        child_init.ops.read.register::<PartitionPdoIo>();
        child_init.ops.write.register::<PartitionPdoIo>();
        child_init.ops.flush.register::<PartitionPdoIo>();
        child_init.ops.flush_dirty.register::<PartitionPdoIo>();

        let vt = PnpVtable::new();
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
        pext.parent.call_once(|| {
            pdo.dev_node
                .get()
                .unwrap()
                .upgrade()
                .unwrap()
                .parent
                .get()
                .unwrap()
                .clone()
        });

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
