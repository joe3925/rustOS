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
use kernel_api::device::{open_public_protocol, publish_stack_protocol, register_protocol};
use kernel_api::dma::dma::IoBufferBackingConfig;
use kernel_api::dma::dma::{IoBufferBacking, IoBufferBackingDesc};
use kernel_api::kernel_types::dma::{FromDevice, IoBuffer};
use kernel_api::kernel_types::io::{
    DeviceFlush, DeviceFlushDirty, DeviceFlushDirtyOp, DeviceFlushOp, DeviceRead, DeviceReadOp,
    DeviceWrite, DeviceWriteOp, DiskInfo, DiskInfoProtocol, DiskInfoProtocolVTable, GptHeader,
    GptPartitionEntry, PartitionInfo, PartitionInfoProtocol, PartitionInfoProtocolVTable,
};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::IoctlData;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpOp, PnpOps, driver_set_evt_device_add, io, pnp,
    pnp_create_child_devnode_and_pdo_with_init,
};
use kernel_api::request::{DeviceControl, Flush, FlushDirty, Read, Write};
use kernel_api::status::DriverStatus;
use kernel_api::{println, request_handler};
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
pub unsafe extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, partmgr_device_add);
    DriverStatus::Success
}

pub extern "C" fn partmgr_device_add(
    _driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStep {
    init.set_dev_ext_default::<PartMgrExt>();

    let mut pnp = PnpOps::new();
    pnp.init_complete.set(partmgr_init_complete);
    pnp.query_device_relations.set(partmgr_pnp_query_devrels);
    init.pnp_ops = Some(pnp);

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

fn partition_len_bytes(start_lba: u64, end_lba: u64) -> Option<u64> {
    if end_lba < start_lba {
        return None;
    }

    end_lba
        .checked_sub(start_lba)?
        .checked_add(1)?
        .checked_mul(512)
}

fn validate_partition_read_chain<'io>(
    first: &Read<'io>,
    part_bytes: u64,
    block_size: u64,
) -> Result<(), DriverStatus> {
    for read in first.iter() {
        if read.len == 0 {
            continue;
        }

        if !read.no_buffer {
            let Some(buffer) = read.buffer.as_ref() else {
                return Err(DriverStatus::InvalidParameter);
            };

            if buffer.len() < read.len {
                return Err(DriverStatus::InvalidParameter);
            }
        }

        let end = read
            .offset
            .checked_add(read.len as u64)
            .ok_or(DriverStatus::InvalidParameter)?;

        if end > part_bytes {
            return Err(DriverStatus::InvalidParameter);
        }

        if read.offset % block_size != 0 || !(read.len as u64).is_multiple_of(block_size) {
            return Err(DriverStatus::InvalidParameter);
        }
    }

    Ok(())
}

fn validate_partition_write_chain<'io>(
    first: &Write<'io>,
    part_bytes: u64,
    block_size: u64,
) -> Result<(), DriverStatus> {
    for write in first.iter() {
        if write.len == 0 {
            continue;
        }

        if !write.no_buffer {
            let Some(buffer) = write.buffer.as_ref() else {
                return Err(DriverStatus::InvalidParameter);
            };

            if buffer.len() < write.len {
                return Err(DriverStatus::InvalidParameter);
            }
        }

        let end = write
            .offset
            .checked_add(write.len as u64)
            .ok_or(DriverStatus::InvalidParameter)?;

        if end > part_bytes {
            return Err(DriverStatus::InvalidParameter);
        }

        if write.offset % block_size != 0 || !(write.len as u64).is_multiple_of(block_size) {
            return Err(DriverStatus::InvalidParameter);
        }
    }

    Ok(())
}

fn translate_read_chain<'io>(first: &mut Read<'io>, base: u64) -> Result<(), DriverStatus> {
    for read in first.iter_mut() {
        read.offset = read
            .offset
            .checked_add(base)
            .ok_or(DriverStatus::InvalidParameter)?;
    }

    Ok(())
}

fn translate_write_chain<'io>(first: &mut Write<'io>, base: u64) -> Result<(), DriverStatus> {
    for write in first.iter_mut() {
        write.offset = write
            .offset
            .checked_add(base)
            .ok_or(DriverStatus::InvalidParameter)?;
    }

    Ok(())
}

impl DeviceRead for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        device: &Arc<DeviceObject>,
        request: &'b mut Read<'data>,
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

        let part_bytes = match partition_len_bytes(start_lba, end_lba) {
            Some(bytes) => bytes,
            None => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };

        let base = match start_lba.checked_mul(512) {
            Some(base) => base,
            None => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };

        {
            let body = &request;
            if let Err(status) = validate_partition_read_chain(body, part_bytes, block_size) {
                cold_path();
                return DriverStep::complete(status);
            }
        }

        {
            if let Err(status) = translate_read_chain(request, base) {
                cold_path();
                return DriverStep::complete(status);
            }
        }

        let status = io::send_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}

impl DeviceWrite for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        device: &Arc<DeviceObject>,
        request: &'b mut Write<'data>,
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

        let part_bytes = match partition_len_bytes(start_lba, end_lba) {
            Some(bytes) => bytes,
            None => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };

        let base = match start_lba.checked_mul(512) {
            Some(base) => base,
            None => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };

        {
            let body = &request;
            if let Err(status) = validate_partition_write_chain(body, part_bytes, block_size) {
                cold_path();
                return DriverStep::complete(status);
            }
        }

        {
            if let Err(status) = translate_write_chain(request, base) {
                cold_path();
                return DriverStep::complete(status);
            }
        }

        let status = io::send_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}
impl DeviceFlush for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(device: &Arc<DeviceObject>, request: &'b mut Flush) -> DriverStep {
        let dx = ext::<PartDevExt>(&device);
        let status = io::send_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}

impl DeviceFlushDirty for PartitionPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        device: &Arc<DeviceObject>,
        request: &'b mut FlushDirty,
    ) -> DriverStep {
        let dx = ext::<PartDevExt>(&device);
        let status = io::send_to_stack_top(dx.parent.get().unwrap().clone(), request).await;

        DriverStep::complete(status)
    }
}

#[request_handler]
async fn partmgr_pdo_start<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut kernel_api::pnp::StartDevice,
) -> DriverStep {
    if let Some(dn) = dev.dev_node.get() {
        if let Some(dn) = dn.upgrade() {
            register_protocol::<PartitionInfoProtocol>(dev, &PARTITION_INFO_VTABLE);
            publish_stack_protocol::<PartitionInfoProtocol>(&dn);
        }
    }
    DriverStep::Continue
}

#[request_handler]
pub async fn partition_pdo_register_dma_backing<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    request: &'b mut kernel_api::pnp::RegisterDmaBacking<'data>,
) -> DriverStep {
    let dx = ext::<PartDevExt>(&device);

    let Some(parent) = dx.parent.get() else {
        cold_path();
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    let status = pnp::send_to_stack_top(parent.clone(), request).await;

    DriverStep::complete(status)
}
#[request_handler]
pub async fn partmgr_init_complete<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut kernel_api::pnp::InitComplete,
) -> DriverStep {
    let dx = ext::<PartMgrExt>(&dev);

    let devnode = dev.dev_node.get().unwrap().upgrade().unwrap();
    let proto = match open_public_protocol::<DiskInfoProtocol>(&devnode) {
        Ok(p) => p,
        Err(e) => {
            cold_path();
            return DriverStep::complete(e);
        }
    };

    let di = match (proto.query)(&proto.provider()) {
        Ok(di) => di,
        Err(e) => {
            cold_path();
            return DriverStep::complete(e);
        }
    };

    dx.disk_info.call_once(|| di);

    DriverStep::Continue
}

async fn read_from_lower_async(
    dev: &Arc<DeviceObject>,
    offset: u64,
    len: usize,
) -> Result<Box<[u8]>, DriverStatus> {
    let mut data = vec![0u8; len];
    let io_buf = IoBufferBacking::new(
        IoBufferBackingDesc::SliceMut(&mut data),
        IoBufferBackingConfig::default(),
    )
    .expect("io_buf creation for read_from_lower_async failed");
    let mut child_req = Read::new(
        offset,
        len,
        false,
        Some(
            io_buf
                .create_from_device(0, len)
                .expect("io_buf creation for read_from_lower_async failed"),
        ),
    );
    let status = io::send_next_lower(dev.clone(), &mut child_req).await;

    drop(child_req);
    drop(io_buf);
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
    _op: PnpOp,
    request: &'b mut kernel_api::pnp::QueryDeviceRelations,
) -> DriverStep {
    let relation = request.relation;
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
        child_init.ops.register::<DeviceReadOp, PartitionPdoIo>();
        child_init.ops.register::<DeviceWriteOp, PartitionPdoIo>();
        child_init.ops.register::<DeviceFlushOp, PartitionPdoIo>();
        child_init
            .ops
            .register::<DeviceFlushDirtyOp, PartitionPdoIo>();

        let mut pnp_vt = PnpOps::new();
        pnp_vt.start_device.set(partmgr_pdo_start);
        pnp_vt
            .register_dma_backing
            .set(partition_pdo_register_dma_backing);
        child_init.pnp_ops = Some(pnp_vt);
        child_init.set_dev_ext_default::<PartDevExt>();

        let name = alloc::format!("Partition{}", idx);
        let inst = alloc::format!("STOR\\PARTITION\\{}\\{:04}", disk_guid_s, idx);
        let ids = DeviceIds {
            hardware: vec!["STOR\\Partition".into(), "STOR\\Partition\\GPT".into()],
            compatible: vec!["STOR\\Partition".into()],
        };

        let (dn_child, pdo) = pnp_create_child_devnode_and_pdo_with_init(
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
        pext.block_size.call_once(|| di.logical_block_size.max(1));
        pext.parent.call_once(|| Arc::downgrade(&parent_dn));

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

extern "C" fn part_partition_info(
    device: &Arc<DeviceObject>,
) -> Result<PartitionInfo, DriverStatus> {
    let dx = ext::<PartDevExt>(device);
    if let Some(pi) = dx.part.get() {
        Ok(pi.clone())
    } else {
        Err(DriverStatus::Unsuccessful)
    }
}
const PARTITION_INFO_VTABLE: PartitionInfoProtocolVTable = PartitionInfoProtocolVTable {
    query: part_partition_info,
};
