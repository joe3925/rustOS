#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![allow(async_fn_in_trait)]

extern crate alloc;

use crate::alloc::vec;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::panic::PanicInfo;
use core::sync::atomic::AtomicBool;
use kernel_api::async_ffi::FfiFuture;
use kernel_api::async_ffi::FutureExt;

use futures::future::BoxFuture;

use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::kernel_types::io::IoTarget;
use kernel_api::kernel_types::io::IoType;
use kernel_api::kernel_types::io::IoVtable;
use kernel_api::kernel_types::io::PartitionInfo;
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::pnp::DeviceRelationType;
use kernel_api::pnp::DriverStep;
use kernel_api::pnp::PnpMinorFunction;
use kernel_api::pnp::PnpRequest;
use kernel_api::pnp::PnpVtable;
use kernel_api::pnp::QueryIdType;
use kernel_api::pnp::driver_set_evt_device_add;
use kernel_api::pnp::pnp_create_child_devnode_and_pdo_with_init;
use kernel_api::pnp::pnp_forward_request_to_next_lower;
use kernel_api::pnp::pnp_get_device_target;
use kernel_api::pnp::pnp_send_request;
use kernel_api::request::{RequestHandle, RequestType, TraversalPolicy};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;

use spin::Once;

use crate::cache::{CacheConfig, CacheError, VolumeCache, VolumeCacheBackend, VolumeCacheOps};

mod cache;
mod cache_core;
mod cache_traits;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const BLOCK_SIZE: usize = 1024 * 16;

struct CacheBackend {
    target: IoTarget,
}

impl CacheBackend {
    fn new(target: IoTarget) -> Self {
        Self { target }
    }
}

impl VolumeCacheBackend for CacheBackend {
    type Error = DriverStatus;

    fn read_block<'a>(&'a self, lba: u64, out: &'a mut [u8]) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let offset = lba * BLOCK_SIZE as u64;
            let len = out.len();
            let mut req = RequestHandle::new(
                RequestType::Read { offset, len },
                RequestData::from_boxed_bytes(vec![0u8; len].into_boxed_slice()),
            );
            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), &mut req).await;
            if status != DriverStatus::Success {
                return Err(status);
            }
            let guard = req.read();
            let data = guard.data_slice();
            out.copy_from_slice(&data[..len]);
            Ok(())
        }
        .into_ffi()
    }

    fn write_block<'a>(&'a self, lba: u64, data: &'a [u8]) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let offset = lba * BLOCK_SIZE as u64;
            let len = data.len();
            let buf = RequestData::from_boxed_bytes(data.to_vec().into_boxed_slice());
            let mut req = RequestHandle::new(
                RequestType::Write {
                    offset,
                    len,
                    flush_write_through: false,
                },
                buf,
            );
            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), &mut req).await;
            if status != DriverStatus::Success {
                return Err(status);
            }
            Ok(())
        }
        .into_ffi()
    }

    fn flush_device(&self) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut req = RequestHandle::new(RequestType::Flush, RequestData::empty());
            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), &mut req).await;
            if status != DriverStatus::Success {
                return Err(status);
            }
            Ok(())
        }
        .into_ffi()
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    panic_common(MOD_NAME, info)
}

#[repr(C)]
#[derive(Default)]
struct VolExt {
    part: Once<PartitionInfo>,
    enumerated: AtomicBool,
}

#[inline]
pub fn ext<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("Failed to get volmgr dev ext")
}

type VolCache = VolumeCache<CacheBackend, BLOCK_SIZE>;

#[repr(C)]
struct VolPdoExt {
    backing: Once<IoTarget>,
    part: Once<PartitionInfo>,
    cache: Once<Arc<VolCache>>,
}

impl Default for VolPdoExt {
    fn default() -> Self {
        Self {
            backing: Once::new(),
            part: Once::new(),
            cache: Once::new(),
        }
    }
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
    driver_set_evt_device_add(driver, vol_device_add);
    DriverStatus::Success
}

pub extern "win64" fn vol_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, vol_prepare_hardware);
    pnp_vtable.set(
        PnpMinorFunction::QueryDeviceRelations,
        vol_enumerate_devices,
    );

    dev_init.set_dev_ext_default::<VolExt>();
    dev_init.pnp_vtable = Some(pnp_vtable);
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn vol_prepare_hardware<'a, 'b>(
    dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let mut query_req = RequestHandle::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::DeviceId,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
        RequestData::empty(),
    );

    let st = pnp_forward_request_to_next_lower(dev.clone(), &mut query_req).await;
    if st == DriverStatus::NoSuchDevice {
        return DriverStep::complete(DriverStatus::Success);
    }

    let dx = ext::<VolExt>(&dev);
    let status = query_req.read().status;
    if status != DriverStatus::Success {
        return DriverStep::complete(status);
    }

    let pi_opt: Option<PartitionInfo> = {
        let mut req = query_req.write();
        let pnp = req.pnp.as_mut().unwrap();
        pnp.data_out.try_take::<PartitionInfo>()
    };
    if let Some(pi) = pi_opt {
        dx.part.call_once(|| pi);
    }

    DriverStep::Continue
}

#[request_handler]
pub async fn vol_enumerate_devices<'a, 'b>(
    device: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let dx = ext::<VolExt>(&device);

    let binding = dx.part.get();
    let pi = if let Some(ref pi) = binding {
        pi
    } else {
        return DriverStep::Continue;
    };

    let binding = (pi.gpt_header, pi.gpt_entry);
    let (_hdr, ent) = if let (Some(ref hdr), Some(ref ent)) = binding {
        (hdr, ent)
    } else {
        return DriverStep::Continue;
    };

    if dx
        .enumerated
        .swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        return DriverStep::Continue;
    }

    let parent_dn = if let Some(dn) = device.dev_node.get().unwrap().upgrade() {
        dn
    } else {
        return DriverStep::complete(DriverStatus::Unsuccessful);
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
        return DriverStep::Continue;
    }

    let part_guid_s = guid_to_string(&ent.unique_partition_guid);
    let name = alloc::format!("Volume{}", &part_guid_s[..8]);
    let inst = alloc::format!("STOR\\VOLUME\\{}\\0000", part_guid_s);

    let ids = DeviceIds {
        hardware: vec!["STOR\\Volume".into(), "STOR\\Volume\\GPT".into()],
        compatible: vec!["STOR\\Volume".into()],
    };

    let mut io_table = IoVtable::new();
    io_table.set(IoType::Read(vol_pdo_read), 0);
    io_table.set(IoType::Write(vol_pdo_write), 0);
    io_table.set(IoType::Flush(vol_pdo_flush), 0);

    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::QueryResources, vol_pdo_query_resources);
    pnp_vtable.set(PnpMinorFunction::RemoveDevice, vol_pdo_remove_device);

    let mut init = DeviceInit::new(io_table, Some(pnp_vtable));
    init.set_dev_ext_default::<VolPdoExt>();

    let (_dn, pdo) = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn,
        name,
        inst,
        ids,
        Some("volume".into()),
        init,
    );

    if let Some(tgt) = pnp_get_device_target(&parent_dn.instance_path) {
        let pdx = ext::<VolPdoExt>(&pdo);
        let tgt_clone = tgt.clone();
        pdx.backing.call_once(|| tgt);
        pdx.part.call_once(|| dx.part.get().unwrap().clone());

        let backend = Arc::new(CacheBackend::new(tgt_clone));
        let cfg = CacheConfig::new(1024 * 1024 * 20 / BLOCK_SIZE);
        if let Ok(cache) = VolCache::new(backend, cfg) {
            pdx.cache.call_once(|| Arc::new(cache));
        }
    }

    DriverStep::Continue
}

#[request_handler]
pub async fn vol_pdo_read<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    buf_len: usize,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(&dev);

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let (offset, len_req) = {
        let r = req.read();
        match r.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    let mut len = len_req;
    len = core::cmp::min(len, buf_len);
    len = core::cmp::min(len, req.read().data_len());

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let mut guard = req.write();
    let buf = &mut guard.data_slice_mut()[..len];
    match cache.read_at(offset, buf).await {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(CacheError::Backend(s)) => DriverStep::complete(s),
        Err(_) => DriverStep::complete(DriverStatus::Unsuccessful),
    }
}

#[request_handler]
pub async fn vol_pdo_write<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    buf_len: usize,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(&dev);

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let (offset, len_req, flush_write_through) = match req.read().kind {
        RequestType::Write {
            offset,
            len,
            flush_write_through,
        } => (offset, len, flush_write_through),
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    let mut len = len_req;
    len = core::cmp::min(len, buf_len);
    len = core::cmp::min(len, req.read().data_len());

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let data = req.read().data_slice()[..len].to_vec();

    let result = if flush_write_through {
        cache.write_through_at(offset, &data).await
    } else {
        cache.write_at(offset, &data).await
    };

    match result {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(CacheError::Backend(s)) => DriverStep::complete(s),
        Err(_) => DriverStep::complete(DriverStatus::Unsuccessful),
    }
}

#[request_handler]
pub async fn vol_pdo_flush<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(dev);

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let is_dirty_only = matches!(req.read().kind, RequestType::FlushDirty);

    if is_dirty_only {
        cache.flush_background_pass().await;
        DriverStep::complete(DriverStatus::Success)
    } else {
        match cache.flush().await {
            Ok(()) => DriverStep::complete(DriverStatus::Success),
            Err(CacheError::Backend(s)) => DriverStep::complete(s),
            Err(_) => DriverStep::complete(DriverStatus::Unsuccessful),
        }
    }
}

#[request_handler]
pub async fn vol_pdo_remove_device<'a, 'b>(
    dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(dev);

    if let Some(cache) = dx.cache.get() {
        let _ = cache.close_and_flush().await;
    }

    DriverStep::Continue
}

#[request_handler]
async fn vol_pdo_query_resources<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let status = {
        let mut w = req.write();
        if let Some(pnp) = w.pnp.as_mut() {
            if let Some(pi) = ext::<VolPdoExt>(&pdo).part.get() {
                pnp.data_out = RequestData::from_t(pi.clone());
            } else {
                pnp.data_out = RequestData::empty();
            }
            DriverStatus::Success
        } else {
            DriverStatus::InvalidParameter
        }
    };

    DriverStep::complete(status)
}
