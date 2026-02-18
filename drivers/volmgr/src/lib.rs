#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use crate::alloc::vec;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_api::runtime::spawn;

use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::kernel_types::io::IoTarget;
use kernel_api::kernel_types::io::IoType;
use kernel_api::kernel_types::io::IoVtable;
use kernel_api::kernel_types::io::PartitionInfo;
use kernel_api::kernel_types::io::Synchronization;
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
use kernel_api::request::{Request, RequestHandle, RequestType};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;

use spin::Once;
use spin::RwLock;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

mod cache;

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
    dev.try_devext().expect("Failed to get partmgr dev ext")
}

#[repr(C)]
#[derive(Default)]
struct VolPdoExt {
    backing: Once<IoTarget>,
    part: Once<PartitionInfo>,
    cache: Once<RwLock<cache::VolumeCache>>,
    caching_enabled: AtomicBool,
}

#[repr(C)]
struct ReadCacheCtx {
    cache: *const RwLock<cache::VolumeCache>,
    tgt: IoTarget,
    dev: Arc<DeviceObject>,
    offset: u64,
    len: usize,
}

#[repr(C)]
struct WriteThroughCacheCtx {
    cache: *const RwLock<cache::VolumeCache>,
    offset: u64,
    dev: Arc<DeviceObject>,
    tgt: IoTarget,
    len: usize,
}

extern "win64" fn vol_cache_read_completion(req: &mut Request, ctx: usize) -> DriverStatus {
    let ctx_box = unsafe { Box::from_raw(ctx as *mut ReadCacheCtx) };

    let cache_ptr = ctx_box.cache;
    let tgt = ctx_box.tgt.clone();
    let fill_offset = ctx_box.offset;
    let fill_len = ctx_box.len;

    let cache_lock = unsafe { &*cache_ptr };

    if req.status != DriverStatus::Success {
        return req.status;
    }

    let data = req.data_slice();
    if fill_len > data.len() {
        return req.status;
    }

    let mut should_flush = false;
    {
        let mut cache = cache_lock.write();
        match cache.fill_clean(fill_offset, &data[..fill_len]) {
            Ok(()) => {}
            Err(cache::CacheError::CacheFull) => {
                if let Ok(pct) = cache.dirty_percent() {
                    let dirty_bytes_est =
                        ((pct as f64) * (20.0 * 1024.0 * 1024.0) / 100.0) as usize;

                    if pct > 60.0 || dirty_bytes_est >= fill_len {
                        should_flush = true;
                    }
                }
            }
            Err(cache::CacheError::UnalignedRange) => {}
            Err(_) => {
                // TODO: decide whether to ignore, invalidate, or treat as bug.
            }
        }
    }

    if should_flush {
        let tgt_task = tgt.clone();
        let dev_clone = ctx_box.dev.clone();
        let fill_offset_task = fill_offset;
        let data_task: alloc::vec::Vec<u8> = data[..fill_len].to_vec(); // own the bytes

        spawn(async move {
            let dev_ext = dev_clone.try_devext::<VolPdoExt>().unwrap();
            let _ = cache::VolumeCache::flush_dirty_for_new(
                dev_ext.cache.get().unwrap(),
                tgt_task.clone(),
                fill_offset_task,
                data_task.into(),
            )
            .await;
        });
    }

    req.status
}

extern "win64" fn vol_cache_write_through_completion(
    req: &mut Request,
    ctx: usize,
) -> DriverStatus {
    let ctx_box = unsafe { Box::from_raw(ctx as *mut WriteThroughCacheCtx) };

    let cache_lock = unsafe { &*ctx_box.cache };

    if req.status != DriverStatus::Success {
        return req.status;
    }

    let tgt = ctx_box.tgt.clone();
    let fill_offset = ctx_box.offset;
    let fill_len = ctx_box.len;

    let data = req.data_slice();
    if fill_len > data.len() {
        return req.status;
    }

    let mut should_flush = false;
    {
        let mut cache = cache_lock.write();

        match cache.fill_clean(fill_offset, &data[..fill_len]) {
            Ok(()) => {}
            Err(cache::CacheError::CacheFull) => {
                if let Ok(pct) = cache.dirty_percent() {
                    let dirty_bytes_est =
                        ((pct as f64) * (20.0 * 1024.0 * 1024.0) / 100.0) as usize;

                    if pct > 60.0 || dirty_bytes_est >= fill_len {
                        should_flush = true;
                    }
                }
            }
            Err(cache::CacheError::UnalignedRange) => {}
            Err(_) => {}
        }
    }

    if should_flush {
        let tgt_task = tgt.clone();
        let dev_clone = ctx_box.dev.clone();
        let fill_offset_task = fill_offset;
        let data_task: alloc::vec::Vec<u8> = data[..fill_len].to_vec();

        spawn(async move {
            let dev_ext = dev_clone.try_devext::<VolPdoExt>().unwrap();
            let _ = cache::VolumeCache::flush_dirty_for_new(
                dev_ext.cache.get().unwrap(),
                tgt_task,
                fill_offset_task,
                data_task.into(),
            )
            .await;
        });
    }

    req.status
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
    io_table.set(IoType::Read(vol_pdo_read), Synchronization::Sync, 0);
    io_table.set(IoType::Write(vol_pdo_write), Synchronization::Sync, 0);

    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::QueryResources, vol_pdo_query_resources);

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
        ext::<VolPdoExt>(&pdo).backing.call_once(|| tgt);
        ext::<VolPdoExt>(&pdo)
            .part
            .call_once(|| dx.part.get().unwrap().clone());
        ext::<VolPdoExt>(&pdo)
            .caching_enabled
            .store(false, Ordering::Release);

        let sector_size = pi.disk.physical_block_size as usize;

        ext::<VolPdoExt>(&pdo).cache.call_once(|| {
            let mut c = cache::VolumeCache::new(20 * 1024 * 1024);

            // TODO: block size policy should be configurable per volume.
            c.set_block_size(1024 * 64, sector_size).unwrap();

            RwLock::new(c)
        });
    }

    DriverStep::Continue
}

#[request_handler]
pub async fn vol_pdo_read<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    buf_len: usize,
) -> DriverStep {
    let tgt = {
        let dx = ext::<VolPdoExt>(&dev);
        match dx.backing.get() {
            Some(t) => t.clone(),
            None => return DriverStep::complete(DriverStatus::NoSuchDevice),
        }
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

    let cache_enabled = ext::<VolPdoExt>(&dev)
        .caching_enabled
        .load(Ordering::Acquire);

    if cache_enabled && let Some(cache_lock) = ext::<VolPdoExt>(&dev).cache.get() {
        {
            let cache = cache_lock.read();
            let mut w = req.write();
            let dst = &mut w.data_slice_mut()[..len];

            if cache.lookup(offset, dst).is_ok() {
                w.status = DriverStatus::Success;
                return DriverStep::complete(DriverStatus::Success);
            }
        }

        {
            let cache_ptr = cache_lock as *const RwLock<cache::VolumeCache>;
            let ctx = Box::new(ReadCacheCtx {
                cache: cache_ptr,
                offset,
                len,
                tgt: tgt.clone(),
                dev: dev.clone(),
            });
            let ctx_ptr = Box::into_raw(ctx) as usize;

            let mut w = req.write();
            w.add_completion(vol_cache_read_completion, ctx_ptr);
        }
    }

    let status = pnp_send_request(tgt, req).await;
    DriverStep::complete(status)
}

#[request_handler]
pub async fn vol_pdo_write<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    buf_len: usize,
) -> DriverStep {
    let tgt = {
        let dx = ext::<VolPdoExt>(&dev);
        match dx.backing.get() {
            Some(t) => t.clone(),
            None => return DriverStep::complete(DriverStatus::NoSuchDevice),
        }
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

    let cache_enabled = ext::<VolPdoExt>(&dev)
        .caching_enabled
        .load(Ordering::Acquire);

    if cache_enabled && let Some(cache_lock) = ext::<VolPdoExt>(&dev).cache.get() {
        if !flush_write_through {
            let res = {
                let mut cache = cache_lock.write();
                let r = req.read();
                let src = &r.data_slice()[..len];
                cache.upsert_dirty(offset, src)
            };

            match res {
                Ok(()) => {
                    let mut w = req.write();
                    w.status = DriverStatus::Success;
                    return DriverStep::complete(DriverStatus::Success);
                }
                Err(cache::CacheError::CacheFull) => {
                    let should_flush = cache_lock
                        .read()
                        .dirty_percent()
                        .ok()
                        .map(|pct| {
                            pct > 60.0 || (pct / 100.0) * (20 * 1024 * 1024) as f32 >= len as f32
                        })
                        .unwrap_or(false);

                    if should_flush {
                        let data_copy: alloc::vec::Vec<u8> = {
                            let r = req.read();
                            r.data_slice()[..len].to_vec()
                        };

                        let dev_clone = dev.clone();
                        let tgt_clone = tgt.clone();
                        let offset_clone = offset;

                        spawn(async move {
                            let dev_ext = dev_clone.try_devext::<VolPdoExt>().unwrap();
                            if let Some(lock) = dev_ext.cache.get() {
                                let _ = cache::VolumeCache::flush_dirty_for_new(
                                    lock,
                                    tgt_clone,
                                    offset_clone,
                                    data_copy.into(),
                                )
                                .await;
                            }
                        });

                        let cache_ptr = cache_lock as *const RwLock<cache::VolumeCache>;
                        let ctx = Box::new(WriteThroughCacheCtx {
                            cache: cache_ptr,
                            tgt: tgt.clone(),
                            dev: dev.clone(),
                            offset,
                            len,
                        });
                        let ctx_ptr = Box::into_raw(ctx) as usize;

                        let mut w = req.write();
                        w.add_completion(vol_cache_write_through_completion, ctx_ptr);
                    }
                }
                Err(_) => {}
            }
        } else {
            let cache_ptr = cache_lock as *const RwLock<cache::VolumeCache>;
            let ctx = Box::new(WriteThroughCacheCtx {
                cache: cache_ptr,
                tgt: tgt.clone(),
                dev: dev.clone(),
                offset,
                len,
            });
            let ctx_ptr = Box::into_raw(ctx) as usize;

            let mut w = req.write();
            w.add_completion(vol_cache_write_through_completion, ctx_ptr);
        }
    }

    let status = pnp_send_request(tgt, req).await;
    DriverStep::complete(status)
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
