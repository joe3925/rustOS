#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use crate::alloc::vec;
use alloc::{string::String, sync::Arc, vec::Vec};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::kernel_types::async_types::AsyncRwLock;
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
use kernel_api::request::{RequestHandle, RequestType};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;

use spin::Once;

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
    dev.try_devext().expect("Failed to get volmgr dev ext")
}

#[repr(C)]
struct VolPdoExt {
    backing: Once<IoTarget>,
    part: Once<PartitionInfo>,
    cache: Once<AsyncRwLock<cache::VolumeCache>>,
    caching_enabled: AtomicBool,
    flush_running: AtomicBool,
}

impl Default for VolPdoExt {
    fn default() -> Self {
        Self {
            backing: Once::new(),
            part: Once::new(),
            cache: Once::new(),
            caching_enabled: AtomicBool::new(false),
            flush_running: AtomicBool::new(false),
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
    io_table.set(IoType::Read(vol_pdo_read), Synchronization::Sync, 0);
    io_table.set(IoType::Write(vol_pdo_write), Synchronization::Sync, 0);
    io_table.set(IoType::Flush(vol_pdo_flush), Synchronization::Sync, 0);

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
            .store(true, Ordering::Release);

        let sector_size = pi.disk.physical_block_size as usize;

        ext::<VolPdoExt>(&pdo).cache.call_once(|| {
            let mut c = cache::VolumeCache::new(20 * 1024 * 1024);
            c.set_block_size(1024 * 64, sector_size).unwrap();
            AsyncRwLock::new(c)
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

    if cache_enabled {
        if let Some(cache_lock) = ext::<VolPdoExt>(&dev).cache.get() {
            // Fast path: cache hit
            {
                let cache = cache_lock.read().await;
                let mut w = req.write();
                let dst = &mut w.data_slice_mut()[..len];
                if cache.lookup(offset, dst).is_ok() {
                    w.status = DriverStatus::Success;
                    return DriverStep::complete(DriverStatus::Success);
                }
            }

            // Miss: forward to backing device
            let status = pnp_send_request(tgt.clone(), req).await;
            if status != DriverStatus::Success {
                return DriverStep::complete(status);
            }

            // Fill cache with the data we just read; evict cold entries if needed.
            let data: alloc::vec::Vec<u8> = req.read().data_slice()[..len].to_vec();
            let fill_result = cache::VolumeCache::fill_clean_async(cache_lock, offset, &data).await;
            match fill_result {
                Ok(evicted) => {
                    flush_evicted_entries(cache_lock, evicted, tgt.clone()).await;
                }
                Err(cache::CacheError::CacheFull) => {
                    // All entries were flushing; nudge the coordinator.
                    if should_flush(cache_lock, len).await {
                        try_spawn_flush(&dev, tgt);
                    }
                }
                Err(_) => {}
            }

            return DriverStep::complete(status);
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

    if cache_enabled {
        if let Some(cache_lock) = ext::<VolPdoExt>(&dev).cache.get() {
            if !flush_write_through {
                // Write-back: absorb into cache, evicting cold entries if needed.
                let src_buf: alloc::vec::Vec<u8> = {
                    let r = req.read();
                    r.data_slice()[..len].to_vec()
                };
                match cache::VolumeCache::upsert_dirty_async(cache_lock, offset, &src_buf).await {
                    Ok(evicted) => {
                        flush_evicted_entries(cache_lock, evicted, tgt.clone()).await;
                        let mut w = req.write();
                        w.status = DriverStatus::Success;
                        return DriverStep::complete(DriverStatus::Success);
                    }
                    Err(cache::CacheError::CacheFull) => {
                        // All entries were flushing; fall through to write-through.
                        if should_flush(cache_lock, len).await {
                            try_spawn_flush(&dev, tgt.clone());
                        }
                    }
                    Err(_) => {}
                }
            } else {
                // Write-through: forward, then populate cache with the written data.
                let status = pnp_send_request(tgt.clone(), req).await;
                if status == DriverStatus::Success {
                    let data: alloc::vec::Vec<u8> = req.read().data_slice()[..len].to_vec();
                    match cache::VolumeCache::fill_clean_async(cache_lock, offset, &data).await {
                        Ok(evicted) => {
                            flush_evicted_entries(cache_lock, evicted, tgt.clone()).await;
                        }
                        Err(cache::CacheError::CacheFull) => {
                            if should_flush(cache_lock, len).await {
                                try_spawn_flush(&dev, tgt);
                            }
                        }
                        Err(_) => {}
                    }
                }
                return DriverStep::complete(status);
            }
        }
    }

    let status = pnp_send_request(tgt, req).await;
    DriverStep::complete(status)
}

/// Flush all dirty cache entries to the backing device (used by explicit Flush IRP).
/// Bypasses the 50 MiB cap — drains everything.
pub async fn flush_volume_cache(dev: &Arc<DeviceObject>) -> DriverStatus {
    let dx = ext::<VolPdoExt>(dev);

    let tgt = match dx.backing.get() {
        Some(t) => t.clone(),
        None => return DriverStatus::NoSuchDevice,
    };

    let cache_addr = match dx.cache.get() {
        Some(c) => c as *const AsyncRwLock<cache::VolumeCache> as usize,
        None => return DriverStatus::Success,
    };

    // Pass None for limit_bytes so the explicit flush drains everything.
    // SAFETY: cache_addr points into VolPdoExt which is kept alive by the Arc<DeviceObject>
    // that the caller holds, so it outlives this await.
    match cache::VolumeCache::flush_dirty(cache_addr, tgt, None).await {
        Ok(()) => DriverStatus::Success,
        Err(_) => DriverStatus::Unsuccessful,
    }
}

#[request_handler]
pub async fn vol_pdo_flush<'a, 'b>(
    dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let status = flush_volume_cache(dev).await;
    if status != DriverStatus::Success {
        return DriverStep::complete(status);
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

// ---------------------------------------------------------------------------
// Flush helpers (non-public, live here so lib.rs stays handler-only)
// ---------------------------------------------------------------------------

/// Coalesce evicted entries into contiguous runs under the write lock,
/// then spawn fire-and-forget write tasks after releasing it.
async fn flush_evicted_entries(
    cache_lock: &AsyncRwLock<cache::VolumeCache>,
    evicted: Vec<cache::EvictedEntry>,
    tgt: IoTarget,
) {
    let runs = {
        let mut cache = cache_lock.write().await;
        cache.coalesce_evicted(evicted)
    };
    let shell = cache::VolumeCache::spawn_evicted_writes(runs, tgt);
    {
        let mut cache = cache_lock.write().await;
        cache.recycle_evicted_scratch(shell);
    }
}

/// Returns true if a background flush should be triggered given the current
/// cache state and the size of the incoming data that didn't fit.
async fn should_flush(cache_lock: &AsyncRwLock<cache::VolumeCache>, incoming_len: usize) -> bool {
    let cache = cache_lock.read().await;
    let dirty = cache.dirty_bytes();
    let dirty_runs = cache.dirty_run_hint();
    let max_bytes = 20 * 1024 * 1024usize;
    // Flush if more than 60% of the cache is dirty, dirty data >= incoming,
    // or too many fragmented dirty runs (many small writes).
    dirty >= incoming_len
        || dirty * 100 / max_bytes > 60
        || (dirty_runs > 16 && dirty * 4 >= max_bytes) // lots of runs and 25% full
}

/// Attempt to spawn a background flush coordinator. If one is already running,
/// this is a no-op. The coordinator and all logic live in cache.rs.
///
/// # Safety
/// Both pointers are derived from VolPdoExt fields that live as long as the
/// Arc<DeviceObject>. The spawned coordinator task must not outlive the device.
fn try_spawn_flush(dev: &Arc<DeviceObject>, tgt: IoTarget) {
    let dx = ext::<VolPdoExt>(dev);
    let cache_addr = match dx.cache.get() {
        Some(c) => c as *const AsyncRwLock<cache::VolumeCache> as usize,
        None => return,
    };
    let flush_addr = &dx.flush_running as *const AtomicBool as usize;
    cache::VolumeCache::try_spawn_flush(cache_addr, tgt, flush_addr);
}
