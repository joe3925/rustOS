#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![feature(likely_unlikely)]
#![allow(async_fn_in_trait)]

extern crate alloc;
use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::hint::{cold_path, unlikely};
use core::panic::PanicInfo;
use core::sync::atomic::AtomicBool;
use kernel_api::async_ffi::FfiFuture;
use kernel_api::async_ffi::FutureExt;
use kernel_api::dma::dma::IoBufferBacking;
use kernel_api::pnp::PnpMinorFunction::RegisterDmaBacking;
use kernel_api::println;

use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::kernel_types::dma::{Described, FromDevice, IoBuffer, ToDevice};
use kernel_api::kernel_types::io::PartitionInfo;
use kernel_api::kernel_types::io::{
    DeviceFlush, DeviceFlushDirty, DeviceFlushOwner, DeviceRead, DeviceWrite,
};
use kernel_api::kernel_types::io::{DmaBacking, IoTarget};
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
use kernel_api::request::{
    Flush, FlushDirty, FlushOwner, Pnp, Read, RequestHandle, TraversalPolicy, Write,
};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;

use spin::Once;

use crate::cache_core::core::VolumeCache;
use crate::cache_traits::{CacheConfig, CacheError, VolumeCacheBackend, VolumeCacheOps};

mod cache;
mod cache_core;
mod cache_traits;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const BLOCK_SIZE: usize = 1024 * 64;
const CACHE_CAPACITY_BYTES: usize = 1024 * 1024 * 50;

struct VolPdoIo;

impl DeviceRead for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Read<'data>>,
    ) -> DriverStep {
        vol_pdo_read_impl(dev, req).await
    }
}

impl DeviceWrite for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Write<'data>>,
    ) -> DriverStep {
        vol_pdo_write_impl(dev, req).await
    }
}

impl DeviceFlush for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Flush>,
    ) -> DriverStep {
        vol_pdo_flush_impl(dev, req).await
    }
}

impl DeviceFlushDirty for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FlushDirty>,
    ) -> DriverStep {
        vol_pdo_flush_dirty_impl(dev, req).await
    }
}

impl DeviceFlushOwner for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FlushOwner>,
    ) -> DriverStep {
        vol_pdo_flush_owner_impl(dev, req).await
    }
}

struct CacheBackend {
    target: IoTarget,
    /// Total addressable bytes for the volume (computed from partition info).
    volume_bytes: u64,
}

impl CacheBackend {
    fn new(target: IoTarget, volume_bytes: u64) -> Self {
        Self {
            target,
            volume_bytes,
        }
    }

    #[inline]
    fn block_len(&self, lba: u64) -> Option<usize> {
        let start = lba.checked_mul(BLOCK_SIZE as u64)?;
        if unlikely(start >= self.volume_bytes) {
            cold_path();
            return None;
        }
        let remaining = self.volume_bytes - start;
        Some(core::cmp::min(remaining, BLOCK_SIZE as u64) as usize)
    }

    #[inline]
    fn request_len_from_offset(&self, offset: u64, len: usize) -> Option<usize> {
        if offset >= self.volume_bytes {
            cold_path();
            return None;
        }
        let remaining = self.volume_bytes - offset;
        Some(core::cmp::min(len as u64, remaining) as usize)
    }
}

impl VolumeCacheBackend for CacheBackend {
    type Error = DriverStatus;

    fn read_phys_framed<'a, 'buffer>(
        &'a self,
        lba: u64,
        blocks: usize,
        buffer: IoBuffer<'buffer, 'buffer, Described, FromDevice>,
    ) -> FfiFuture<Result<usize, Self::Error>> {
        async move {
            if unlikely(blocks == 0) {
                cold_path();
                return Ok(0);
            }

            let Some(offset) = lba.checked_mul(BLOCK_SIZE as u64) else {
                cold_path();
                return Err(DriverStatus::InvalidParameter);
            };

            let mut total_len = 0usize;
            let mut block_idx = 0usize;
            while block_idx < blocks {
                let Some(block_lba) = lba.checked_add(block_idx as u64) else {
                    cold_path();
                    return Err(DriverStatus::InvalidParameter);
                };
                let block_len = match self.block_len(block_lba) {
                    Some(block_len) => block_len,
                    None => {
                        cold_path();
                        println!(
                            "volmgr: CacheBackend::read_phys_framed invalid lba {} for volume length {}",
                            block_lba, self.volume_bytes
                        );
                        return Err(DriverStatus::InvalidParameter);
                    }
                };
                let Some(next_total_len) = total_len.checked_add(block_len) else {
                    cold_path();
                    return Err(DriverStatus::InvalidParameter);
                };
                total_len = next_total_len;
                block_idx += 1;
            }

            if unlikely(buffer.len() < total_len) {
                cold_path();
                return Err(DriverStatus::InvalidParameter);
            }

            let mut req = RequestHandle::new(Read {
                offset,
                len: total_len,
                no_buffer: false,
                buffer: Some(buffer),
                next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            });
            req.set_traversal_policy(TraversalPolicy::ForwardLower);

            let status = pnp_send_request(self.target.clone(), &mut req).await;

            if unlikely(status != DriverStatus::Success) {
                cold_path();
                println!(
                    "volmgr: CacheBackend::read_phys_framed lower read failed at lba {} blocks {} len {}: {}",
                    lba, blocks, total_len, status
                );
                return Err(status);
            }

            Ok(total_len)
        }
        .into_ffi()
    }
    fn read_request<'a, 'req, 'data>(
        &'a self,
        req: &'a mut RequestHandle<'req, Read<'data>>,
    ) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let (first_offset, first_len) = {
                let mut r = req.write();
                let mut current: *mut Read<'data> = &mut r.body;
                let mut first_offset = 0u64;
                let mut first_len = 0usize;
                let mut first = true;

                while !current.is_null() {
                    let body = unsafe { &mut *current };
                    let offset = body.offset;
                    let len = body.len;

                    let max_len = match self.request_len_from_offset(offset, len) {
                        Some(max_len) => max_len,
                        None => {
                            cold_path();
                            println!(
                                "volmgr: CacheBackend::read_request invalid read offset {} len {} for volume length {}",
                                offset,
                                len,
                                self.volume_bytes
                            );
                            return Err(DriverStatus::InvalidParameter);
                        }
                    };

                    if unlikely(max_len == 0 || max_len != len) {
                        cold_path();
                        println!(
                            "volmgr: CacheBackend::read_request read exceeds volume offset {} len {} max_len {} volume length {}",
                            offset,
                            len,
                            max_len,
                            self.volume_bytes
                        );
                        return Err(DriverStatus::InvalidParameter);
                    }

                    if first {
                        first_offset = offset;
                        first_len = len;
                        first = false;
                    }

                    current = body.next.load(core::sync::atomic::Ordering::Acquire);
                }

                (first_offset, first_len)
            };

            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), req).await;
            if unlikely(status != DriverStatus::Success) {
                cold_path();
                println!(
                    "volmgr: CacheBackend::read_request lower read failed at offset {} len {}: {}",
                    first_offset,
                    first_len,
                    status
                );
                return Err(status);
            }

            Ok(())
        }
        .into_ffi()
    }
    fn write_request<'a, 'req, 'data>(
        &'a self,
        req: &'a mut RequestHandle<'req, Write<'data>>,
    ) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let (first_offset, first_len) = {
                let mut w = req.write();
                let mut current: *mut Write<'data> = &mut w.body;
                let mut first_offset = 0u64;
                let mut first_len = 0usize;
                let mut first = true;

                while !current.is_null() {
                    let body = unsafe { &mut *current };
                    let offset = body.offset;
                    let len = body.len;

                    let max_len = match self.request_len_from_offset(offset, len) {
                        Some(max_len) => max_len,
                        None => {
                            cold_path();
                            println!(
                                "volmgr: CacheBackend::write_request invalid write offset {} len {} for volume length {}",
                                offset, len, self.volume_bytes
                            );
                            return Err(DriverStatus::InvalidParameter);
                        }
                    };

                    if unlikely(max_len == 0) {
                        cold_path();
                        println!(
                            "volmgr: CacheBackend::write_request zero-length write after clamp at offset {} len {}",
                            offset, len
                        );
                        return Err(DriverStatus::InvalidParameter);
                    }

                    if unlikely(max_len == 0 || max_len != len) {
                        cold_path();
                        println!(
                            "volmgr: CacheBackend::write_request write exceeds volume offset {} len {} max_len {} volume length {}",
                            offset,
                            len,
                            max_len,
                            self.volume_bytes
                        );
                        return Err(DriverStatus::InvalidParameter);
                    }

                    if first {
                        first_offset = offset;
                        first_len = max_len;
                        first = false;
                    }

                    current = body.next.load(core::sync::atomic::Ordering::Acquire);
                }

                (first_offset, first_len)
            };

            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), req).await;
            if unlikely(status != DriverStatus::Success) {
                cold_path();
                println!(
                    "volmgr: CacheBackend::write_request lower write failed at offset {} len {}: {}",
                    first_offset, first_len, status
                );
                return Err(status);
            }
            Ok(())
        }
        .into_ffi()
    }

    fn write_phys_framed<'a, 'buffer>(
        &'a self,
        lba: u64,
        blocks: usize,
        buffer: IoBuffer<'buffer, 'buffer, Described, ToDevice>,
    ) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            if unlikely(blocks == 0) {
                cold_path();
                return Ok(());
            }

            let Some(offset) = lba.checked_mul(BLOCK_SIZE as u64) else {
                cold_path();
                return Err(DriverStatus::InvalidParameter);
            };

            let mut total_len = 0usize;
            let mut block_idx = 0usize;
            while block_idx < blocks {
                let Some(block_lba) = lba.checked_add(block_idx as u64) else {
                    cold_path();
                    return Err(DriverStatus::InvalidParameter);
                };
                let Some(block_len) = self.block_len(block_lba) else {
                    cold_path();
                    return Err(DriverStatus::InvalidParameter);
                };
                let Some(next_total_len) = total_len.checked_add(block_len) else {
                    cold_path();
                    return Err(DriverStatus::InvalidParameter);
                };
                total_len = next_total_len;
                block_idx += 1;
            }

            if unlikely(buffer.len() < total_len) {
                cold_path();
                return Err(DriverStatus::InvalidParameter);
            }

            let mut req = RequestHandle::new(Write {
                offset,
                len: total_len,
                no_buffer: false,
                owner: 0,
                buffer: Some(buffer),
                next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            });
            req.set_traversal_policy(TraversalPolicy::ForwardLower);

            let status = pnp_send_request(self.target.clone(), &mut req).await;

            if unlikely(status != DriverStatus::Success) {
                cold_path();
                println!(
                    "volmgr: CacheBackend::write_phys_framed lower write failed at lba {} blocks {} len {}: {}",
                    lba, blocks, total_len, status
                );
                return Err(status);
            }

            Ok(())
        }
        .into_ffi()
    }

    fn flush_device(&self) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut req = RequestHandle::new(Flush { should_block: true });
            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), &mut req).await;
            if unlikely(status != DriverStatus::Success && status != DriverStatus::NotImplemented) {
                cold_path();
                println!(
                    "volmgr: CacheBackend::flush_device lower flush failed: {}",
                    status
                );
                return Err(status);
            }
            Ok(())
        }
        .into_ffi()
    }
    fn dma_map_cache(&self, backing: &mut IoBufferBacking) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let payload = DmaBacking { backing: &*backing };

            let mut req = RequestHandle::new(Pnp {
                request: PnpRequest {
                    minor_function: PnpMinorFunction::RegisterDmaBacking,
                    relation: DeviceRelationType::TargetDeviceRelation,
                    id_type: QueryIdType::CompatibleIds,
                    ids_out: Vec::new(),
                    data_out: RequestData::from_t(payload),
                },
            });

            req.set_traversal_policy(TraversalPolicy::ForwardLower);

            let status = pnp_send_request(self.target.clone(), &mut req).await;

            if unlikely(status != DriverStatus::Success) {
                cold_path();
                println!(
                    "volmgr: CacheBackend::dma_map_cache lower RegisterDmaBacking failed: {}",
                    status
                );
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
    len_bytes: Once<u64>,
}

impl Default for VolPdoExt {
    fn default() -> Self {
        Self {
            backing: Once::new(),
            part: Once::new(),
            cache: Once::new(),
            len_bytes: Once::new(),
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

#[inline]
fn partition_len_bytes(pi: &PartitionInfo) -> Option<u64> {
    let sector_sz = pi.disk.logical_block_size as u64;
    let ent = pi.gpt_entry?;

    if unlikely(sector_sz == 0) {
        cold_path();
        return None;
    }

    let sectors = ent.last_lba.checked_sub(ent.first_lba)?.saturating_add(1);

    sectors.checked_mul(sector_sz)
}

#[inline]
fn cache_error_status(context: &str, err: CacheError<DriverStatus>) -> DriverStatus {
    match err {
        CacheError::Backend(status) => {
            cold_path();
            println!("volmgr: {} lower-device error: {}", context, status);
            status
        }
        err => {
            cold_path();
            println!("volmgr: {} cache error: {:?}", context, err);
            match err {
                CacheError::InvalidIoBuffer(_) => DriverStatus::InvalidParameter,
                _ => DriverStatus::Unsuccessful,
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, vol_device_add);
    DriverStatus::Success
}

pub extern "C" fn vol_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let pnp_vtable = PnpVtable::new();
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
    _req: &'b mut RequestHandle<'a, Pnp<'_>>,
) -> DriverStep {
    let mut query_req = RequestHandle::new(Pnp {
        request: PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::DeviceId,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
    });

    let st = pnp_forward_request_to_next_lower(dev.clone(), &mut query_req).await;
    if unlikely(st == DriverStatus::NoSuchDevice) {
        cold_path();
        return DriverStep::complete(DriverStatus::Success);
    }
    if unlikely(st != DriverStatus::Success) {
        cold_path();
        println!(
            "volmgr: vol_prepare_hardware lower QueryResources dispatch failed: {}",
            st
        );
        return DriverStep::complete(st);
    }

    let dx = ext::<VolExt>(&dev);
    let status = query_req.read().status.clone();
    if unlikely(status != DriverStatus::Success) {
        cold_path();
        println!(
            "volmgr: vol_prepare_hardware lower QueryResources completed with: {}",
            status
        );
        return DriverStep::complete(status);
    }

    let pi_opt: Option<PartitionInfo> = {
        let req = query_req.write();
        req.body.request.data_out.take_exact::<PartitionInfo>().ok()
    };
    if let Some(pi) = pi_opt {
        dx.part.call_once(|| pi);
    }

    DriverStep::Continue
}

#[request_handler]
pub async fn vol_enumerate_devices<'a, 'b>(
    device: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a, Pnp<'_>>,
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
    const MICROSOFT_RESERVED: [u8; 16] = [
        0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15,
        0xAE,
    ];

    let ptype = ent.partition_type_guid;
    if ptype == zero || ptype == EFI_SYSTEM || ptype == BIOS_BOOT || ptype == MICROSOFT_RESERVED {
        return DriverStep::Continue;
    }

    let part_guid_s = guid_to_string(&ent.unique_partition_guid);
    let name = alloc::format!("Volume{}", &part_guid_s[..8]);
    let inst = alloc::format!("STOR\\VOLUME\\{}\\0000", part_guid_s);

    let ids = DeviceIds {
        hardware: vec!["STOR\\Volume".into(), "STOR\\Volume\\GPT".into()],
        compatible: vec!["STOR\\Volume".into()],
    };

    let pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::QueryResources, vol_pdo_query_resources);
    pnp_vtable.set(PnpMinorFunction::RemoveDevice, vol_pdo_remove_device);

    let mut init = DeviceInit::with_pnp(Some(pnp_vtable));
    init.ops.read.register::<VolPdoIo>();
    init.ops.write.register::<VolPdoIo>();
    init.ops.flush.register::<VolPdoIo>();
    init.ops.flush_dirty.register::<VolPdoIo>();
    init.ops.flush_owner.register::<VolPdoIo>();
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
        let part_info = dx.part.get().unwrap().clone();
        let vol_len = partition_len_bytes(&part_info).unwrap_or(0);

        pdx.backing.call_once(|| tgt);
        pdx.part.call_once(|| part_info);
        pdx.len_bytes.call_once(|| vol_len);

        if vol_len != 0 {
            let backend = Arc::new(CacheBackend::new(tgt_clone, vol_len));
            // TODO: set this based on system memory and maybe volume size
            let mut cfg = CacheConfig::new(CACHE_CAPACITY_BYTES / BLOCK_SIZE, 50, 25);
            match VolCache::new(backend, cfg).await {
                Ok(cache) => {
                    pdx.cache.call_once(|| Arc::new(cache));
                }
                Err(err) => {
                    println!("volmgr: vol_enumerate_devices cache init failed: {:?}", err);
                }
            }
        }
    }

    DriverStep::Continue
}

async fn vol_pdo_read_impl<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Read<'data>>,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(dev);

    let vol_len = match dx.len_bytes.get() {
        Some(v) => *v,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    let (offset, len_req, no_buffer, req_data_len) = {
        let r = req.read();
        (
            r.body.offset,
            r.body.len,
            r.body.no_buffer,
            r.body.buffer.as_ref().map_or(0, |buffer| buffer.len()),
        )
    };

    if unlikely(len_req == 0) {
        cold_path();
        return DriverStep::complete(DriverStatus::Success);
    }

    if unlikely(offset >= vol_len) {
        cold_path();
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    if unlikely(
        offset
            .checked_add(len_req as u64)
            .map_or(true, |end| end > vol_len),
    ) {
        cold_path();
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let len = if no_buffer {
        len_req
    } else {
        core::cmp::min(len_req, req_data_len)
    };

    if unlikely(len == 0) {
        cold_path();
        return DriverStep::complete(DriverStatus::Success);
    }

    {
        let mut w = req.write();
        w.body.len = len;
    }

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    match cache.read_request(req).await {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(err) => {
            cold_path();
            DriverStep::complete(cache_error_status("vol_pdo_read cache.read_request", err))
        }
    }
}

async fn vol_pdo_write_impl<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Write<'data>>,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(dev);

    let vol_len = match dx.len_bytes.get() {
        Some(v) => *v,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    let (offset, len_req, no_buffer, req_data_len) = {
        let r = req.read();
        (
            r.body.offset,
            r.body.len,
            r.body.no_buffer,
            r.body.buffer.as_ref().map_or(0, |buffer| buffer.len()),
        )
    };

    if unlikely(len_req == 0) {
        cold_path();
        return DriverStep::complete(DriverStatus::Success);
    }

    if unlikely(offset >= vol_len) {
        cold_path();
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    if unlikely(
        offset
            .checked_add(len_req as u64)
            .map_or(true, |end| end > vol_len),
    ) {
        cold_path();
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let len = if no_buffer {
        len_req
    } else {
        core::cmp::min(len_req, req_data_len)
    };

    if unlikely(len == 0) {
        cold_path();
        return DriverStep::complete(DriverStatus::Success);
    }

    {
        let mut w = req.write();
        w.body.len = len;
    }

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    match cache.write_request(req).await {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(err) => {
            cold_path();
            DriverStep::complete(cache_error_status("vol_pdo_write cache.write_request", err))
        }
    }
}

async fn vol_pdo_flush_impl<'req, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Flush>,
) -> DriverStep {
    vol_pdo_flush_common(dev, req.read().body.should_block, None).await
}

async fn vol_pdo_flush_dirty_impl<'req, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, FlushDirty>,
) -> DriverStep {
    vol_pdo_flush_common(dev, req.read().body.should_block, None).await
}

async fn vol_pdo_flush_owner_impl<'req, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, FlushOwner>,
) -> DriverStep {
    let body = req.read().body;
    vol_pdo_flush_common(dev, body.should_block, Some(body.owner)).await
}

async fn vol_pdo_flush_common(
    dev: &Arc<DeviceObject>,
    should_block: bool,
    flush_owner: Option<u64>,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(dev);

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    if let Some(owner) = flush_owner {
        if should_block {
            match cache.flush_owner(owner).await {
                Ok(()) => {
                    return DriverStep::complete(DriverStatus::Success);
                }
                Err(err) => {
                    cold_path();
                    return DriverStep::complete(cache_error_status(
                        "vol_pdo_flush cache.flush_owner",
                        err,
                    ));
                }
            }
        } else {
            VolCache::flush_owner_background(cache, owner);
            return DriverStep::complete(DriverStatus::Success);
        }
    }

    if should_block {
        match cache.flush().await {
            Ok(()) => DriverStep::complete(DriverStatus::Success),
            Err(err) => {
                cold_path();
                DriverStep::complete(cache_error_status("vol_pdo_flush cache.flush", err))
            }
        }
    } else {
        cache.flush_background_pass();
        DriverStep::complete(DriverStatus::Success)
    }
}

#[request_handler]
pub async fn vol_pdo_remove_device<'a, 'b>(
    dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a, Pnp<'_>>,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(dev);

    if let Some(cache) = dx.cache.get() {
        if let Err(err) = cache.close_and_flush().await {
            let _ = cache_error_status("vol_pdo_remove_device cache.close_and_flush", err);
        }
    }

    DriverStep::Continue
}

#[request_handler]
async fn vol_pdo_query_resources<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a, Pnp<'_>>,
) -> DriverStep {
    let status = {
        let w = req.write();
        if let Some(pi) = ext::<VolPdoExt>(&pdo).part.get() {
            w.body.request.data_out = RequestData::from_t(pi.clone());
        } else {
            w.body.request.data_out = RequestData::empty();
        }
        DriverStatus::Success
    };

    DriverStep::complete(status)
}
