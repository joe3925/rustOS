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
use kernel_api::println;

use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::kernel_types::dma::{Described, FromDevice, IoBuffer, PhysFramed, ToDevice};
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
use kernel_api::request::{
    Flush, FlushDirty, FlushOwner, Pnp, Read, RequestHandle, TraversalPolicy, Write,
};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;

use spin::Once;

use crate::cache::{CacheConfig, CacheError, VolumeCache, VolumeCacheBackend, VolumeCacheOps};

mod cache;
mod cache_core;
mod cache_traits;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const BLOCK_SIZE: usize = 1024 * 64;
const CACHE_CAPACITY_BYTES: usize = 1024 * 1024 * 50;
const LAZY_CACHE_PAGE_ALLOCATION: bool = false;
const LAZY_INDEX_ALLOCATION: bool = false;
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
}

impl VolumeCacheBackend for CacheBackend {
    type Error = DriverStatus;

    fn read_phys_framed<'a, 'buffer>(
        &'a self,
        lba: u64,
        blocks: usize,
        buffer: IoBuffer<'buffer, PhysFramed, FromDevice>,
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
                buffer: buffer.into(),
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

    fn write_request<'a, 'req, 'data>(
        &'a self,
        req: &'a mut RequestHandle<'req, Write<'data>>,
    ) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let (write_offset, write_len) = {
                // Clamp writes to the actual tail length so we never issue an overrun past
                // the end of the underlying volume.
                let w = req.write();
                let offset = w.body.offset;
                let len = w.body.len;
                let lba = offset / BLOCK_SIZE as u64;
                let max_len = match self.block_len(lba) {
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
                let clamped = len.min(max_len);
                if unlikely(clamped == 0) {
                    cold_path();
                    println!(
                        "volmgr: CacheBackend::write_request zero-length write after clamp at offset {} len {}",
                        offset, len
                    );
                    return Err(DriverStatus::InvalidParameter);
                }
                if unlikely(clamped != len) {
                    w.body.len = clamped;
                }
                (offset, clamped)
            };
            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), req).await;
            if unlikely(status != DriverStatus::Success) {
                cold_path();
                println!(
                    "volmgr: CacheBackend::write_request lower write failed at offset {} len {}: {}",
                    write_offset, write_len, status
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
        buffer: IoBuffer<'buffer, PhysFramed, ToDevice>,
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
                buffer: buffer.into(),
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
                CacheError::InvalidIoBuffer => DriverStatus::InvalidParameter,
                _ => DriverStatus::Unsuccessful,
            }
        }
    }
}

async fn forward_no_buffer_read(target: IoTarget, offset: u64, dst: &mut [u8]) -> DriverStatus {
    let len = dst.len();
    let io_buf = IoBuffer::<Described, FromDevice>::new(dst).into_phys_framed();
    let mut req = RequestHandle::new(Read {
        offset,
        len,
        no_buffer: true,
        buffer: io_buf.into(),
    });
    req.set_traversal_policy(TraversalPolicy::ForwardLower);
    pnp_send_request(target, &mut req).await
}

async fn forward_no_buffer_write(
    target: IoTarget,
    offset: u64,
    src: &[u8],
    owner: u64,
) -> DriverStatus {
    let len = src.len();
    let io_buf = IoBuffer::<Described, ToDevice>::new(src).into_phys_framed();
    let mut req = RequestHandle::new(Write {
        offset,
        len,
        no_buffer: true,
        owner,
        buffer: io_buf.into(),
    });
    req.set_traversal_policy(TraversalPolicy::ForwardLower);
    pnp_send_request(target, &mut req).await
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
    io_table.set(IoType::FlushDirty(vol_pdo_flush_dirty), 0);
    io_table.set(IoType::FlushOwner(vol_pdo_flush_owner), 0);

    let pnp_vtable = PnpVtable::new();
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
        let part_info = dx.part.get().unwrap().clone();
        let vol_len = partition_len_bytes(&part_info).unwrap_or(0);

        pdx.backing.call_once(|| tgt);
        pdx.part.call_once(|| part_info);
        pdx.len_bytes.call_once(|| vol_len);

        if vol_len != 0 {
            let backend = Arc::new(CacheBackend::new(tgt_clone, vol_len));
            // TODO: set this based on system memory and maybe volume size
            let cfg = CacheConfig::new(CACHE_CAPACITY_BYTES / BLOCK_SIZE)
                .with_lazy_page_allocation(LAZY_CACHE_PAGE_ALLOCATION)
                .with_lazy_index_allocation(LAZY_INDEX_ALLOCATION);

            match VolCache::new(backend, cfg) {
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

#[request_handler]
pub async fn vol_pdo_read<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Read<'data>>,
    buf_len: usize,
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
            r.body.buffer.as_inner().len(),
        )
    };

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

    let mut len = len_req;
    len = core::cmp::min(len, buf_len);
    len = core::cmp::min(len, req_data_len);

    if unlikely(len == 0) {
        cold_path();
        return DriverStep::complete(DriverStatus::Success);
    }

    if unlikely(no_buffer) {
        cold_path();
        let target = match dx.backing.get() {
            Some(t) => t.clone(),
            None => return DriverStep::complete(DriverStatus::NoSuchDevice),
        };
        let dst = match req.write().body.buffer.as_inner_mut().try_as_mut_slice() {
            Some(dst) => dst,
            None => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };
        let status = forward_no_buffer_read(target, offset, &mut dst[..len]).await;
        return DriverStep::complete(status);
    }

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    let dst = match req.write().body.buffer.as_inner_mut().try_as_mut_slice() {
        Some(dst) => dst,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }
    };

    match cache.read_at(offset, &mut dst[..len]).await {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(err) => {
            cold_path();
            DriverStep::complete(cache_error_status("vol_pdo_read cache.read_at", err))
        }
    }
}

#[request_handler]
pub async fn vol_pdo_write<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Write<'data>>,
    buf_len: usize,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(&dev);

    let vol_len = match dx.len_bytes.get() {
        Some(v) => *v,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    let (offset, len_req, no_buffer, owner, req_data_len) = {
        let r = req.read();
        (
            r.body.offset,
            r.body.len,
            r.body.no_buffer,
            r.body.owner,
            r.body.buffer.as_inner().len(),
        )
    };

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

    let mut len = len_req;
    len = core::cmp::min(len, buf_len);
    len = core::cmp::min(len, req_data_len);

    if unlikely(len == 0) {
        cold_path();
        return DriverStep::complete(DriverStatus::Success);
    }

    let data_addr = {
        let src = match req.read().body.buffer.as_inner().try_as_slice() {
            Some(src) => src,
            None => {
                cold_path();
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        };
        src.as_ptr() as usize
    };
    let data = unsafe { core::slice::from_raw_parts(data_addr as *const u8, len) };

    if unlikely(no_buffer) {
        cold_path();
        let target = match dx.backing.get() {
            Some(t) => t.clone(),
            None => return DriverStep::complete(DriverStatus::NoSuchDevice),
        };
        let status = forward_no_buffer_write(target, offset, data, owner).await;
        return DriverStep::complete(status);
    }

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    let result = match owner {
        o if o != 0 => cache.write_at_owned(offset, data, o).await,
        _ => cache.write_at(offset, data).await,
    };

    match result {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(err) => {
            cold_path();
            DriverStep::complete(cache_error_status("vol_pdo_write cache.write", err))
        }
    }
}

#[request_handler]
pub async fn vol_pdo_flush<'req, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Flush>,
) -> DriverStep {
    vol_pdo_flush_common(dev, req.read().body.should_block, None).await
}

#[request_handler]
pub async fn vol_pdo_flush_dirty<'req, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, FlushDirty>,
) -> DriverStep {
    vol_pdo_flush_common(dev, req.read().body.should_block, None).await
}

#[request_handler]
pub async fn vol_pdo_flush_owner<'req, 'b>(
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
        match cache.wait_for_flush_job().await {
            Ok(()) => DriverStep::complete(DriverStatus::Success),
            Err(err) => {
                cold_path();
                DriverStep::complete(cache_error_status(
                    "vol_pdo_flush cache.wait_for_flush_job",
                    err,
                ))
            }
        }
    } else {
        let _ = cache.ensure_flush_job().await;
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
