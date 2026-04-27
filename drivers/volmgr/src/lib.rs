#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![allow(async_fn_in_trait)]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::arch::asm;
use core::panic::PanicInfo;
use core::sync::atomic::AtomicBool;
use kernel_api::async_ffi::FfiFuture;
use kernel_api::async_ffi::FutureExt;
use kernel_api::println;

use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::kernel_types::dma::{Described, FromDevice, IoBuffer, ToDevice};
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
    BorrowedHandle, RequestDataView, RequestHandle, RequestType, TraversalPolicy,
};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;

use spin::Once;

use crate::cache::{CacheConfig, CacheError, VolumeCache, VolumeCacheBackend, VolumeCacheOps};

mod cache;
mod cache_core;
mod cache_traits;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const BLOCK_SIZE: usize = 1024 * 16;
const CACHE_CAPACITY_BYTES: usize = 1024 * 1024 * 100;
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
        if start >= self.volume_bytes {
            return None;
        }
        let remaining = self.volume_bytes - start;
        Some(core::cmp::min(remaining, BLOCK_SIZE as u64) as usize)
    }
}

impl VolumeCacheBackend for CacheBackend {
    type Error = DriverStatus;

    fn read_block<'a>(&'a self, lba: u64, out: &'a mut [u8]) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let block_len = match self.block_len(lba) {
                Some(block_len) => block_len,
                None => {
                    println!(
                        "volmgr: CacheBackend::read_block invalid lba {} for volume length {}",
                        lba, self.volume_bytes
                    );
                    return Err(DriverStatus::InvalidParameter);
                }
            };

            let offset = lba * BLOCK_SIZE as u64;
            let len = block_len;

            let mut req =
                RequestHandle::new(RequestType::Read { offset, len }, RequestData::empty());
            req.set_traversal_policy(TraversalPolicy::ForwardLower);

            let status = {
                let mut io_buf = IoBuffer::<Described, FromDevice>::new(&mut out[..len]);
                let mut borrow = BorrowedHandle::writable(&mut req, &mut io_buf);
                pnp_send_request(self.target.clone(), borrow.handle()).await
            };

            if status != DriverStatus::Success {
                println!(
                    "volmgr: CacheBackend::read_block lower read failed at lba {} offset {} len {}: {}",
                    lba, offset, len, status
                );
                return Err(status);
            }

            if len < out.len() {
                out[len..].fill(0);
            }
            Ok(())
        }
        .into_ffi()
    }

    fn write_block<'a>(&'a self, lba: u64, data: &'a [u8]) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let block_len = match self.block_len(lba) {
                Some(block_len) => block_len,
                None => {
                    println!(
                        "volmgr: CacheBackend::write_block invalid lba {} for volume length {}",
                        lba, self.volume_bytes
                    );
                    return Err(DriverStatus::InvalidParameter);
                }
            };

            let offset = lba * BLOCK_SIZE as u64;
            let mut req = RequestHandle::new(
                RequestType::Write {
                    offset,
                    len: block_len,
                    flush_write_through: false,
                    owner: 0,
                },
                RequestData::empty(),
            );
            req.set_traversal_policy(TraversalPolicy::ForwardLower);

            let io_buf = IoBuffer::<Described, ToDevice>::new(&data[..block_len]);
            let status = {
                let mut borrow = BorrowedHandle::read_only(&mut req, &io_buf);
                pnp_send_request(self.target.clone(), borrow.handle()).await
            };

            if status != DriverStatus::Success {
                println!(
                    "volmgr: CacheBackend::write_block lower write failed at lba {} offset {} len {}: {}",
                    lba, offset, block_len, status
                );
                return Err(status);
            }
            Ok(())
        }
        .into_ffi()
    }

    fn write_request<'a>(
        &'a self,
        req: &'a mut RequestHandle<'_>,
    ) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut write_offset = 0u64;
            let mut write_len = 0usize;
            {
                // Clamp writes to the actual tail length so we never issue an overrun past
                // the end of the underlying volume.
                let mut w = req.write();
                if let RequestType::Write {
                    offset,
                    len,
                    flush_write_through,
                    owner,
                } = w.kind
                {
                    let lba = offset / BLOCK_SIZE as u64;
                    let max_len = match self.block_len(lba) {
                        Some(max_len) => max_len,
                        None => {
                            println!(
                                "volmgr: CacheBackend::write_request invalid write offset {} len {} for volume length {}",
                                offset, len, self.volume_bytes
                            );
                            return Err(DriverStatus::InvalidParameter);
                        }
                    };
                    let clamped = len.min(max_len);
                    if clamped == 0 {
                        println!(
                            "volmgr: CacheBackend::write_request zero-length write after clamp at offset {} len {}",
                            offset, len
                        );
                        return Err(DriverStatus::InvalidParameter);
                    }
                    if clamped != len {
                        w.kind = RequestType::Write {
                            offset,
                            len: clamped,
                            flush_write_through,
                            owner,
                        };
                    }
                    write_offset = offset;
                    write_len = clamped;
                }
            }
            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), req).await;
            if status != DriverStatus::Success {
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

    fn flush_device(&self) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut req = RequestHandle::new(
                RequestType::Flush { should_block: true },
                RequestData::empty(),
            );
            req.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_send_request(self.target.clone(), &mut req).await;
            if status != DriverStatus::Success && status != DriverStatus::NotImplemented {
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

    if sector_sz == 0 {
        return None;
    }

    let sectors = ent.last_lba.checked_sub(ent.first_lba)?.saturating_add(1);

    sectors.checked_mul(sector_sz)
}

#[inline]
fn cache_error_status(context: &str, err: CacheError<DriverStatus>) -> DriverStatus {
    match err {
        CacheError::Backend(status) => {
            println!("volmgr: {} lower-device error: {}", context, status);
            status
        }
        err => {
            println!("volmgr: {} cache error: {:?}", context, err);
            DriverStatus::Unsuccessful
        }
    }
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
    if st != DriverStatus::Success {
        println!(
            "volmgr: vol_prepare_hardware lower QueryResources dispatch failed: {}",
            st
        );
        return DriverStep::complete(st);
    }

    let dx = ext::<VolExt>(&dev);
    let status = query_req.read().status.clone();
    if status != DriverStatus::Success {
        println!(
            "volmgr: vol_prepare_hardware lower QueryResources completed with: {}",
            status
        );
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
pub async fn vol_pdo_read<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    buf_len: usize,
) -> DriverStep {
    let dx = ext::<VolPdoExt>(dev);

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let vol_len = match dx.len_bytes.get() {
        Some(v) => *v,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let (offset, len_req) = {
        let r = req.read();
        match r.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    if offset >= vol_len {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    if offset
        .checked_add(len_req as u64)
        .map_or(true, |end| end > vol_len)
    {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let req_data_len = match req.data() {
        RequestDataView::FromDevice(data) => data.view::<[u8]>().map(|b| b.len()).unwrap_or(0),
        RequestDataView::ToDevice(_) => {
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }
    };

    let mut len = len_req;
    len = core::cmp::min(len, buf_len);
    len = core::cmp::min(len, req_data_len);
    len = core::cmp::min(len, (vol_len - offset) as usize);

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let mut data = match req.data() {
        RequestDataView::FromDevice(data) => data,
        RequestDataView::ToDevice(_) => {
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }
    };
    let dst = data
        .view_mut::<[u8]>()
        .expect("read response missing buffer");

    match cache.read_at(offset, &mut dst[..len]).await {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(err) => DriverStep::complete(cache_error_status("vol_pdo_read cache.read_at", err)),
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

    let vol_len = match dx.len_bytes.get() {
        Some(v) => *v,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let (offset, len_req, flush_write_through, owner) = match req.read().kind {
        RequestType::Write {
            offset,
            len,
            flush_write_through,
            owner,
        } => (offset, len, flush_write_through, owner),
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    if offset >= vol_len {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    if offset
        .checked_add(len_req as u64)
        .map_or(true, |end| end > vol_len)
    {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let mut len = len_req;
    len = core::cmp::min(len, buf_len);
    len = core::cmp::min(
        len,
        match req.data() {
            RequestDataView::ToDevice(data) => data.view::<[u8]>().map(|b| b.len()).unwrap_or(0),
            RequestDataView::FromDevice(_) => {
                return DriverStep::complete(DriverStatus::InvalidParameter);
            }
        },
    );
    len = core::cmp::min(len, (vol_len - offset) as usize);

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    let data = match req.data() {
        RequestDataView::ToDevice(data) => data,
        RequestDataView::FromDevice(_) => {
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }
    };
    let data = data.view::<[u8]>().expect("write req missing buffer");

    let result = match (flush_write_through, owner) {
        (true, o) if o != 0 => cache.write_through_at_owned(offset, &data[..len], o).await,
        (true, _) => cache.write_through_at(offset, &data[..len]).await,
        (false, o) if o != 0 => cache.write_at_owned(offset, &data[..len], o).await,
        (false, _) => cache.write_at(offset, &data[..len]).await,
    };

    match result {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(err) => DriverStep::complete(cache_error_status("vol_pdo_write cache.write", err)),
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

    let (should_block, flush_owner) = match req.read().kind {
        RequestType::Flush { should_block } | RequestType::FlushDirty { should_block } => {
            (should_block, None)
        }
        RequestType::FlushOwner {
            owner,
            should_block,
        } => (should_block, Some(owner)),
        _ => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    if let Some(owner) = flush_owner {
        if should_block {
            match cache.flush_owner(owner).await {
                Ok(()) => {
                    return DriverStep::complete(DriverStatus::Success);
                }
                Err(err) => {
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
            Err(err) => DriverStep::complete(cache_error_status(
                "vol_pdo_flush cache.wait_for_flush_job",
                err,
            )),
        }
    } else {
        let _ = cache.ensure_flush_job().await;
        DriverStep::complete(DriverStatus::Success)
    }
}

#[request_handler]
pub async fn vol_pdo_remove_device<'a, 'b>(
    dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
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
