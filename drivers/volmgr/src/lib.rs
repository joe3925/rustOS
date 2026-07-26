#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![feature(likely_unlikely)]
#![allow(async_fn_in_trait)]

extern crate alloc;
use kernel_api::pnp::InitComplete;
use kernel_api::pnp::QueryDeviceRelations;

use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::hint::{cold_path, unlikely};
use core::panic::PanicInfo;
use core::sync::atomic::AtomicBool;
use kernel_api::async_ffi::FfiFuture;
use kernel_api::async_ffi::FutureExt;
use kernel_api::dma::dma::IoBufferBacking;
use kernel_api::pnp::RemoveDevice;
use kernel_api::pnp::StartDevice;
use kernel_api::println;

use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::device::{open_public_protocol, publish_stack_protocol, register_protocol};
use kernel_api::error::{
    error, error_with_message, DriverErrorKind, ErrorKind, KernelError, ResultErrorContext,
};
use kernel_api::kernel_types::dma::{FromDevice, IoBuffer};
use kernel_api::kernel_types::io::IoTarget;
use kernel_api::kernel_types::io::PartitionInfo;
use kernel_api::kernel_types::io::{
    DeviceFlush, DeviceFlushDirty, DeviceFlushDirtyOp, DeviceFlushOp, DeviceFlushOwner,
    DeviceFlushOwnerOp, DeviceRead, DeviceReadOp, DeviceWrite, DeviceWriteOp,
};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::protocol::disk::PartitionInfoProtocol;
use kernel_api::kernel_types::protocol::volmgr::{VolumeProtocol, VolumeProtocolVTable};
use kernel_api::pnp::DeviceRelationType;
use kernel_api::pnp::DriverStep;
use kernel_api::pnp::PnpOp;
use kernel_api::pnp::PnpOps;
use kernel_api::pnp::RegisterDmaBacking;
use kernel_api::pnp::driver_set_evt_device_add;
use kernel_api::pnp::pnp_create_child_devnode_and_pdo_with_init;
use kernel_api::pnp::pnp_get_device_target;
use kernel_api::pnp::{io, pnp};
use kernel_api::request::{Flush, FlushDirty, FlushOwner, Read, Write};
use kernel_api::request_handler;

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
        req: &'b mut Read<'data>,
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        vol_pdo_read_impl(dev, req).await
    }
}

impl DeviceWrite for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut Write<'data>,
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        vol_pdo_write_impl(dev, req).await
    }
}

impl DeviceFlush for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(dev: &Arc<DeviceObject>, req: &'b mut Flush) -> Result<DriverStep, kernel_api::error::KernelError> {
        vol_pdo_flush_impl(dev, req).await
    }
}

impl DeviceFlushDirty for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(dev: &Arc<DeviceObject>, req: &'b mut FlushDirty) -> Result<DriverStep, kernel_api::error::KernelError> {
        vol_pdo_flush_dirty_impl(dev, req).await
    }
}

impl DeviceFlushOwner for VolPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(dev: &Arc<DeviceObject>, req: &'b mut FlushOwner) -> Result<DriverStep, kernel_api::error::KernelError> {
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
    type Error = KernelError;

    fn read_phys_framed<'a, 'buffer>(
        &'a self,
        lba: u64,
        blocks: usize,
        buffer: IoBuffer<'buffer, 'buffer, FromDevice>,
    ) -> FfiFuture<Result<usize, Self::Error>> {
        async move {
            if unlikely(blocks == 0) {
                cold_path();
                return Ok(0);
            }

            let Some(offset) = lba.checked_mul(BLOCK_SIZE as u64) else {
                cold_path();
                return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
                    alloc::format!(
                        "calculating volmgr cache read offset for LBA {lba}, block count {blocks}"
                    )
                });
            };

            let mut total_len = 0usize;
            let mut block_idx = 0usize;
            while block_idx < blocks {
                let Some(block_lba) = lba.checked_add(block_idx as u64) else {
                    cold_path();
                    return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
                        alloc::format!(
                            "calculating volmgr cache block LBA from base {lba} and index {block_idx}"
                        )
                    });
                };
                let block_len = match self.block_len(block_lba) {
                    Some(block_len) => block_len,
                    None => {
                        cold_path();
                        println!(
                            "volmgr: CacheBackend::read_phys_framed invalid lba {} for volume length {}",
                            block_lba, self.volume_bytes
                        );
                        return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
                            alloc::format!(
                                "reading cache block LBA {block_lba} beyond volume length {}",
                                self.volume_bytes
                            )
                        });
                    }
                };
                let Some(next_total_len) = total_len.checked_add(block_len) else {
                    cold_path();
                    return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
                        alloc::format!(
                            "accumulating cache read length at block index {block_idx}"
                        )
                    });
                };
                total_len = next_total_len;
                block_idx += 1;
            }

            if unlikely(buffer.len() < total_len) {
                cold_path();
                return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
                    alloc::format!(
                        "cache read buffer has {} bytes but {total_len} are required for LBA {lba}, block count {blocks}",
                        buffer.len()
                    )
                });
            }

            let mut req =  Read::new(
                offset,
                 total_len,
                 false,Some(buffer),);
            io::send_down_stack(self.target.clone(), &mut req)
                .await
                .map(|_| ())
                .with_context(|| {
                    alloc::format!(
                        "reading lower volume at cache LBA {lba}, block count {blocks}, byte length {total_len}"
                    )
                })?;

            Ok(total_len)
        }
        .into_ffi()
    }
    fn read_request<'a, 'req, 'data>(
        &'a self,
        req: &'a mut Read<'data>,
    ) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let (first_offset, first_len) = {
                let r = &mut *req;
                let mut first_offset = 0u64;
                let mut first_len = 0usize;
                let mut first = true;
                    for body in &mut r.iter_mut() {
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
                                return Err(error(DriverErrorKind::InvalidParameter)).with_context(
                                    || {
                                        alloc::format!(
                                            "reading volume at offset {offset} with length {len} beyond volume length {}",
                                            self.volume_bytes
                                        )
                                    },
                                );
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
                            return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
                                alloc::format!(
                                    "volume read at offset {offset} with length {len} exceeds remaining length {max_len}"
                                )
                            });
                        }

                        if !body.no_buffer {
                            let buffer = body
                                .buffer
                                .as_mut()
                                .ok_or_else(|| error(DriverErrorKind::InvalidParameter))
                                .with_context(|| {
                                    alloc::format!(
                                        "volume read at offset {offset} with length {len} is missing its buffer"
                                    )
                                })?;

                            buffer
                                .ensure_phys_described()
                                .map_err(|_| error(DriverErrorKind::InsufficientResources))
                                .with_context(|| {
                                    alloc::format!(
                                        "describing the physical buffer for volume read at offset {offset} with length {len}"
                                    )
                                })?;
                        }

                        if first {
                            first_offset = offset;
                            first_len = len;
                            first = false;
                        }
                    }

                (first_offset, first_len)
            };

            io::send_down_stack(self.target.clone(), req)
                .await
                .map(|_| ())
                .with_context(|| {
                    alloc::format!(
                        "forwarding volume read chain beginning at offset {first_offset}, length {first_len}"
                    )
                })?;

            Ok(())
        }
        .into_ffi()
    }
    fn write_request<'a, 'req, 'data>(
        &'a self,
        req: &'a mut Write<'data>,
    ) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let (first_offset, first_len) = {
                let w = &mut *req;
                let mut first_offset = 0u64;
                let mut first_len = 0usize;
                let mut first = true;

                for body in w.iter_mut() {
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
                            return Err(error(DriverErrorKind::InvalidParameter)).with_context(
                                || {
                                    alloc::format!(
                                        "writing volume at offset {offset} with length {len} beyond volume length {}",
                                        self.volume_bytes
                                    )
                                },
                            );
                        }
                    };

                    if unlikely(max_len == 0 || max_len != len) {
                        cold_path();
                        println!(
                            "volmgr: CacheBackend::write_request write exceeds volume offset {} len {} max_len {} volume length {}",
                            offset,
                            len,
                            max_len,
                            self.volume_bytes
                        );
                        return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
                            alloc::format!(
                                "volume write at offset {offset} with length {len} exceeds remaining length {max_len}"
                            )
                        });
                    }

                    if !body.no_buffer {
                        let buffer = body
                            .buffer
                            .as_mut()
                            .ok_or_else(|| error(DriverErrorKind::InvalidParameter))
                            .with_context(|| {
                                alloc::format!(
                                    "volume write at offset {offset} with length {len} is missing its buffer"
                                )
                            })?;

                        buffer
                            .ensure_phys_described()
                            .map_err(|_| error(DriverErrorKind::InsufficientResources))
                            .with_context(|| {
                                alloc::format!(
                                    "describing the physical buffer for volume write at offset {offset} with length {len}"
                                )
                            })?;
                    }

                    if first {
                        first_offset = offset;
                        first_len = max_len;
                        first = false;
                    }
                }

                (first_offset, first_len)
            };

            io::send_down_stack(self.target.clone(), req)
                .await
                .map(|_| ())
                .with_context(|| {
                    alloc::format!(
                        "forwarding volume write chain beginning at offset {first_offset}, length {first_len}"
                    )
                })?;

            Ok(())
        }
        .into_ffi()
    }

    fn flush_device(&self) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut req = Flush { should_block: true };
            match io::send_down_stack(self.target.clone(), &mut req).await {
                Ok(_) => {}
                Err(err)
                    if err.kind()
                        == ErrorKind::Driver(DriverErrorKind::NotImplemented) => {}
                Err(err) => {
                    return Err(err)
                        .with_context(|| "flushing the lower device for the volume cache")
                }
            }
            Ok(())
        }
        .into_ffi()
    }
    fn dma_map_cache(&self, backing: &mut IoBufferBacking) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut req = RegisterDmaBacking { backing: &*backing };

            pnp::send_down_stack(self.target.clone(), &mut req)
                .await
                .map(|_| ())
                .with_context(|| "registering volume-cache DMA backing with the lower device")?;

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
fn cache_error(context: &str, err: CacheError<KernelError>) -> KernelError {
    match err {
        CacheError::Backend(err) => err.with_context(context),
        CacheError::InvalidConfig => error_with_message(
            DriverErrorKind::InvalidParameter,
            format_args!("{context}: invalid cache configuration"),
        ),
        CacheError::OffsetOverflow => error_with_message(
            DriverErrorKind::InvalidParameter,
            format_args!("{context}: cache offset overflow"),
        ),
        CacheError::Closed => error_with_message(
            DriverErrorKind::DeviceNotReady,
            format_args!("{context}: volume cache is closed"),
        ),
        CacheError::NoFreePages => error_with_message(
            DriverErrorKind::InsufficientResources,
            format_args!("{context}: volume cache has no free pages"),
        ),
        CacheError::InsufficientResources => error_with_message(
            DriverErrorKind::InsufficientResources,
            format_args!("{context}: insufficient cache resources"),
        ),
        CacheError::InvalidIoBuffer(buffer_error) => error_with_message(
            DriverErrorKind::InvalidParameter,
            format_args!("{context}: invalid cache I/O buffer: {buffer_error:?}"),
        ),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> Result<(), kernel_api::error::KernelError> {
    driver_set_evt_device_add(driver, vol_device_add);
    Ok(())
}

pub extern "C" fn vol_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let mut pnp_ops = PnpOps::new();
    pnp_ops.init_complete.set(vol_init_complete);
    pnp_ops.query_device_relations.set(vol_enumerate_devices);

    dev_init.set_dev_ext_default::<VolExt>();
    dev_init.pnp_ops = Some(pnp_ops);
    Ok(DriverStep::Complete)
}

#[request_handler]
pub async fn vol_init_complete<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut InitComplete,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let devnode = dev.dev_node.get().unwrap().upgrade().unwrap();
    let proto = match open_public_protocol::<PartitionInfoProtocol>(&devnode) {
        Ok(p) => p,
        Err(e) => {
            cold_path();
            return Err(error(e))
                .with_context(|| "opening the public partition-info protocol in volmgr");
        }
    };
    let pi = match (proto.query)(&proto.provider()) {
        Ok(pi) => pi,
        Err(e) => {
            cold_path();
            return Err(e).with_context(|| "querying partition information in volmgr");
        }
    };

    let dx = ext::<VolExt>(&dev);
    dx.part.call_once(|| pi);

    Ok(DriverStep::Continue)
}

#[request_handler]
pub async fn vol_enumerate_devices<'a, 'b>(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut QueryDeviceRelations,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let dx = ext::<VolExt>(&device);

    let binding = dx.part.get();
    let pi = if let Some(ref pi) = binding {
        pi
    } else {
        return Ok(DriverStep::Continue);
    };

    let binding = (pi.gpt_header, pi.gpt_entry);
    let (_hdr, ent) = if let (Some(ref hdr), Some(ref ent)) = binding {
        (hdr, ent)
    } else {
        return Ok(DriverStep::Continue);
    };

    if dx
        .enumerated
        .swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        return Ok(DriverStep::Continue);
    }

    let parent_dn = if let Some(dn) = device.dev_node.get().unwrap().upgrade() {
        dn
    } else {
        return Err(error(DriverErrorKind::NoSuchDevice))
            .with_context(|| "enumerating a volume whose parent device node was removed");
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
        return Ok(DriverStep::Continue);
    }

    let part_guid_s = guid_to_string(&ent.unique_partition_guid);
    let name = alloc::format!("Volume{}", &part_guid_s[..8]);
    let inst = alloc::format!("STOR\\VOLUME\\{}\\0000", part_guid_s);

    let ids = DeviceIds {
        hardware: vec!["STOR\\Volume".into(), "STOR\\Volume\\GPT".into()],
        compatible: vec!["STOR\\Volume".into()],
    };

    let mut pnp_ops = PnpOps::new();
    pnp_ops.start_device.set(vol_pdo_start);
    pnp_ops.remove_device.set(vol_pdo_remove_device);
    pnp_ops
        .register_dma_backing
        .set(vol_pdo_register_dma_backing);

    let mut init = DeviceInit::with_pnp(Some(pnp_ops));
    init.ops.register::<DeviceReadOp, VolPdoIo>();
    init.ops.register::<DeviceWriteOp, VolPdoIo>();
    init.ops.register::<DeviceFlushOp, VolPdoIo>();
    init.ops.register::<DeviceFlushDirtyOp, VolPdoIo>();
    init.ops.register::<DeviceFlushOwnerOp, VolPdoIo>();
    init.set_dev_ext_default::<VolPdoExt>();

    let (dn_child, pdo) = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn,
        name,
        inst,
        ids,
        Some("Volume".into()),
        init,
    );

    let tgt = pnp_get_device_target(&parent_dn.instance_path).ok_or_else(|| {
        error(DriverErrorKind::NoSuchDevice).with_context(alloc::format!(
            "resolving the lower I/O target for volume parent {}",
            parent_dn.instance_path
        ))
    })?;
    let pdx = ext::<VolPdoExt>(&pdo);
    let tgt_clone = tgt.clone();
    let part_info = dx.part.get().unwrap().clone();
    let vol_len = partition_len_bytes(&part_info).ok_or_else(|| {
        error(DriverErrorKind::InvalidParameter)
            .with_context("calculating volume length from GPT partition information")
    })?;

    pdx.backing.call_once(|| tgt);
    pdx.part.call_once(|| part_info);
    pdx.len_bytes.call_once(|| vol_len);

    let backend = Arc::new(CacheBackend::new(tgt_clone, vol_len));
    // TODO: set this based on system memory and maybe volume size
    let cfg = CacheConfig::new(CACHE_CAPACITY_BYTES / BLOCK_SIZE, 50, 25);
    let cache = VolCache::new(backend, cfg)
        .await
        .map_err(|err| cache_error("initializing the volume cache", err))?;
    pdx.cache.call_once(|| Arc::new(cache));

    Ok(DriverStep::Continue)
}

async fn vol_pdo_read_impl<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut Read<'data>,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let dx = ext::<VolPdoExt>(dev);

    let vol_len = match dx.len_bytes.get() {
        Some(v) => *v,
        None => {
            cold_path();
            return Err(error(DriverErrorKind::NoSuchDevice))
                .with_context(|| "reading a volume before its length was initialized");
        }
    };

    let (offset, len_req, no_buffer, req_data_len) = {
        let r = &*req;
        (
            r.offset,
            r.len,
            r.no_buffer,
            r.buffer.as_ref().map_or(0, |buffer| buffer.len()),
        )
    };

    if unlikely(len_req == 0) {
        cold_path();
        return Ok(DriverStep::Complete);
    }

    if unlikely(offset >= vol_len) {
        cold_path();
        return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
            alloc::format!(
                "volume read offset {offset} is outside volume length {vol_len}"
            )
        });
    }

    if unlikely(
        offset
            .checked_add(len_req as u64)
            .map_or(true, |end| end > vol_len),
    ) {
        cold_path();
        return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
            alloc::format!(
                "volume read range offset {offset}, length {len_req} exceeds volume length {vol_len}"
            )
        });
    }

    let len = if no_buffer {
        len_req
    } else {
        core::cmp::min(len_req, req_data_len)
    };

    if unlikely(len == 0) {
        cold_path();
        return Ok(DriverStep::Complete);
    }

    {
        let w = &mut *req;
        w.len = len;
    }

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return Err(error(DriverErrorKind::DeviceNotReady))
                .with_context(|| "reading a volume before its cache was initialized");
        }
    };

    match cache.read_request(req).await {
        Ok(()) => Ok(DriverStep::Complete),
        Err(err) => {
            cold_path();
            Err(cache_error("servicing a cached volume read", err))
        }
    }
}

async fn vol_pdo_write_impl<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut Write<'data>,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let dx = ext::<VolPdoExt>(dev);

    let vol_len = match dx.len_bytes.get() {
        Some(v) => *v,
        None => {
            cold_path();
            return Err(error(DriverErrorKind::NoSuchDevice))
                .with_context(|| "writing a volume before its length was initialized");
        }
    };

    let (offset, len_req, no_buffer, req_data_len) = {
        let r = &*req;
        (
            r.offset,
            r.len,
            r.no_buffer,
            r.buffer.as_ref().map_or(0, |buffer| buffer.len()),
        )
    };

    if unlikely(len_req == 0) {
        cold_path();
        return Ok(DriverStep::Complete);
    }

    if unlikely(offset >= vol_len) {
        cold_path();
        return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
            alloc::format!(
                "volume write offset {offset} is outside volume length {vol_len}"
            )
        });
    }

    if unlikely(
        offset
            .checked_add(len_req as u64)
            .map_or(true, |end| end > vol_len),
    ) {
        cold_path();
        return Err(error(DriverErrorKind::InvalidParameter)).with_context(|| {
            alloc::format!(
                "volume write range offset {offset}, length {len_req} exceeds volume length {vol_len}"
            )
        });
    }

    let len = if no_buffer {
        len_req
    } else {
        core::cmp::min(len_req, req_data_len)
    };

    if unlikely(len == 0) {
        cold_path();
        return Ok(DriverStep::Complete);
    }

    {
        let w = &mut *req;
        w.len = len;
    }

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return Err(error(DriverErrorKind::DeviceNotReady))
                .with_context(|| "writing a volume before its cache was initialized");
        }
    };

    match cache.write_request(req).await {
        Ok(()) => Ok(DriverStep::Complete),
        Err(err) => {
            cold_path();
            Err(cache_error("servicing a cached volume write", err))
        }
    }
}

async fn vol_pdo_flush_impl<'req, 'b>(dev: &Arc<DeviceObject>, req: &'b mut Flush) -> Result<DriverStep, kernel_api::error::KernelError> {
    vol_pdo_flush_common(dev, req.should_block, None).await
}

async fn vol_pdo_flush_dirty_impl<'req, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut FlushDirty,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    vol_pdo_flush_common(dev, req.should_block, None).await
}

async fn vol_pdo_flush_owner_impl<'req, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut FlushOwner,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let body = req;
    vol_pdo_flush_common(dev, body.should_block, Some(body.owner)).await
}

async fn vol_pdo_flush_common(
    dev: &Arc<DeviceObject>,
    should_block: bool,
    flush_owner: Option<u64>,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let dx = ext::<VolPdoExt>(dev);

    let cache = match dx.cache.get() {
        Some(c) => c,
        None => {
            cold_path();
            return Err(error(DriverErrorKind::DeviceNotReady))
                .with_context(|| "flushing a volume before its cache was initialized");
        }
    };

    if let Some(owner) = flush_owner {
        if should_block {
            match cache.flush_owner(owner).await {
                Ok(()) => {
                    return Ok(DriverStep::Complete);
                }
                Err(err) => {
                    cold_path();
                    return Err(cache_error(
                        &alloc::format!("flushing volume-cache owner {owner}"),
                        err,
                    ));
                }
            }
        } else {
            VolCache::flush_owner_background(cache, owner);
            return Ok(DriverStep::Complete);
        }
    }

    if should_block {
        match cache.flush().await {
            Ok(()) => Ok(DriverStep::Complete),
            Err(err) => {
                cold_path();
                Err(cache_error("flushing the volume cache", err))
            }
        }
    } else {
        cache.flush_background_pass();
        Ok(DriverStep::Complete)
    }
}

#[request_handler]
async fn vol_pdo_start<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut StartDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    if let Some(dn) = dev.dev_node.get() {
        if let Some(dn) = dn.upgrade() {
            register_protocol::<VolumeProtocol>(dev, &VOLMGR_INFO_VTABLE)
                .map_err(error)
                .with_context(|| "registering the volmgr volume protocol")?;
            publish_stack_protocol::<VolumeProtocol>(&dn)
                .map_err(error)
                .with_context(|| "publishing the volmgr volume protocol")?;
        }
    }
    Ok(DriverStep::Continue)
}

#[request_handler]
pub async fn vol_pdo_remove_device<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut RemoveDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let dx = ext::<VolPdoExt>(dev);

    if let Some(cache) = dx.cache.get() {
        if let Err(err) = cache.close_and_flush().await {
            return Err(cache_error(
                "closing and flushing the volume cache during device removal",
                err,
            ));
        }
    }

    Ok(DriverStep::Complete)
}

#[request_handler]
async fn vol_pdo_register_dma_backing<'req, 'data, 'b>(
    _pdo: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut RegisterDmaBacking<'data>,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    Ok(DriverStep::Complete)
}

extern "C" fn vol_partition_info(
    device: &Arc<DeviceObject>,
) -> Result<PartitionInfo, KernelError> {
    let dx = ext::<VolPdoExt>(device);
    if let Some(pi) = dx.part.get() {
        Ok(pi.clone())
    } else {
        Err(error(DriverErrorKind::DeviceNotReady))
            .with_context(|| "querying partition information before volmgr initialized it")
    }
}
const VOLMGR_INFO_VTABLE: VolumeProtocolVTable = VolumeProtocolVTable {
    partition_info: vol_partition_info,
};
