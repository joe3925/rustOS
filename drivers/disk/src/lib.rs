#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![feature(likely_unlikely)]
extern crate alloc;
use kernel_api::device::open_protocol_to_next_lower;
use kernel_api::pnp::InitComplete;
use kernel_api::pnp::RemoveDevice;
use kernel_api::pnp::StartDevice;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    hint::{cold_path, unlikely},
    mem::size_of,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use kernel_api::util::panic_common;

use kernel_api::{
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        dma::{FromDevice, IoBuffer, ToDevice},
        io::{DeviceControlHandler, DeviceControlOp, DeviceFlush, DeviceFlushOp, DeviceRead, DeviceReadOp, DeviceWrite, DeviceWriteOp, DiskInfo},
        request::IoctlData,
    },
    pnp::{
        DriverStep, PnpOp, PnpOps, QueryResources, driver_set_evt_device_add, io, pnp,
    },
    request::{DeviceControl, Flush, Read, Write},
    request_handler,
    status::DriverStatus,
};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[panic_handler]
#[cfg(not(test))]
fn panic(info: &PanicInfo) -> ! {
    panic_common(MOD_NAME, info)
}

const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;

struct DiskIo;
fn validate_disk_read_chain<'io>(
    first: &Read<'io>,
    block_size: u64,
) -> Result<(u64, u64), DriverStatus> {
    let mut requests = 0u64;
    let mut bytes = 0u64;

    for read in first.iter() {
        if read.len == 0 {
            continue;
        }

        if read.no_buffer {
            return Err(DriverStatus::InvalidParameter);
        }

        let Some(buffer) = read.buffer.as_ref() else {
            return Err(DriverStatus::InvalidParameter);
        };

        if !has_from_device_buffer(buffer, read.len) {
            return Err(DriverStatus::InsufficientResources);
        }

        let len = read.len as u64;

        if read.offset % block_size != 0 || !len.is_multiple_of(block_size) {
            return Err(DriverStatus::InvalidParameter);
        }

        read.offset
            .checked_add(len)
            .ok_or(DriverStatus::InvalidParameter)?;

        requests = requests
            .checked_add(1)
            .ok_or(DriverStatus::InvalidParameter)?;

        bytes = bytes
            .checked_add(len)
            .ok_or(DriverStatus::InvalidParameter)?;
    }

    Ok((requests, bytes))
}

fn validate_disk_write_chain<'io>(
    first: &Write<'io>,
    block_size: u64,
) -> Result<(u64, u64), DriverStatus> {
    let mut requests = 0u64;
    let mut bytes = 0u64;

    for write in first.iter() {
        if write.len == 0 {
            continue;
        }

        if write.no_buffer {
            return Err(DriverStatus::InvalidParameter);
        }

        let Some(buffer) = write.buffer.as_ref() else {
            return Err(DriverStatus::InvalidParameter);
        };

        if !has_to_device_buffer(buffer, write.len) {
            return Err(DriverStatus::InsufficientResources);
        }

        let len = write.len as u64;

        if write.offset % block_size != 0 || !len.is_multiple_of(block_size) {
            return Err(DriverStatus::InvalidParameter);
        }

        write
            .offset
            .checked_add(len)
            .ok_or(DriverStatus::InvalidParameter)?;

        requests = requests
            .checked_add(1)
            .ok_or(DriverStatus::InvalidParameter)?;

        bytes = bytes
            .checked_add(len)
            .ok_or(DriverStatus::InvalidParameter)?;
    }

    Ok((requests, bytes))
}

impl DeviceRead for DiskIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut Read<'data>,
    ) -> DriverStep {
        let dx = disk_ext(&dev);

        let bs = dx.block_size.load(Ordering::Acquire) as u64;
        if unlikely(bs == 0) {
            cold_path();
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }

        let (requests, bytes) = {
            let body = &req;

            match validate_disk_read_chain(body, bs) {
                Ok(v) => v,
                Err(st) => {
                    cold_path();
                    return DriverStep::complete(st);
                }
            }
        };

        if requests == 0 {
            return DriverStep::complete(DriverStatus::Success);
        }

        DriverStep::complete(io::send_next_lower(dev.clone(), req).await)
    }
}

impl DeviceWrite for DiskIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut Write<'data>,
    ) -> DriverStep {
        let dx = disk_ext(&dev);

        let bs = dx.block_size.load(Ordering::Acquire) as u64;
        if unlikely(bs == 0) {
            cold_path();
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }

        let (requests, bytes) = {
            let body = &req;

            match validate_disk_write_chain(body, bs) {
                Ok(v) => v,
                Err(st) => {
                    cold_path();
                    return DriverStep::complete(st);
                }
            }
        };

        if requests == 0 {
            return DriverStep::complete(DriverStatus::Success);
        }

        DriverStep::complete(io::send_next_lower(dev.clone(), req).await)
    }
}
impl DeviceFlush for DiskIo {
    #[request_handler]
    async fn handler<'req, 'b>(_dev: &Arc<DeviceObject>, _req: &'b mut Flush) -> DriverStep {
        DriverStep::complete(io::send_next_lower(_dev.clone(), _req).await)
    }
}

impl DeviceControlHandler for DiskIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut DeviceControl<'data>,
    ) -> DriverStep {
        let code = req.code;

        match code {
            IOCTL_DRIVE_IDENTIFY => {
                let devnode = dev.dev_node.get().unwrap().upgrade().unwrap();
                let info = match open_public_protocol::<DiskInfoProtocol>(&devnode) {
                    Ok(proto) => {
                        match (proto.query)(&proto.provider()) {
                            Ok(di) => di,
                            Err(_) => {
                                cold_path();
                                return DriverStep::complete(DriverStatus::Unsuccessful);
                            }
                        }
                    }
                    Err(_) => {
                        cold_path();
                        return DriverStep::complete(DriverStatus::Unsuccessful);
                    }
                };

                req.set_data_t::<DiskInfo>(info);
                DriverStep::complete(DriverStatus::Success)
            }
            _ => DriverStep::complete(io::send_next_lower(dev.clone(), req).await),
        }
    }
}

fn has_from_device_buffer(buffer: &IoBuffer<'_, '_, FromDevice>, len: usize) -> bool {
    buffer.len() >= len
}

fn has_to_device_buffer(buffer: &IoBuffer<'_, '_, ToDevice>, len: usize) -> bool {
    buffer.len() >= len
}

use kernel_api::kernel_types::protocol::disk::{DiskInfoProtocol, DiskInfoProtocolVTable};
use kernel_api::device::open_public_protocol;
use spin::RwLock;

struct DiskExt {
    block_size: AtomicU32,
    props_ready: AtomicBool,
    info: RwLock<Option<DiskInfo>>,
}

impl Default for DiskExt {
    fn default() -> Self {
        Self {
            block_size: AtomicU32::new(0),
            props_ready: AtomicBool::new(false),
            info: RwLock::new(None),
        }
    }
}

#[request_handler]
async fn disk_pnp_start<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut StartDevice,
) -> DriverStep {
    let devnode = match dev.dev_node.get() {
        Some(dn) => match dn.upgrade() {
            Some(dn) => dn,
            None => return DriverStep::complete(DriverStatus::Unsuccessful),
        },
        None => return DriverStep::complete(DriverStatus::Unsuccessful),
    };

    DriverStep::Continue
}

#[request_handler]
async fn disk_init_complete<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut InitComplete,
) -> DriverStep {
    if let Err(st) = query_props_sync(dev) {
        cold_path();
        return DriverStep::complete(st);
    }
    DriverStep::Continue
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, disk_device_add);
    DriverStatus::Success
}

pub extern "C" fn disk_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    dev_init.ops.register::<DeviceReadOp, DiskIo>();
    dev_init.ops.register::<DeviceWriteOp, DiskIo>();
    dev_init.ops.register::<DeviceControlOp, DiskIo>();
    dev_init.ops.register::<DeviceFlushOp, DiskIo>();

    let mut pnp_vt = PnpOps::new();
    pnp_vt.start_device.set(disk_pnp_start);
    pnp_vt.init_complete.set(disk_init_complete);
    pnp_vt.remove_device.set(disk_pnp_remove);
    dev_init.pnp_ops = Some(pnp_vt);

    dev_init.set_dev_ext_default::<DiskExt>();
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn disk_pnp_remove<'req, 'data, 'b>(
    _dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut RemoveDevice,
) -> DriverStep {
    DriverStep::Continue
}

#[inline]
fn disk_ext<'a>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, DiskExt> {
    dev.try_devext::<DiskExt>().expect("disk dev ext missing")
}

fn query_props_sync(dev: &Arc<DeviceObject>) -> Result<(), DriverStatus> {
    let proto = match open_protocol_to_next_lower::<DiskInfoProtocol>(dev) {
        Ok(p) => p,
        Err(e) => {
            cold_path();
            return Err(e);
        }
    };
    let di = (proto.query)(&proto.provider())?;

    let dx = disk_ext(dev);
    *dx.info.write() = Some(di.clone());
    dx.block_size
        .store(di.logical_block_size.max(1), Ordering::Release);
    dx.props_ready.store(true, Ordering::Release);

    Ok(())
}


