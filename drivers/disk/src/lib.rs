#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![feature(likely_unlikely)]
extern crate alloc;
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
        dma::{Described, FromDevice, IoBuffer, ToDevice},
        io::{DeviceControlHandler, DeviceFlush, DeviceRead, DeviceWrite, DiskInfo},
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
        driver_set_evt_device_add, io, pnp,
    },
    request::{DeviceControl, Flush, Pnp, Read, RequestHandle, Write},
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
        req: &'b mut RequestHandle<'req, Read<'data>>,
    ) -> DriverStep {
        let dx = disk_ext(&dev);

        if unlikely(!dx.props_ready.load(Ordering::Acquire)) {
            if let Err(st) = query_props_sync(&dev).await {
                cold_path();
                return DriverStep::complete(st);
            }
        }

        let bs = dx.block_size.load(Ordering::Acquire) as u64;
        if unlikely(bs == 0) {
            cold_path();
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }

        let (requests, bytes) = {
            let body = &req.read().body;

            match validate_disk_read_chain(body, bs) {
                Ok(v) => v,
                Err(st) => {
                    cold_path();
                    req.write().status = st.clone();
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
        req: &'b mut RequestHandle<'req, Write<'data>>,
    ) -> DriverStep {
        let dx = disk_ext(&dev);

        if unlikely(!dx.props_ready.load(Ordering::Acquire)) {
            if let Err(st) = query_props_sync(&dev).await {
                cold_path();
                return DriverStep::complete(st);
            }
        }

        let bs = dx.block_size.load(Ordering::Acquire) as u64;
        if unlikely(bs == 0) {
            cold_path();
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }

        let (requests, bytes) = {
            let body = &req.read().body;

            match validate_disk_write_chain(body, bs) {
                Ok(v) => v,
                Err(st) => {
                    cold_path();
                    req.write().status = st.clone();
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
    async fn handler<'req, 'b>(
        _dev: &Arc<DeviceObject>,
        _req: &'b mut RequestHandle<'req, Flush>,
    ) -> DriverStep {
        DriverStep::complete(io::send_next_lower(_dev.clone(), _req).await)
    }
}

impl DeviceControlHandler for DiskIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, DeviceControl<'data>>,
    ) -> DriverStep {
        let code = req.read().body.code;

        match code {
            IOCTL_DRIVE_IDENTIFY => {
                let mut ch = RequestHandle::new(Pnp {
                    request: PnpRequest {
                        minor_function: PnpMinorFunction::QueryResources,
                        relation: DeviceRelationType::TargetDeviceRelation,
                        id_type: QueryIdType::CompatibleIds,
                        ids_out: Vec::new(),
                        data_out: RequestData::empty(),
                    },
                });

                let st = pnp::send_next_lower(dev.clone(), &mut ch).await;
                if unlikely(st != DriverStatus::Success) {
                    cold_path();
                    return DriverStep::complete(st);
                }

                let mut info_opt = {
                    let wr = ch.write();
                    wr.body.request.data_out.take_exact::<DiskInfo>().ok()
                };
                if unlikely(info_opt.is_none()) {
                    info_opt = ch
                        .read()
                        .body
                        .request
                        .data_out_ref()
                        .view::<DiskInfo>()
                        .copied();
                }

                let info = match info_opt {
                    Some(di) => di,
                    None => {
                        cold_path();
                        return DriverStep::complete(DriverStatus::Unsuccessful);
                    }
                };

                req.write().body.set_data_t::<DiskInfo>(info);
                DriverStep::complete(DriverStatus::Success)
            }
            _ => DriverStep::complete(io::send_next_lower(dev.clone(), req).await),
        }
    }
}

fn has_from_device_buffer(buffer: &IoBuffer<'_, '_, Described, FromDevice>, len: usize) -> bool {
    buffer.len() >= len
}

fn has_to_device_buffer(buffer: &IoBuffer<'_, '_, Described, ToDevice>, len: usize) -> bool {
    buffer.len() >= len
}

#[repr(C)]
struct DiskExt {
    block_size: AtomicU32,
    props_ready: AtomicBool,
}

impl Default for DiskExt {
    fn default() -> Self {
        Self {
            block_size: AtomicU32::new(0),
            props_ready: AtomicBool::new(false),
        }
    }
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
    dev_init.ops.read.register::<DiskIo>();
    dev_init.ops.write.register::<DiskIo>();
    dev_init.ops.device_control.register::<DiskIo>();
    dev_init.ops.flush.register::<DiskIo>();

    let pnp_vt = PnpVtable::new();
    pnp_vt.set(PnpMinorFunction::RemoveDevice, disk_pnp_remove);
    dev_init.pnp_vtable = Some(pnp_vt);

    dev_init.set_dev_ext_default::<DiskExt>();
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn disk_pnp_remove<'req, 'data, 'b>(
    _dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    DriverStep::Continue
}

#[inline]
fn disk_ext<'a>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, DiskExt> {
    dev.try_devext::<DiskExt>().expect("disk dev ext missing")
}

async fn query_props_sync(dev: &Arc<DeviceObject>) -> Result<(), DriverStatus> {
    let mut ch = RequestHandle::new(Pnp {
        request: PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
    });
    let st = pnp::send_next_lower(dev.clone(), &mut ch).await;

    if unlikely(st != DriverStatus::Success) {
        cold_path();
        return Err(st);
    }
    if unlikely(ch.read().status != DriverStatus::Success) {
        cold_path();
        return Err(ch.read().status.clone());
    }

    let mut di_opt = {
        let req = ch.write();
        req.body.request.data_out.take_exact::<DiskInfo>().ok()
    };

    if unlikely(di_opt.is_none()) {
        let req = ch.read();
        di_opt = req
            .body
            .request
            .data_out_ref()
            .view::<DiskInfo>()
            .copied()
            .or_else(|| {
                let blob = req
                    .body
                    .request
                    .data_out_ref()
                    .view::<Vec<u8>>()
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                if blob.len() < size_of::<DiskInfo>() {
                    return None;
                }
                Some(unsafe { *(blob.as_ptr() as *const DiskInfo) })
            });
    }

    let di = match di_opt {
        Some(di) => di,
        None => {
            cold_path();
            return Err(DriverStatus::Unsuccessful);
        }
    };

    let dx = disk_ext(dev);
    dx.block_size
        .store(di.logical_block_size.max(1), Ordering::Release);
    dx.props_ready.store(true, Ordering::Release);

    Ok(())
}
