#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::{
    mem::size_of,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use kernel_api::util::panic_common;

use kernel_api::{
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        io::{DiskInfo, IoType},
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
        driver_set_evt_device_add, pnp_forward_request_to_next_lower,
    },
    request::{RequestHandle, RequestType, TraversalPolicy},
    request_handler,
    status::DriverStatus,
};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[panic_handler]
#[cfg(not(test))]
fn panic(info: &PanicInfo) -> ! {
    panic_common(MOD_NAME, info)
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;
const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;

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
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, disk_device_add);
    DriverStatus::Success
}

pub extern "win64" fn disk_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> kernel_api::pnp::DriverStep {
    dev_init.io_vtable.set(IoType::Read(disk_read), 0);
    dev_init.io_vtable.set(IoType::Write(disk_write), 0);
    dev_init.io_vtable.set(IoType::DeviceControl(disk_ioctl), 0);

    let mut pnp_vt = PnpVtable::new();
    pnp_vt.set(PnpMinorFunction::RemoveDevice, disk_pnp_remove);
    dev_init.pnp_vtable = Some(pnp_vt);

    dev_init.set_dev_ext_default::<DiskExt>();
    kernel_api::pnp::DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn disk_pnp_remove<'a, 'b>(
    _dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> kernel_api::pnp::DriverStep {
    kernel_api::pnp::DriverStep::Continue
}

#[request_handler]
pub async fn disk_read<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> kernel_api::pnp::DriverStep {
    let (off, total) = match req.read().kind {
        RequestType::Read { offset, len } => (offset, len),
        _ => return kernel_api::pnp::DriverStep::complete(DriverStatus::InvalidParameter),
    };

    if total == 0 {
        return kernel_api::pnp::DriverStep::complete(DriverStatus::Success);
    }

    let dx = disk_ext(&dev);
    if !dx.props_ready.load(Ordering::Acquire)
        && let Err(st) = query_props_sync(&dev).await
    {
        return kernel_api::pnp::DriverStep::complete(st);
    }

    let bs = dx.block_size.load(Ordering::Acquire) as u64;
    if bs == 0 {
        return kernel_api::pnp::DriverStep::complete(DriverStatus::InvalidParameter);
    }

    if req.read().data_len() < total {
        return kernel_api::pnp::DriverStep::complete(DriverStatus::InsufficientResources);
    }

    let aligned = (off % bs == 0) && (total as u64).is_multiple_of(bs);
    if !aligned {
        req.write().status = DriverStatus::InvalidParameter;
        return kernel_api::pnp::DriverStep::complete(DriverStatus::InvalidParameter);
    }

    req.write().traversal_policy = TraversalPolicy::ForwardLower;
    kernel_api::pnp::DriverStep::Continue
}

#[request_handler]
pub async fn disk_write<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> kernel_api::pnp::DriverStep {
    let (off, total) = match req.read().kind {
        RequestType::Write {
            offset,
            len,
            flush_write_through: _,
        } => (offset, len),
        _ => return kernel_api::pnp::DriverStep::complete(DriverStatus::InvalidParameter),
    };

    if total == 0 {
        return kernel_api::pnp::DriverStep::complete(DriverStatus::Success);
    }

    let dx = disk_ext(&dev);
    if !dx.props_ready.load(Ordering::Acquire)
        && let Err(st) = query_props_sync(&dev).await
    {
        return kernel_api::pnp::DriverStep::complete(st);
    }

    let bs = dx.block_size.load(Ordering::Acquire) as u64;
    if bs == 0 {
        return kernel_api::pnp::DriverStep::complete(DriverStatus::InvalidParameter);
    }

    if req.read().data_len() < total {
        return kernel_api::pnp::DriverStep::complete(DriverStatus::InsufficientResources);
    }

    let aligned = (off % bs == 0) && (total as u64).is_multiple_of(bs);
    if !aligned {
        req.write().status = DriverStatus::InvalidParameter;
        return kernel_api::pnp::DriverStep::complete(DriverStatus::InvalidParameter);
    }

    req.write().traversal_policy = TraversalPolicy::ForwardLower;
    kernel_api::pnp::DriverStep::Continue
}

#[request_handler]
pub async fn disk_ioctl<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> kernel_api::pnp::DriverStep {
    let code = match req.read().kind {
        RequestType::DeviceControl(c) => c,
        _ => return kernel_api::pnp::DriverStep::complete(DriverStatus::InvalidParameter),
    };

    match code {
        IOCTL_DRIVE_IDENTIFY => {
            let mut ch = RequestHandle::new_pnp(
                PnpRequest {
                    minor_function: PnpMinorFunction::QueryResources,
                    relation: DeviceRelationType::TargetDeviceRelation,
                    id_type: QueryIdType::CompatibleIds,
                    ids_out: Vec::new(),
                    data_out: RequestData::empty(),
                },
                RequestData::empty(),
            );

            let st = pnp_forward_request_to_next_lower(dev.clone(), &mut ch).await;
            if st != DriverStatus::Success {
                return kernel_api::pnp::DriverStep::complete(st);
            }

            let mut info_opt = {
                let mut wr = ch.write();
                wr.pnp
                    .as_mut()
                    .and_then(|p| p.data_out.try_take::<DiskInfo>())
            };
            if info_opt.is_none() {
                info_opt = ch
                    .read()
                    .pnp
                    .as_ref()
                    .and_then(|p| p.data_out.view::<DiskInfo>())
                    .copied();
            }

            let info = match info_opt {
                Some(di) => di,
                None => return kernel_api::pnp::DriverStep::complete(DriverStatus::Unsuccessful),
            };

            req.write().set_data_t::<DiskInfo>(info);
            kernel_api::pnp::DriverStep::complete(DriverStatus::Success)
        }
        IOCTL_BLOCK_FLUSH => {
            let mut handle = RequestHandle::new(
                RequestType::DeviceControl(IOCTL_BLOCK_FLUSH),
                RequestData::empty(),
            );
            handle.set_traversal_policy(TraversalPolicy::ForwardLower);
            let status = pnp_forward_request_to_next_lower(dev.clone(), &mut handle).await;
            kernel_api::pnp::DriverStep::complete(status)
        }
        _ => kernel_api::pnp::DriverStep::Continue,
    }
}

#[inline]
pub fn disk_ext<'a>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, DiskExt> {
    dev.try_devext::<DiskExt>().expect("disk dev ext missing")
}

async fn query_props_sync(dev: &Arc<DeviceObject>) -> Result<(), DriverStatus> {
    let mut ch = RequestHandle::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
        RequestData::empty(),
    );
    let st = pnp_forward_request_to_next_lower(dev.clone(), &mut ch).await;

    if st != DriverStatus::Success {
        return Err(st);
    }
    if ch.read().status != DriverStatus::Success {
        return Err(ch.read().status);
    }

    let mut di_opt = {
        let mut req = ch.write();
        req.pnp
            .as_mut()
            .and_then(|p| p.data_out.try_take::<DiskInfo>())
    };

    if di_opt.is_none() {
        let req = ch.read();
        di_opt = req
            .pnp
            .as_ref()
            .and_then(|p| p.data_out.view::<DiskInfo>())
            .copied()
            .or_else(|| {
                let Some(pnp) = req.pnp.as_ref() else {
                    return None;
                };
                let blob = pnp.data_out.as_slice();
                if blob.len() < size_of::<DiskInfo>() {
                    return None;
                }
                Some(unsafe { *(blob.as_ptr() as *const DiskInfo) })
            });
    }

    let di = match di_opt {
        Some(di) => di,
        None => return Err(DriverStatus::Unsuccessful),
    };

    let dx = disk_ext(dev);
    dx.block_size
        .store(di.logical_block_size.max(1), Ordering::Release);
    dx.props_ready.store(true, Ordering::Release);

    Ok(())
}
