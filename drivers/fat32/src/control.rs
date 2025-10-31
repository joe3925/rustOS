#![no_std]

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::mem::size_of;
use fatfs::FsOptions;
use spin::RwLock;

use kernel_api::{
    DeviceObject, DeviceRelationType, DriverObject, DriverStatus, FsIdentify, GLOBAL_CTRL_LINK,
    IOCTL_FS_IDENTIFY, IOCTL_MOUNTMGR_REGISTER_FS, PartitionInfo, PnpMinorFunction, QueryIdType,
    Request, RequestType,
    alloc_api::{
        DeviceInit, IoType, IoVtable, PnpRequest, PnpVtable, Synchronization,
        ffi::{
            driver_set_evt_device_add, pnp_create_control_device_and_link,
            pnp_create_control_device_with_init, pnp_ioctl_via_symlink, pnp_send_request,
            pnp_wait_for_request,
        },
    },
    bytes_to_box, println,
};

use crate::volume::{VolCtrlDevExt, fs_op_dispatch};
use crate::{block_dev::BlockDev, fat32::Fat32}; // assumed to expose `mount(&Arc<DeviceObject>) -> FileSystem<BlockDev>`
const IOCTL_DRIVE_IDENTIFY: u32 = 0xB000_0004;
#[repr(C)]
struct CtrlDevExt;

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

pub extern "win64" fn fs_root_ioctl(_dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => {
                drop(r);
                req.write().status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };

    match code {
        IOCTL_FS_IDENTIFY => {
            println!("Identify");
            let mut r = req.write();
            if r.data.len() < core::mem::size_of::<FsIdentify>() {
                r.status = DriverStatus::InvalidParameter;
                return;
            }

            let id: &mut FsIdentify = unsafe { &mut *(r.data.as_mut_ptr() as *mut FsIdentify) };

            let mut q = Request::new(RequestType::Pnp, Box::new([]));
            q.pnp = Some(PnpRequest {
                minor_function: PnpMinorFunction::QueryResources,
                relation: DeviceRelationType::TargetDeviceRelation,
                id_type: QueryIdType::DeviceId,
                ids_out: Vec::new(),
                blob_out: Vec::new(),
            });
            let q = Arc::new(RwLock::new(q));

            unsafe { pnp_send_request(&*id.volume_fdo, q.clone()) };
            unsafe { pnp_wait_for_request(&q) };

            let mut sector_size: u16 = 512;
            let mut total_sectors: u64 = 10_000;

            {
                let mut w = q.write();
                if w.status == DriverStatus::Success {
                    if let Some(pnp) = w.pnp.as_mut() {
                        let buf = core::mem::take(&mut pnp.blob_out);
                        if buf.len() == core::mem::size_of::<PartitionInfo>() {
                            let boxed: Box<[u8]> = buf.into_boxed_slice();
                            let pi: Box<PartitionInfo> = unsafe { bytes_to_box(boxed) };
                            sector_size = if pi.disk.logical_block_size != 0 {
                                pi.disk.logical_block_size as u16
                            } else {
                                512
                            };

                            total_sectors = if let Some(ent) = pi.gpt_entry {
                                ent.last_lba.saturating_sub(ent.first_lba).saturating_add(1)
                            } else {
                                id.mount_device = None;
                                id.can_mount = false;
                                r.status = DriverStatus::Success;
                                return;
                            };
                        }
                    }
                }
            }

            let options = FsOptions::new();
            match fatfs::FileSystem::new(
                BlockDev::new(id.volume_fdo.clone(), sector_size, total_sectors),
                options,
            ) {
                Ok(fs) => {
                    let mut io_vtable = IoVtable::new();
                    io_vtable.set(IoType::Fs(fs_op_dispatch), Synchronization::Sync, 0);

                    let init = DeviceInit {
                        dev_ext_size: size_of::<VolCtrlDevExt>(),
                        io_vtable,
                        pnp_vtable: None,
                    };

                    let vol_name = alloc::format!("\\Device\\fat32.vol.{:p}", &*id.volume_fdo);
                    let vol_ctrl = unsafe { pnp_create_control_device_with_init(vol_name, init) };
                    println!("1");
                    let vdx = ext_mut::<VolCtrlDevExt>(&vol_ctrl);
                    println!("addr = {:p}", &vdx.fs as *const _);
                    println!("fs addr = {:p}", &fs as *const _);
                    vdx.fs = fs;
                    println!("3");
                    id.mount_device = Some(vol_ctrl);
                    println!("4");
                    id.can_mount = true;
                    println!("5");
                    println!("idk");
                    r.status = DriverStatus::Success;
                }
                Err(_) => {
                    id.mount_device = None;
                    id.can_mount = false;
                    r.status = DriverStatus::Success;
                }
            }
        }
        _ => {
            req.write().status = DriverStatus::NotImplemented;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn fat_start(
    _dev: &Arc<DeviceObject>,
    _req: Arc<spin::rwlock::RwLock<Request>>,
) -> DriverStatus {
    DriverStatus::Success
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, fs_device_add) };

    let mut io_vtable = IoVtable::new();
    io_vtable.set(
        IoType::DeviceControl(fs_root_ioctl),
        Synchronization::Sync,
        0,
    );

    let init = DeviceInit {
        dev_ext_size: core::mem::size_of::<CtrlDevExt>(),
        io_vtable,
        pnp_vtable: None,
    };

    let ctrl_link = "\\GLOBAL\\FileSystems\\fat32".to_string();
    let ctrl_name = "\\Device\\fat32.fs".to_string();
    let _ctrl =
        unsafe { pnp_create_control_device_and_link(ctrl_name.clone(), init, ctrl_link.clone()) };

    let reg = Arc::new(RwLock::new(Request::new(
        RequestType::DeviceControl(IOCTL_MOUNTMGR_REGISTER_FS),
        ctrl_link.clone().into_bytes().into_boxed_slice(),
    )));
    unsafe {
        let _ = pnp_ioctl_via_symlink(
            GLOBAL_CTRL_LINK.to_string(),
            IOCTL_MOUNTMGR_REGISTER_FS,
            reg.clone(),
        );
        pnp_wait_for_request(&reg);
    }

    DriverStatus::Success
}

pub extern "win64" fn fs_device_add(
    _driver: &Arc<DriverObject>,
    _dev_init: &mut DeviceInit,
) -> DriverStatus {
    DriverStatus::Success
}
