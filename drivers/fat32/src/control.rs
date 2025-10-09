use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
};
use core::{mem::size_of, ptr, slice};
use spin::RwLock;

use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, FsIdentify, IOCTL_FS_IDENTIFY,
    IOCTL_MOUNTMGR_REGISTER_FS, PnpMinorFunction, Request, RequestType,
    alloc_api::{
        DeviceInit, IoType, IoVtable, PnpVtable, Synchronization,
        ffi::{
            driver_set_evt_device_add, pnp_create_control_device_and_link,
            pnp_create_control_device_with_init, pnp_ioctl_via_symlink, pnp_wait_for_request,
        },
    },
    println,
};

use crate::volume::VolCtrlDevExt;
use crate::{fat32::Fat32, volume::fs_op_dispatch};

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
            let mut r = req.write();
            if r.data.len() < core::mem::size_of::<FsIdentify>() {
                r.status = DriverStatus::InvalidParameter;
                return;
            }

            let id: &mut FsIdentify = unsafe { &mut *(r.data.as_mut_ptr() as *mut FsIdentify) };

            match Fat32::mount(&id.volume_fdo) {
                Ok(fs) => {
                    let mut io_vtable = IoVtable::new();

                    io_vtable.set(IoType::Fs(fs_op_dispatch), Synchronization::Sync, 0);
                    let mut init = DeviceInit {
                        dev_ext_size: size_of::<VolCtrlDevExt>(),
                        io_vtable,
                        pnp_vtable: None,
                    };

                    let vol_name = alloc::format!("\\Device\\fat32.vol.{:p}", &*id.volume_fdo);
                    let vol_ctrl = unsafe { pnp_create_control_device_with_init(vol_name, init) };

                    let vdx = ext_mut::<VolCtrlDevExt>(&vol_ctrl);
                    unsafe { ptr::write(&mut vdx.fs as *mut Fat32, fs) };

                    id.mount_device = Some(vol_ctrl);
                    id.can_mount = true;
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
    dev: &Arc<DeviceObject>,
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

    let mut init = DeviceInit {
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
            "\\GLOBAL\\MountMgr".to_string(),
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
