use alloc::sync::Arc;
use spin::RwLock;

use kernel_api::{DeviceObject, DriverStatus, FsOp, Request, RequestType};
// assume these are defined in kernel_api; adjust names if different:

use crate::fat32::Fat32;

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Fat32,
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

pub extern "win64" fn fs_volume_dispatch(dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    // peek which kind of request we got
    let kind = { req.read().kind };

    match kind {
        RequestType::Fs(op) => {
            let mut r = req.write();

            let _vdx = ext_mut::<VolCtrlDevExt>(dev);

            match op {
                // open/close
                FsOp::Open => {
                    /* TODO: parse path/flags; return a handle */
                    r.status = DriverStatus::NotImplemented;
                }
                FsOp::Close => {
                    /* TODO: close handle */
                    r.status = DriverStatus::NotImplemented;
                }

                FsOp::Read => {
                    /* TODO: read from handle + offset */
                    r.status = DriverStatus::NotImplemented;
                }
                FsOp::Write => {
                    /* TODO: write to handle + offset */
                    r.status = DriverStatus::NotImplemented;
                }
                FsOp::Flush => {
                    /* TODO: flush file/volume */
                    r.status = DriverStatus::NotImplemented;
                }

                FsOp::Create => {
                    /* TODO: create file */
                    r.status = DriverStatus::NotImplemented;
                }
                FsOp::Rename => {
                    /* TODO: rename/move */
                    r.status = DriverStatus::NotImplemented;
                }

                FsOp::Seek => {
                    /* TODO: update handle pointer */
                    r.status = DriverStatus::NotImplemented;
                }

                _ => {
                    r.status = DriverStatus::NotImplemented;
                }
            }
        }

        // ===== Your existing IOCTLs (keep as-is or expand) =====
        RequestType::DeviceControl(_code) => {
            // handle per-volume IOCTLs here if you have any; otherwise:
            req.write().status = DriverStatus::NotImplemented;
        }

        // these should be sent via FsOp or Read/Write; reject here
        _ => {
            req.write().status = DriverStatus::InvalidParameter;
        }
    }
}
