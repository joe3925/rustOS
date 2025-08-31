use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use aml::{AmlContext, AmlName, AmlValue, value::Args};
use kernel_api::{DeviceObject, DriverStatus, PnpMinorFunction, QueryIdType, Request, println};
use spin::RwLock;

use crate::aml::{McfgSeg, append_ecam_list, build_query_resources_blob, read_ids};

#[repr(C)]
pub struct AcpiPdoExt {
    pub acpi_path: aml::AmlName,
    pub ctx: *const spin::RwLock<aml::AmlContext>,
    pub ecam: alloc::vec::Vec<McfgSeg>,
}

#[unsafe(no_mangle)]
pub extern "win64" fn acpi_pdo_pnp_dispatch(dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    use kernel_api::alloc_api::ffi::pnp_complete_request;

    // No PnP payload → complete as NoSuchDevice.
    if req.read().pnp.is_none() {
        let mut r = {
            let mut g = req.write();
            core::mem::replace(&mut *g, Request::empty())
        };
        r.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(&mut r) };
        {
            *req.write() = r;
        }
        return;
    }

    let minor = { req.read().pnp.as_ref().unwrap().minor_function };

    match minor {
        PnpMinorFunction::QueryId => {
            let ext: &AcpiPdoExt = unsafe { &*((&*dev.dev_ext).as_ptr() as *const AcpiPdoExt) };
            let ctx_lock = unsafe { &*ext.ctx };
            let mut ctx = ctx_lock.write();

            let id_type = { req.read().pnp.as_ref().unwrap().id_type };

            match id_type {
                QueryIdType::HardwareIds => {
                    let (hid_opt, mut cids) = read_ids(&mut ctx, &ext.acpi_path);
                    {
                        let mut g = req.write();
                        if let Some(hid) = hid_opt {
                            g.pnp.as_mut().unwrap().ids_out.push(hid);
                        }
                        g.pnp.as_mut().unwrap().ids_out.append(&mut cids);
                        g.status = DriverStatus::Success;
                    }
                }
                QueryIdType::CompatibleIds => {
                    let (_hid, mut cids) = read_ids(&mut ctx, &ext.acpi_path);
                    {
                        let mut g = req.write();
                        g.pnp.as_mut().unwrap().ids_out.append(&mut cids);
                        g.status = DriverStatus::Success;
                    }
                }
                QueryIdType::DeviceId => {
                    let st = {
                        if let (Some(hid), _) = read_ids(&mut ctx, &ext.acpi_path) {
                            let mut g = req.write();
                            g.pnp
                                .as_mut()
                                .unwrap()
                                .ids_out
                                .push(alloc::format!("ACPI\\{}", hid));
                            g.status = DriverStatus::Success;
                            DriverStatus::Success
                        } else {
                            req.write().status = DriverStatus::NoSuchDevice;
                            DriverStatus::NoSuchDevice
                        }
                    };
                    let _ = st;
                }
                QueryIdType::InstanceId => {
                    let st = {
                        if let Some(uid) = read_uid(&mut ctx, &ext.acpi_path) {
                            let mut g = req.write();
                            g.pnp.as_mut().unwrap().ids_out.push(uid);
                            g.status = DriverStatus::Success;
                            DriverStatus::Success
                        } else {
                            req.write().status = DriverStatus::NoSuchDevice;
                            DriverStatus::NoSuchDevice
                        }
                    };
                    let _ = st;
                }
            }

            drop(ctx);
            let mut r = {
                let mut g = req.write();
                core::mem::replace(&mut *g, Request::empty())
            };
            unsafe { pnp_complete_request(&mut r) };
            {
                *req.write() = r;
            }
        }

        PnpMinorFunction::QueryResources => {
            let ext: &AcpiPdoExt = unsafe { &*((&*dev.dev_ext).as_ptr() as *const AcpiPdoExt) };
            let ctx_lock: &spin::RwLock<aml::AmlContext> = unsafe { &*ext.ctx };
            let mut ctx = ctx_lock.write();

            let mut blob = build_query_resources_blob(&mut ctx, &ext.acpi_path).unwrap_or_default();
            if !ext.ecam.is_empty() {
                append_ecam_list(&mut blob, &ext.ecam);
            }

            if blob.is_empty() {
                req.write().status = DriverStatus::NoSuchDevice;
            } else {
                let mut g = req.write();

                g.pnp.as_mut().unwrap().blob_out = blob;
                g.status = DriverStatus::Success;
            }

            drop(ctx);
            let mut r = {
                let mut g = req.write();
                core::mem::replace(&mut *g, Request::empty())
            };
            unsafe { pnp_complete_request(&mut r) };
            {
                *req.write() = r;
            }
        }

        PnpMinorFunction::StartDevice => {
            req.write().status = DriverStatus::Success;
            let mut r = {
                let mut g = req.write();
                core::mem::replace(&mut *g, Request::empty())
            };
            unsafe { pnp_complete_request(&mut r) };
            {
                *req.write() = r;
            }
        }

        PnpMinorFunction::QueryDeviceRelations => {
            let mut r = {
                let mut g = req.write();
                core::mem::replace(&mut *g, Request::empty())
            };
            unsafe { pnp_complete_request(&mut r) };
            {
                *req.write() = r;
            }
        }

        _ => {
            req.write().status = DriverStatus::NotImplemented;
            let mut r = {
                let mut g = req.write();
                core::mem::replace(&mut *g, Request::empty())
            };
            unsafe { pnp_complete_request(&mut r) };
            {
                *req.write() = r;
            }
        }
    }
}

pub fn read_uid(ctx: &mut AmlContext, dev: &AmlName) -> Option<String> {
    let uid_path = AmlName::from_str(&(dev.as_string() + "._UID")).ok()?;

    if let Ok(val) = ctx.invoke_method(&uid_path, Args::EMPTY) {
        return uid_to_string(val);
    }
    None
}

#[inline]
fn uid_to_string(v: AmlValue) -> Option<String> {
    match v {
        AmlValue::Integer(n) => Some(n.to_string()),
        AmlValue::String(s) => Some(s),
        AmlValue::Buffer(b) => core::str::from_utf8(&b.lock())
            .ok()
            .map(|s| s.trim_end_matches('\0').to_string()),
        _ => None,
    }
}
