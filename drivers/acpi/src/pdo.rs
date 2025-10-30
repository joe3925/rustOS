use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use aml::{AmlContext, AmlName, AmlValue, value::Args};
use kernel_api::{
    DeviceObject, DriverStatus, PnpMinorFunction, QueryIdType, Request,
    alloc_api::ffi::pnp_complete_request,
};
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
    if req.read().pnp.is_none() {
        {
            let mut g = req.write();
            g.status = DriverStatus::NoSuchDevice;
        }
        unsafe { pnp_complete_request(&req) };
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
                    if let (Some(hid), _) = read_ids(&mut ctx, &ext.acpi_path) {
                        let mut g = req.write();
                        g.pnp
                            .as_mut()
                            .unwrap()
                            .ids_out
                            .push(alloc::format!("ACPI\\{}", hid));
                        g.status = DriverStatus::Success;
                    } else {
                        req.write().status = DriverStatus::NoSuchDevice;
                    }
                }
                QueryIdType::InstanceId => {
                    if let Some(uid) = read_uid(&mut ctx, &ext.acpi_path) {
                        let mut g = req.write();
                        g.pnp.as_mut().unwrap().ids_out.push(uid);
                        g.status = DriverStatus::Success;
                    } else {
                        req.write().status = DriverStatus::NoSuchDevice;
                    }
                }
            }

            drop(ctx);
            unsafe { pnp_complete_request(&req) };
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
            unsafe { pnp_complete_request(&req) };
        }

        PnpMinorFunction::StartDevice => {
            {
                let mut g = req.write();
                g.status = DriverStatus::Success;
            }
            unsafe { pnp_complete_request(&req) };
        }

        PnpMinorFunction::QueryDeviceRelations => {
            unsafe { pnp_complete_request(&req) };
        }

        _ => {
            {
                let mut g = req.write();
                g.status = DriverStatus::NotImplemented;
            }
            unsafe { pnp_complete_request(&req) };
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
