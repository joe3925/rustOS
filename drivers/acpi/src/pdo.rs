use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use aml::{AmlContext, AmlName, AmlValue, value::Args};
use kernel_api::{DeviceObject, DriverStatus, PnpMinorFunction, QueryIdType, Request, println};

use crate::aml::{build_query_resources_blob, read_ids};

#[repr(C)]
pub struct AcpiPdoExt {
    pub acpi_path: aml::AmlName,
    pub ctx: *const spin::RwLock<aml::AmlContext>,
}

#[unsafe(no_mangle)]
pub extern "win64" fn acpi_pdo_pnp_dispatch(dev: &Arc<DeviceObject>, req: &mut Request) {
    use kernel_api::alloc_api::ffi::pnp_complete_request;
    let Some(pnp) = req.pnp.as_mut() else {
        req.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(req) };
        return;
    };

    match pnp.minor_function {
        PnpMinorFunction::QueryId => {
            let ext: &AcpiPdoExt = unsafe { &*((&*dev.dev_ext).as_ptr() as *const AcpiPdoExt) };
            let ctx_lock = unsafe { &*ext.ctx };
            let mut ctx = ctx_lock.write();

            match pnp.id_type {
                QueryIdType::HardwareIds => {
                    let (hid_opt, mut cids) = read_ids(&mut ctx, &ext.acpi_path);
                    if let Some(hid) = hid_opt {
                        pnp.ids_out.push(hid);
                    }
                    pnp.ids_out.append(&mut cids);
                    req.status = DriverStatus::Success;
                }
                QueryIdType::CompatibleIds => {
                    let (_hid, mut cids) = read_ids(&mut ctx, &ext.acpi_path);
                    pnp.ids_out.append(&mut cids);
                    req.status = DriverStatus::Success;
                }
                QueryIdType::DeviceId => {
                    if let (Some(hid), _) = read_ids(&mut ctx, &ext.acpi_path) {
                        pnp.ids_out.push(alloc::format!("ACPI\\{}", hid));
                        req.status = DriverStatus::Success;
                    } else {
                        req.status = DriverStatus::NoSuchDevice;
                    }
                }
                QueryIdType::InstanceId => {
                    if let Some(uid) = read_uid(&mut ctx, &ext.acpi_path) {
                        pnp.ids_out.push(uid);
                        req.status = DriverStatus::Success;
                    } else {
                        req.status = DriverStatus::NoSuchDevice;
                    }
                }
            }

            drop(ctx);
            unsafe { pnp_complete_request(req) };
        }

        PnpMinorFunction::QueryResources => {
            let ext: &AcpiPdoExt = unsafe { &*((&*dev.dev_ext).as_ptr() as *const AcpiPdoExt) };
            let ctx_lock: &spin::RwLock<aml::AmlContext> = unsafe { &*ext.ctx };
            let mut ctx = ctx_lock.write();

            match build_query_resources_blob(&mut ctx, &ext.acpi_path) {
                Some(blob) => {
                    pnp.blob_out = blob;
                    req.status = DriverStatus::Success;
                }
                None => {
                    req.status = DriverStatus::NoSuchDevice;
                }
            }

            drop(ctx);
            unsafe { pnp_complete_request(req) };
        }

        PnpMinorFunction::StartDevice => {
            req.status = DriverStatus::Success;
            unsafe { pnp_complete_request(req) };
        }

        PnpMinorFunction::QueryDeviceRelations => {
            req.status = DriverStatus::Success;
            unsafe { pnp_complete_request(req) };
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
