use alloc::string::{String, ToString};
use alloc::sync::Arc;
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
    pub ctx: Arc<spin::RwLock<aml::AmlContext>>,
    pub ecam: alloc::vec::Vec<McfgSeg>,
}

#[unsafe(no_mangle)]
pub extern "win64" fn acpi_pdo_pnp_dispatch(dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    if req.read().pnp.is_none() {
        {
            req.write().status = DriverStatus::NoSuchDevice;
        }
        unsafe { pnp_complete_request(&req) };
        return;
    }

    let minor = { req.read().pnp.as_ref().unwrap().minor_function };

    match minor {
        PnpMinorFunction::QueryId => {
            let ext: &AcpiPdoExt = &dev.try_devext().expect("Failed to get dev ext");
            let ctx_lock = unsafe { &ext.ctx };
            let mut ctx = ctx_lock.write();

            match { req.read().pnp.as_ref().unwrap().id_type } {
                QueryIdType::HardwareIds => {
                    let (hid_opt, mut cids) = read_ids(&mut ctx, &ext.acpi_path);
                    let mut g = req.write();
                    if let Some(hid) = hid_opt {
                        g.pnp.as_mut().unwrap().ids_out.push(hid);
                    }
                    g.pnp.as_mut().unwrap().ids_out.append(&mut cids);
                    g.status = DriverStatus::Success;
                }
                QueryIdType::CompatibleIds => {
                    let (_hid, mut cids) = read_ids(&mut ctx, &ext.acpi_path);
                    let mut g = req.write();
                    g.pnp.as_mut().unwrap().ids_out.append(&mut cids);
                    g.status = DriverStatus::Success;
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
                    } else if let Some(adr) = read_adr(&mut ctx, &ext.acpi_path) {
                        let mut g = req.write();
                        g.pnp
                            .as_mut()
                            .unwrap()
                            .ids_out
                            .push(alloc::format!("ADR_{:08X}", adr));
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
            let ext: &AcpiPdoExt = &dev
                .try_devext::<&AcpiPdoExt>()
                .expect("ACPI enum failed AcpiPdoExt is not set ");
            let ctx_lock: &spin::RwLock<AmlContext> = unsafe { &ext.ctx };
            let mut ctx = ctx_lock.write();

            let mut blob = build_query_resources_blob(&mut ctx, &ext.acpi_path).unwrap_or_default();

            // Only append ECAM for PCI/PCIe root bridges.
            if is_pci_root(&mut ctx, &ext.acpi_path) && !ext.ecam.is_empty() {
                append_ecam_list(&mut blob, &ext.ecam);
            }

            {
                let mut g = req.write();
                g.pnp.as_mut().unwrap().blob_out = blob; // may be empty; that’s valid
                g.status = DriverStatus::Success;
            }

            drop(ctx);
            unsafe { pnp_complete_request(&req) };
        }

        PnpMinorFunction::StartDevice => {
            {
                req.write().status = DriverStatus::Success;
            }
            unsafe { pnp_complete_request(&req) };
        }

        PnpMinorFunction::QueryDeviceRelations => {
            // Leaf PDO: nothing to enumerate.
            unsafe { pnp_complete_request(&req) };
        }

        _ => {
            {
                req.write().status = DriverStatus::NotImplemented;
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

fn read_adr(ctx: &mut AmlContext, dev: &AmlName) -> Option<u32> {
    let adr_path = AmlName::from_str(&(dev.as_string() + "._ADR")).ok()?;
    if let Ok(AmlValue::Integer(n)) = ctx.invoke_method(&adr_path, Args::EMPTY) {
        return Some(n as u32);
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

fn is_pci_root(ctx: &mut AmlContext, dev: &AmlName) -> bool {
    let (hid_opt, cids) = read_ids(ctx, dev);
    let hid = hid_opt.unwrap_or_default();
    let is_pci_hid = hid == "PNP0A03" || hid == "PNP0A08";
    let is_pci_cid = cids.iter().any(|c| c == "PNP0A03" || c == "PNP0A08");
    is_pci_hid || is_pci_cid
}
