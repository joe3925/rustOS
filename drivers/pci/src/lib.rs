#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod dev_ext;
mod msvc_shims;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(not(test))]
use core::panic::PanicInfo;

use dev_ext::{
    DevExt, PciPdoExt, build_resources_blob, header_type, hwids_for, instance_path_for,
    load_segments_from_parent, name_for, parse_ecam_segments_from_blob, probe_function,
};

use kernel_api::{
    RequestExt,
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{io::IoVtable, pnp::DeviceIds},
    pnp::{
        DeviceRelationType, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
        driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
        pnp_forward_request_to_next_lower,
    },
    println,
    request::Request,
    request_handler,
    status::DriverStatus,
};
use spin::{Once, RwLock};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        use kernel_api::util::panic_common;
        panic_common(MOD_NAME, info)
    }
}
#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, bus_driver_device_add);
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_device_add(
    _driver: Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::StartDevice, pci_bus_pnp_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        pci_bus_pnp_query_devrels,
    );
    dev_init.pnp_vtable = Some(vt);

    dev_init.set_dev_ext_from(DevExt {
        segments: Once::new(),
    });

    DriverStatus::Success
}

#[request_handler]
pub async fn pci_bus_pnp_start(
    device: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let query = Request::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        },
        Box::new([]),
    );

    let child = Arc::new(RwLock::new(query));
    let st = pnp_forward_request_to_next_lower(&device, child.clone())?.await;

    if st != DriverStatus::NoSuchDevice {
        let qst = { child.read().status };
        if qst != DriverStatus::Success {
            return qst;
        }

        let blob = {
            let g = child.read();
            g.pnp
                .as_ref()
                .map(|p| p.blob_out.clone())
                .unwrap_or_default()
        };
        let segs = parse_ecam_segments_from_blob(&blob);

        if segs.is_empty() {
            println!("[PCI] no ECAM block found in parent resources");
            return DriverStatus::Continue;
        }

        if let Ok(ext) = device.try_devext::<DevExt>() {
            ext.segments.call_once(|| segs);
        } else {
            return DriverStatus::Continue;
        }
    } else {
        // Fallback derive segments from parent using platform-specific probe
        let segs = load_segments_from_parent(&device);
        if let Ok(ext) = device.try_devext::<DevExt>() {
            if !segs.is_empty() {
                ext.segments.call_once(|| segs);
            }
        } else {
            return DriverStatus::Continue;
        }
    }

    DriverStatus::Continue
}

#[request_handler]
pub async fn pci_bus_pnp_query_devrels(
    device: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let relation = req.read().pnp.as_ref().unwrap().relation;
    if relation == DeviceRelationType::BusRelations {
        let st = enumerate_bus(&device, &mut *req.write());
        if st == DriverStatus::Success {
            return DriverStatus::Continue;
        } else {
            return st;
        }
    }

    DriverStatus::Continue
}

pub extern "win64" fn enumerate_bus(
    device: &Arc<DeviceObject>,
    _req: &mut Request,
) -> DriverStatus {
    let devnode = match device.dev_node.get().unwrap().upgrade() {
        Some(dn) => dn,
        None => {
            println!("[PCI] PDO missing DevNode");
            return DriverStatus::NoSuchDevice;
        }
    };

    let ext = match device.try_devext::<DevExt>() {
        Ok(g) => g,
        Err(_) => {
            println!("[PCI] missing DevExt");
            return DriverStatus::NoSuchDevice;
        }
    };

    if ext.segments.get().is_none() {
        println!("[PCI] No ECAM segments; falling back to legacy CFG#1 scan.");
        for bus in 0u8..=255 {
            for dev in 0u8..32 {
                let ht = match dev_ext::header_type_legacy(bus, dev) {
                    Some(v) => v,
                    None => continue,
                };
                let multi = (ht & 0x80) != 0;
                let func_span = if multi { 0u8..8 } else { 0u8..1 };
                for func in func_span {
                    if let Some(p) = dev_ext::probe_function_legacy(bus, dev, func) {
                        make_pdo_for_function(&devnode, &p);
                    }
                }
            }
        }
        return DriverStatus::Success;
    }

    for seg in ext.segments.get().unwrap() {
        for bus in seg.start_bus..=seg.end_bus {
            for dev in 0u8..32 {
                let ht = match header_type(seg, bus, dev) {
                    Some(v) => v,
                    None => continue,
                };
                let multi = (ht & 0x80) != 0;
                let func_span = if multi { 0u8..8 } else { 0u8..1 };
                for func in func_span {
                    if let Some(p) = probe_function(seg, bus, dev, func) {
                        make_pdo_for_function(&devnode, &p);
                    }
                }
            }
        }
    }

    DriverStatus::Success
}

fn make_pdo_for_function(parent: &Arc<DevNode>, p: &PciPdoExt) {
    let (hardware, compatible, class_tag) = hwids_for(p);
    let ids = DeviceIds {
        hardware,
        compatible,
    };

    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::QueryId, pci_pdo_query_id);
    vt.set(PnpMinorFunction::QueryResources, pci_pdo_query_resources);
    vt.set(PnpMinorFunction::StartDevice, pci_pdo_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        pci_pdo_query_devrels,
    );

    let mut child_init = DeviceInit::new(IoVtable::new(), Some(vt));
    child_init.set_dev_ext_from(*p);

    let name = name_for(p);
    let instance_path = instance_path_for(p);

    let (_child_dn, _child_pdo) = pnp_create_child_devnode_and_pdo_with_init(
        parent,
        name,
        instance_path,
        ids,
        Some(class_tag),
        child_init,
    );
}

#[request_handler]
pub async fn pci_pdo_query_id(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStatus {
    use kernel_api::pnp::QueryIdType;

    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(g) => g,
        Err(_) => {
            req.write().status = DriverStatus::NoSuchDevice;
            return DriverStatus::Success;
        }
    };

    let mut r = req.write();
    let pnp = r.pnp.as_mut().unwrap();
    match pnp.id_type {
        QueryIdType::HardwareIds => {
            let (hw, _cmp, _) = hwids_for(&ext);
            pnp.ids_out.extend(hw);
            r.status = DriverStatus::Success;
        }
        QueryIdType::CompatibleIds => {
            let (_hw, cmp, _) = hwids_for(&ext);
            pnp.ids_out.extend(cmp);
            r.status = DriverStatus::Success;
        }
        QueryIdType::DeviceId => {
            let (hw, _, _) = hwids_for(&ext);
            if let Some(primary) = hw.first() {
                pnp.ids_out.push(primary.clone());
                r.status = DriverStatus::Success;
            } else {
                r.status = DriverStatus::NoSuchDevice;
            }
        }
        QueryIdType::InstanceId => {
            pnp.ids_out.push(instance_path_for(&ext));
            r.status = DriverStatus::Success;
        }
    }
    DriverStatus::Success
}

#[request_handler]
pub async fn pci_pdo_query_resources(
    dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(g) => g,
        Err(_) => {
            req.write().status = DriverStatus::NoSuchDevice;
            return DriverStatus::Success;
        }
    };

    let mut r = req.write();
    let pnp = r.pnp.as_mut().unwrap();
    pnp.blob_out = build_resources_blob(&ext);
    r.status = DriverStatus::Success;
    DriverStatus::Success
}

#[request_handler]
pub async fn pci_pdo_start(_dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStatus {
    DriverStatus::Success
}

#[request_handler]
pub async fn pci_pdo_query_devrels(
    _dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    DriverStatus::Success
}
