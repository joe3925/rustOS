#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod dev_ext;
mod msix;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(not(test))]
use core::panic::PanicInfo;

use dev_ext::{
    DevExt, PciPdoExt, PrtEntry, build_resources_blob, hwids_for, instance_path_for,
    load_segments_from_parent, name_for, parse_ecam_segments_from_blob, parse_prt_from_blob,
    scan_ecam_bus,
};

use kernel_api::{
    IOCTL_PCI_SETUP_MSIX,
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        io::{IoType, IoVtable, Synchronization},
        pnp::DeviceIds,
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
        driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
        pnp_forward_request_to_next_lower,
    },
    println,
    request::{Request, RequestHandle, RequestType},
    request_handler,
    runtime::spawn_blocking,
    status::DriverStatus,
};
use spin::Once;

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
) -> DriverStep {
    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::StartDevice, pci_bus_pnp_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        pci_bus_pnp_query_devrels,
    );
    dev_init.pnp_vtable = Some(vt);

    dev_init.set_dev_ext_from(DevExt {
        segments: Once::new(),
        prt: Once::new(),
    });

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn pci_bus_pnp_start<'a, 'b>(
    device: Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let mut query_handle = RequestHandle::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
        RequestData::empty(),
    );

    let st = pnp_forward_request_to_next_lower(device.clone(), &mut query_handle).await;

    if st != DriverStatus::NoSuchDevice {
        let qst = st;
        if qst != DriverStatus::Success {
            return DriverStep::complete(qst);
        }

        let blob = query_handle
            .read()
            .pnp
            .as_ref()
            .map(|p| p.data_out.as_slice().to_vec())
            .unwrap_or_default();
        let segs = parse_ecam_segments_from_blob(&blob);

        if segs.is_empty() {
            println!("[PCI] no ECAM block found in parent resources");
            return DriverStep::Continue;
        }

        let prt_entries = parse_prt_from_blob(&blob);

        if let Ok(ext) = device.try_devext::<DevExt>() {
            ext.segments.call_once(|| segs);
            if !prt_entries.is_empty() {
                ext.prt.call_once(|| prt_entries);
            }
        } else {
            return DriverStep::Continue;
        }
    } else {
        // Fallback derive segments from parent using platform-specific probe
        let segs = load_segments_from_parent(&device).await;
        if let Ok(ext) = device.try_devext::<DevExt>() {
            if !segs.is_empty() {
                ext.segments.call_once(|| segs);
            }
        } else {
            return DriverStep::Continue;
        }
    }

    DriverStep::Continue
}

#[request_handler]
pub async fn pci_bus_pnp_query_devrels<'a, 'b>(
    device: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
    if relation == DeviceRelationType::BusRelations {
        let st = enumerate_bus(&device).await;
        if st == DriverStatus::Success {
            return DriverStep::Continue;
        } else {
            return DriverStep::complete(st);
        }
    }

    DriverStep::Continue
}

fn resolve_gsi(p: &mut PciPdoExt, prt: &[PrtEntry]) {
    if p.irq_pin == 0 {
        return;
    }
    let prt_pin = p.irq_pin - 1; // PCI irq_pin is 1-based, PRT pin is 0-based
    if let Some(entry) = prt.iter().find(|e| e.device == p.dev && e.pin == prt_pin) {
        p.irq_gsi = Some(entry.gsi);
    }
}

pub async fn enumerate_bus(device: &Arc<DeviceObject>) -> DriverStatus {
    let devnode = match device.dev_node.get().unwrap().upgrade() {
        Some(dn) => dn,
        None => {
            println!("[PCI] PDO missing DevNode");
            return DriverStatus::NoSuchDevice;
        }
    };

    let (segments, prt_vec) = match device.try_devext::<DevExt>() {
        Ok(g) => (
            g.segments.get().cloned(),
            g.prt.get().cloned().unwrap_or_default(),
        ),
        Err(_) => {
            println!("[PCI] missing DevExt");
            return DriverStatus::NoSuchDevice;
        }
    };

    let prt_arc: Arc<[PrtEntry]> = Arc::from(prt_vec.clone());

    if segments.is_none() {
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
                    if let Some(mut p) = dev_ext::probe_function_legacy(bus, dev, func) {
                        resolve_gsi(&mut p, prt_vec.as_slice());
                        make_pdo_for_function(&devnode, &p);
                    }
                }
            }
        }
        return DriverStatus::Success;
    }

    let mut joins = Vec::new();
    for seg in segments.unwrap() {
        for bus in seg.start_bus..=seg.end_bus {
            let seg_copy = seg;
            let prt_copy = prt_arc.clone();
            joins.push(spawn_blocking(move || {
                let mut devices = match scan_ecam_bus(&seg_copy, bus) {
                    Ok(v) => v,
                    Err(e) => {
                        println!(
                            "[PCI] failed to scan segment {} bus {}: {:?}",
                            seg_copy.seg, bus, e
                        );
                        Vec::new()
                    }
                };

                if !prt_copy.is_empty() {
                    for p in devices.iter_mut() {
                        resolve_gsi(p, prt_copy.as_ref());
                    }
                }
                devices
            }));
        }
    }

    for join in joins {
        for p in join.await {
            make_pdo_for_function(&devnode, &p);
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

    let mut io_vt = IoVtable::new();
    io_vt.set(
        IoType::DeviceControl(pci_pdo_ioctl),
        Synchronization::Async,
        0,
    );

    let mut child_init = DeviceInit::new(io_vt, Some(vt));
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
pub async fn pci_pdo_query_id<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    use kernel_api::pnp::QueryIdType;

    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(g) => g,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let mut status = DriverStatus::Success;
    {
        let mut r = req.write();
        match r.pnp.as_mut() {
            Some(pnp) => match pnp.id_type {
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
            },
            None => status = DriverStatus::InvalidParameter,
        }
    }
    DriverStep::complete(status)
}

#[request_handler]
pub async fn pci_pdo_query_resources<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(g) => g,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let status = {
        let mut r = req.write();
        match r.pnp.as_mut() {
            Some(pnp) => {
                pnp.data_out =
                    RequestData::from_boxed_bytes(build_resources_blob(&ext).into_boxed_slice());
                DriverStatus::Success
            }
            None => DriverStatus::InvalidParameter,
        }
    };

    DriverStep::complete(status)
}

#[request_handler]
pub async fn pci_pdo_start<'a, 'b>(
    _dev: Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}
#[request_handler]
pub async fn pci_pdo_query_devrels<'a, 'b>(
    _dev: Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn pci_pdo_ioctl<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let code = match {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => Some(c),
            _ => None,
        }
    } {
        Some(c) => c,
        None => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    match code {
        IOCTL_PCI_SETUP_MSIX => msix::pci_setup_msix(dev, req).await,
        _ => DriverStep::complete(DriverStatus::NotImplemented),
    }
}
