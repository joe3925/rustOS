#![no_std]
#![no_main]
extern crate alloc;

mod dev_ext;
mod msvc_shims;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::{
    mem::{size_of, zeroed},
    ptr,
};

use dev_ext::{
    DevExt, PciPdoExt, build_resources_blob, header_type, hwids_for, instance_path_for,
    load_segments_from_parent, name_for, probe_function,
};

use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, PnpMinorFunction, Request,
    RequestType,
    alloc_api::{
        DeviceIds, DeviceInit, PnpVtable,
        ffi::{
            driver_set_evt_device_add, pnp_complete_request,
            pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
            pnp_wait_for_request,
        },
    },
    println,
};
use spin::RwLock;

use crate::dev_ext::parse_ecam_segments_from_blob;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[PCI] {}", info);
    loop {}
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, bus_driver_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = size_of::<DevExt>();

    // PnP vtable: split handlers per-minor
    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::StartDevice, pci_bus_pnp_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        pci_bus_pnp_query_devrels,
    );
    dev_init.pnp_vtable = Some(vt);

    DriverStatus::Success
}

/* ---------------- PCI BUS: PnP minor callbacks ---------------- */

extern "win64" fn pci_bus_pnp_start(
    device: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let mut query = Request::new(RequestType::Pnp, Box::new([]));
    query.pnp = Some(kernel_api::alloc_api::PnpRequest {
        minor_function: PnpMinorFunction::QueryResources,
        relation: kernel_api::DeviceRelationType::TargetDeviceRelation,
        id_type: kernel_api::QueryIdType::CompatibleIds,
        ids_out: Vec::new(),
        blob_out: Vec::new(),
    });

    let child = Arc::new(RwLock::new(query));
    let st = unsafe { pnp_forward_request_to_next_lower(device, child.clone()) };
    if st != DriverStatus::NoSuchDevice {
        unsafe { pnp_wait_for_request(&child) };
        let qst = { child.read().status };
        if qst != DriverStatus::Success {
            req.write().status = qst;
            return DriverStatus::Success; // manager will complete
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
        }
        let ext_ptr = device.dev_ext.as_ptr() as *mut DevExt;
        unsafe { core::ptr::write(ext_ptr, DevExt { segments: segs }) };
    } else {
        let ext = load_segments_from_parent(device);
        let ext_ptr = device.dev_ext.as_ptr() as *mut DevExt;
        unsafe { core::ptr::write(ext_ptr, ext) };
    }

    let down2 = unsafe { pnp_forward_request_to_next_lower(device, req.clone()) };
    if down2 == DriverStatus::NoSuchDevice {
        let mut r = req.write();
        if r.status == DriverStatus::Pending {
            r.status = DriverStatus::Success;
        }
        return DriverStatus::Success; // manager completes
    }

    req.write().status = DriverStatus::Pending;
    DriverStatus::Pending
}

extern "win64" fn pci_bus_pnp_query_devrels(
    device: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let relation = req.read().pnp.as_ref().unwrap().relation;
    if relation == kernel_api::DeviceRelationType::BusRelations {
        let st = enumerate_bus(device, &mut *req.write());
        req.write().status = st;
        return DriverStatus::Success;
    }

    req.write().status = DriverStatus::Pending;
    DriverStatus::Pending
}

pub extern "win64" fn enumerate_bus(
    device: &Arc<DeviceObject>,
    _req: &mut Request,
) -> DriverStatus {
    let devnode = unsafe {
        (*(Arc::as_ptr(device) as *const DeviceObject))
            .dev_node
            .upgrade()
            .expect("[PCI] PDO missing DevNode")
    };

    let ext: &DevExt = unsafe { &*(device.dev_ext.as_ptr() as *const DevExt) };

    if ext.segments.is_empty() {
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

    for seg in &ext.segments {
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

fn make_pdo_for_function(parent: &Arc<kernel_api::DevNode>, p: &PciPdoExt) {
    let (hardware, compatible, class_tag) = hwids_for(p);
    let ids = DeviceIds {
        hardware,
        compatible,
    };

    let mut child_init: DeviceInit = unsafe { zeroed() };
    child_init.dev_ext_size = core::mem::size_of::<PciPdoExt>();

    // PDO PnP vtable: split per-minor
    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::QueryId, pci_pdo_query_id);
    vt.set(PnpMinorFunction::QueryResources, pci_pdo_query_resources);
    vt.set(PnpMinorFunction::StartDevice, pci_pdo_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        pci_pdo_query_devrels,
    );
    child_init.pnp_vtable = Some(vt);

    let name = name_for(p);
    let instance_path = instance_path_for(p);

    let (_child_dn, child_pdo) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(
            parent,
            name,
            instance_path,
            ids,
            Some(class_tag),
            child_init,
        )
    };

    let ptr_ext = child_pdo.dev_ext.as_ptr() as *mut PciPdoExt;
    unsafe {
        ptr::write(ptr_ext, *p);
    }
}

/* ---------------- PCI PDO: per-minor callbacks ---------------- */

extern "win64" fn pci_pdo_query_id(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    use kernel_api::QueryIdType;

    let ext: &PciPdoExt = unsafe { &*(dev.dev_ext.as_ptr() as *const PciPdoExt) };
    let mut r = req.write();
    let pnp = r.pnp.as_mut().unwrap();
    match pnp.id_type {
        QueryIdType::HardwareIds => {
            let (hw, _cmp, _) = hwids_for(ext);
            pnp.ids_out.extend(hw);
            r.status = DriverStatus::Success;
        }
        QueryIdType::CompatibleIds => {
            let (_hw, cmp, _) = hwids_for(ext);
            pnp.ids_out.extend(cmp);
            r.status = DriverStatus::Success;
        }
        QueryIdType::DeviceId => {
            let (hw, _, _) = hwids_for(ext);
            if let Some(primary) = hw.first() {
                pnp.ids_out.push(primary.clone());
                r.status = DriverStatus::Success;
            } else {
                r.status = DriverStatus::NoSuchDevice;
            }
        }
        QueryIdType::InstanceId => {
            pnp.ids_out.push(instance_path_for(ext));
            r.status = DriverStatus::Success;
        }
    }
    DriverStatus::Success
}

extern "win64" fn pci_pdo_query_resources(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let ext: &PciPdoExt = unsafe { &*(dev.dev_ext.as_ptr() as *const PciPdoExt) };
    let mut r = req.write();
    let pnp = r.pnp.as_mut().unwrap();
    pnp.blob_out = build_resources_blob(ext);
    r.status = DriverStatus::Success;
    DriverStatus::Success
}

extern "win64" fn pci_pdo_start(
    _dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let mut r = req.write();
    if r.status == DriverStatus::Pending {
        r.status = DriverStatus::Success;
    }
    DriverStatus::Success
}

extern "win64" fn pci_pdo_query_devrels(
    _dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    req.write().status = DriverStatus::Success;
    DriverStatus::Success
}
