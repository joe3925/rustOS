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
    DevExt, PciPdoExt, PrepareHardwareCtx, build_resources_blob, header_type, hwids_for,
    instance_path_for, load_segments_from_parent, name_for, on_query_resources_complete,
    probe_function,
};

use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, PnpMinorFunction, Request,
    RequestType,
    alloc_api::{
        DeviceIds, DeviceInit,
        ffi::{
            driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
            pnp_forward_request_to_next_lower,
        },
    },
    println,
};

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
    dev_init.evt_pnp = Some(bus_pnp_dispatch);
    DriverStatus::Success
}
pub extern "win64" fn bus_pnp_dispatch(device: &Arc<DeviceObject>, req: &mut Request) {
    let Some(pnp) = req.pnp.as_mut() else {
        unsafe { pnp_forward_request_to_next_lower(device, req) };
        return;
    };

    match pnp.minor_function {
        PnpMinorFunction::StartDevice => {
            let pnp_payload = kernel_api::alloc_api::PnpRequest {
                minor_function: PnpMinorFunction::QueryResources,
                relation: kernel_api::DeviceRelationType::TargetDeviceRelation,
                id_type: kernel_api::QueryIdType::CompatibleIds,
                ids_out: Vec::new(),
                blob_out: Vec::new(),
            };

            let mut query_req = Request::new(RequestType::Pnp, Box::new([]));
            query_req.pnp = Some(pnp_payload);

            let original_req_box = Box::new(core::mem::replace(req, Request::empty()));

            let prep_ctx = Box::new(PrepareHardwareCtx {
                original_device: device.clone(),
                original_request: original_req_box,
            });
            let ctx_ptr = Box::into_raw(prep_ctx) as usize;

            query_req.set_completion(on_query_resources_complete, ctx_ptr);

            unsafe { pnp_forward_request_to_next_lower(device, &mut query_req) };
        }
        PnpMinorFunction::QueryDeviceRelations => {
            if pnp.relation == kernel_api::DeviceRelationType::BusRelations {
                enumerate_bus(device);
            }
            unsafe { pnp_forward_request_to_next_lower(device, req) };
        }
        _ => {
            unsafe { pnp_forward_request_to_next_lower(device, req) };
        }
    }
}
pub extern "win64" fn bus_driver_prepare_hardware(device: &Arc<DeviceObject>) -> DriverStatus {
    let ext_ptr = device.dev_ext.as_ptr() as *mut DevExt;
    let ext = load_segments_from_parent(device);
    unsafe {
        core::ptr::write(ext_ptr, ext);
    }

    let n = unsafe { (&*ext_ptr).segments.len() };
    if n == 0 {
        println!("[PCI] WARNING: no ECAM segments provided by parent");
    }
    DriverStatus::Success
}

pub extern "win64" fn enumerate_bus(device: &Arc<DeviceObject>) -> DriverStatus {
    let devnode = unsafe {
        (*(Arc::as_ptr(device) as *const DeviceObject))
            .dev_node
            .upgrade()
            .expect("[PCI] PDO missing DevNode")
    };

    let ext: &DevExt = unsafe { &*(device.dev_ext.as_ptr() as *const DevExt) };

    let mut found = 0usize;

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
                        found += 1;
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
                        found += 1;
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
    child_init.evt_pnp = Some(pci_pdo_pnp_dispatch);

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

#[unsafe(no_mangle)]
pub extern "win64" fn pci_pdo_pnp_dispatch(dev: &Arc<DeviceObject>, req: &mut kernel_api::Request) {
    use kernel_api::alloc_api::ffi::pnp_complete_request;
    use kernel_api::{DriverStatus, PnpMinorFunction, QueryIdType};

    let Some(pnp) = req.pnp.as_mut() else {
        req.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(req) };
        return;
    };

    let ext: &PciPdoExt = unsafe { &*(dev.dev_ext.as_ptr() as *const PciPdoExt) };

    match pnp.minor_function {
        PnpMinorFunction::QueryId => {
            match pnp.id_type {
                QueryIdType::HardwareIds => {
                    let (hw, _cmp, _) = hwids_for(ext);
                    pnp.ids_out.extend(hw);
                    req.status = DriverStatus::Success;
                }
                QueryIdType::CompatibleIds => {
                    let (_hw, cmp, _) = hwids_for(ext);
                    pnp.ids_out.extend(cmp);
                    req.status = DriverStatus::Success;
                }
                QueryIdType::DeviceId => {
                    let (hw, _, _) = hwids_for(ext);
                    if let Some(primary) = hw.first() {
                        pnp.ids_out.push(primary.clone());
                        req.status = DriverStatus::Success;
                    } else {
                        req.status = DriverStatus::NoSuchDevice;
                    }
                }
                QueryIdType::InstanceId => {
                    pnp.ids_out.push(instance_path_for(ext));
                    req.status = DriverStatus::Success;
                }
            }
            unsafe { pnp_complete_request(req) };
        }

        PnpMinorFunction::QueryResources => {
            pnp.blob_out = build_resources_blob(ext);
            req.status = DriverStatus::Success;
            unsafe { pnp_complete_request(req) };
        }

        PnpMinorFunction::StartDevice => {
            req.status = DriverStatus::Success;
            unsafe { pnp_complete_request(req) };
        }

        _ => {
            req.status = DriverStatus::NoSuchDevice;
            unsafe { pnp_complete_request(req) };
        }
    }
}
