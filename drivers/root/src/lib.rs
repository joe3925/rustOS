#![no_std]
#![no_main]

extern crate alloc;

use alloc::{string::ToString, sync::Arc, vec::Vec};
#[cfg(not(test))]
use core::panic::PanicInfo;
use kernel_api::{
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    kernel_types::pnp::DeviceIds,
    pnp::{
        DeviceRelationType, DriverStep, PnpMinorFunction, PnpVtable, driver_set_evt_device_add,
        get_device_tree_blob, get_rsdp, pnp_create_child_devnode_and_pdo_with_init,
    },
    request::{Pnp, RequestHandle},
    request_handler,
    status::DriverStatus,
};

static MOD_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel_api::util::panic_common(MOD_NAME, info)
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, root_device_add);
    DriverStatus::Success
}

pub extern "C" fn root_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let pnp = PnpVtable::new();
    pnp.set(PnpMinorFunction::StartDevice, root_start);
    pnp.set(PnpMinorFunction::QueryDeviceRelations, root_query_devrels);
    dev_init.pnp_vtable = Some(pnp);
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn root_start<'req, 'data, 'b>(
    _device: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn root_query_devrels<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    if req.read().body.request.relation != DeviceRelationType::BusRelations {
        return DriverStep::Continue;
    }

    let Some(root_dn) = device.dev_node.get().and_then(|dn| dn.upgrade()) else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    if get_rsdp().is_some() {
        ensure_acpi_node(&root_dn);
    }

    if get_device_tree_blob().is_some() {
        ensure_device_tree_node(&root_dn);
    }

    DriverStep::complete(DriverStatus::Success)
}

fn child_exists(parent: &Arc<DevNode>, instance_path: &str) -> bool {
    parent
        .children
        .read()
        .iter()
        .any(|child| child.instance_path == instance_path)
}

fn ensure_acpi_node(parent: &Arc<DevNode>) {
    const INSTANCE: &str = "ACPI\\ROOT\\0";
    if child_exists(parent, INSTANCE) {
        return;
    }

    let ids = DeviceIds {
        hardware: alloc::vec!["ACPI\\ROOT".to_string()],
        compatible: Vec::new(),
    };

    let _ = pnp_create_child_devnode_and_pdo_with_init(
        parent,
        "ACPI".to_string(),
        INSTANCE.to_string(),
        ids,
        None,
        DeviceInit::with_pnp(Some(PnpVtable::new())),
    );
}

fn ensure_device_tree_node(parent: &Arc<DevNode>) {
    const INSTANCE: &str = "FDT\\ROOT\\0";
    if child_exists(parent, INSTANCE) {
        return;
    }

    let ids = DeviceIds {
        hardware: alloc::vec!["FDT\\ROOT".to_string()],
        compatible: alloc::vec!["OF\\root".to_string()],
    };

    let _ = pnp_create_child_devnode_and_pdo_with_init(
        parent,
        "devicetree".to_string(),
        INSTANCE.to_string(),
        ids,
        None,
        DeviceInit::with_pnp(Some(PnpVtable::new())),
    );
}
