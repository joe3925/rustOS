use alloc::string::String;
use alloc::sync::Arc;
use kernel_sys::KernelAcpiHandler;

use kernel_types::device::{DevNode, DeviceInit, DeviceObject, DriverObject};
use kernel_types::fdt::FdtHeader;
use kernel_types::io::IoTarget;
use kernel_types::status::{DriverError, DriverStatus};
use kernel_types::{ClassAddCallback, EvtDriverDeviceAdd, EvtDriverUnload};

pub use kernel_types::pnp::*;

pub mod io {
    use alloc::sync::{Arc, Weak};
    use kernel_routing::IoRequest;
    use kernel_types::device::{DevNode, DeviceObject};
    use kernel_types::io::IoTarget;
    use kernel_types::status::DriverStatus;

    pub fn resolve_target(link_path: &str) -> Option<IoTarget> {
        kernel_routing::io::resolve_target(link_path)
    }

    pub async fn send_to_device<K: IoRequest>(target: IoTarget, req: &mut K) -> DriverStatus {
        kernel_routing::io::send_to_device(target, req).await
    }

    pub async fn send_down_stack<K: IoRequest>(target: IoTarget, req: &mut K) -> DriverStatus {
        kernel_routing::io::send_down_stack(target, req).await
    }

    pub async fn send_next_lower<K: IoRequest>(
        from: Arc<DeviceObject>,
        req: &mut K,
    ) -> DriverStatus {
        kernel_routing::io::send_next_lower(from, req).await
    }

    pub async fn send_to_stack_top<K: IoRequest>(
        dev_node_weak: Weak<DevNode>,
        req: &mut K,
    ) -> DriverStatus {
        kernel_routing::io::send_to_stack_top(dev_node_weak, req).await
    }
}

pub mod pnp {
    use alloc::sync::{Arc, Weak};
    use kernel_routing::PnpRequest;
    use kernel_types::device::{DevNode, DeviceObject};
    use kernel_types::io::IoTarget;
    use kernel_types::status::DriverStatus;

    pub fn resolve_target(link_path: &str) -> Option<IoTarget> {
        kernel_routing::pnp::resolve_target(link_path)
    }

    pub async fn send_to_device<K: PnpRequest>(target: IoTarget, req: &mut K) -> DriverStatus {
        kernel_routing::pnp::send_to_device(target, req).await
    }

    pub async fn send_down_stack<K: PnpRequest>(target: IoTarget, req: &mut K) -> DriverStatus {
        kernel_routing::pnp::send_down_stack(target, req).await
    }

    pub async fn send_next_lower<K: PnpRequest>(
        from: Arc<DeviceObject>,
        req: &mut K,
    ) -> DriverStatus {
        kernel_routing::pnp::send_next_lower(from, req).await
    }

    pub async fn send_to_stack_top<K: PnpRequest>(
        dev_node_weak: Weak<DevNode>,
        req: &mut K,
    ) -> DriverStatus {
        kernel_routing::pnp::send_to_stack_top(dev_node_weak, req).await
    }
}

pub fn create_pdo(
    parent: &Arc<DevNode>,
    name: String,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
) -> (Arc<DevNode>, Arc<DeviceObject>) {
    unsafe { kernel_sys::pnp_create_pdo(parent, name, instance_path, ids, class) }
}

pub fn pnp_create_child_devnode_and_pdo_with_init(
    parent: &Arc<DevNode>,
    name: String,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
    init: DeviceInit,
) -> (Arc<DevNode>, Arc<DeviceObject>) {
    unsafe {
        kernel_sys::pnp_create_child_devnode_and_pdo_with_init(
            parent,
            name,
            instance_path,
            ids,
            class,
            init,
        )
    }
}

pub async fn pnp_bind_and_start(dn: &Arc<DevNode>) -> Result<(), DriverError> {
    unsafe { kernel_sys::pnp_bind_and_start(dn).await }
}

pub fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget> {
    unsafe { kernel_sys::pnp_get_device_target(instance_path) }
}

pub fn pnp_create_control_device_with_init(name: String, init: DeviceInit) -> Arc<DeviceObject> {
    unsafe { kernel_sys::pnp_create_control_device_with_init(name, init) }
}

pub fn pnp_create_control_device_and_link(
    name: String,
    init: DeviceInit,
    link: String,
) -> Arc<DeviceObject> {
    unsafe { kernel_sys::pnp_create_control_device_and_link(name, init, link) }
}

pub fn pnp_create_symlink(
    link: String,
    target: String,
) -> Result<(), kernel_types::object_manager::OmError> {
    unsafe { kernel_sys::pnp_create_symlink(link, target) }
}

pub fn pnp_replace_symlink(
    link: String,
    target: String,
) -> Result<(), kernel_types::object_manager::OmError> {
    unsafe { kernel_sys::pnp_replace_symlink(link, target) }
}

pub fn pnp_create_device_symlink_top(
    instance_path: String,
    link_path: String,
) -> Result<(), kernel_types::object_manager::OmError> {
    unsafe { kernel_sys::pnp_create_device_symlink_top(instance_path, link_path) }
}

pub fn pnp_remove_symlink(link_path: String) -> DriverStatus {
    unsafe { kernel_sys::pnp_remove_symlink(link_path) }
}

pub fn pnp_add_class_listener(
    class: String,
    callback: ClassAddCallback,
    dev_obj: &Arc<DeviceObject>,
) {
    unsafe { kernel_sys::pnp_add_class_listener(class, callback, dev_obj) }
}

#[allow(clippy::too_many_arguments)]
pub async fn pnp_create_devnode_over_pdo_with_function(
    parent_dn: &Arc<DevNode>,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
    function_service: &str,
    function_fdo: &Arc<DeviceObject>,
    init_pdo: DeviceInit,
) -> Result<(Arc<DevNode>, Arc<DeviceObject>), DriverError> {
    unsafe {
        kernel_sys::pnp_create_devnode_over_pdo_with_function(
            parent_dn,
            instance_path,
            ids,
            class,
            function_service,
            function_fdo,
            init_pdo,
        )
        .await
    }
}

pub async fn pnp_load_service(name: String) -> Option<Arc<DriverObject>> {
    unsafe { kernel_sys::pnp_load_service(name).await }
}

pub fn driver_set_evt_device_add(driver: &Arc<DriverObject>, callback: EvtDriverDeviceAdd) {
    unsafe { kernel_sys::driver_set_evt_device_add(driver, callback) }
}

pub fn driver_set_evt_driver_unload(driver: &Arc<DriverObject>, callback: EvtDriverUnload) {
    unsafe { kernel_sys::driver_set_evt_driver_unload(driver, callback) }
}

pub fn get_acpi_tables() -> Arc<acpi::AcpiTables<KernelAcpiHandler>> {
    unsafe { kernel_sys::get_acpi_tables() }
}

pub fn get_rsdp() -> Option<u64> {
    match unsafe { kernel_sys::get_rsdp() } {
        0 => None,
        addr => Some(addr),
    }
}

pub fn get_device_tree_blob() -> Option<*const FdtHeader> {
    unsafe { kernel_sys::get_device_tree_blob() }
}
