use alloc::string::String;
use alloc::sync::{Arc, Weak};
use kernel_sys::KernelAcpiHandler;

use kernel_types::device::{DevNode, DeviceInit, DeviceObject, DriverObject};
use kernel_types::io::IoTarget;
use kernel_types::request::{RequestHandle, RequestHandleResult};
use kernel_types::status::{DriverError, DriverStatus};
use kernel_types::{ClassAddCallback, EvtDriverDeviceAdd, EvtDriverUnload};

pub use kernel_types::pnp::*;

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

pub fn pnp_create_symlink(link: String, target: String) -> DriverStatus {
    unsafe { kernel_sys::pnp_create_symlink(link, target) }
}

pub fn pnp_replace_symlink(link: String, target: String) -> DriverStatus {
    unsafe { kernel_sys::pnp_replace_symlink(link, target) }
}

pub fn pnp_create_device_symlink_top(instance_path: String, link_path: String) -> DriverStatus {
    unsafe { kernel_sys::pnp_create_device_symlink_top(instance_path, link_path) }
}

pub fn pnp_remove_symlink(link_path: String) -> DriverStatus {
    unsafe { kernel_sys::pnp_remove_symlink(link_path) }
}

pub fn pnp_add_class_listener(
    class: String,
    callback: ClassAddCallback,
    dev_obj: Arc<DeviceObject>,
) {
    unsafe { kernel_sys::pnp_add_class_listener(class, callback, dev_obj) }
}

pub fn pnp_complete_request<'a>(req: RequestHandle<'a>) -> (RequestHandle<'a>, DriverStatus) {
    let res = unsafe { kernel_sys::pnp_complete_request(req) };
    let status = res.handle.status();
    (res.handle, status)
}

pub async fn pnp_send_request<'a>(
    target: IoTarget,
    req: RequestHandle<'a>,
) -> (RequestHandle<'a>, DriverStatus) {
    let res = unsafe { kernel_sys::pnp_send_request(target, req).await };
    let status = res.handle.status();
    (res.handle, status)
}

pub async fn pnp_forward_request_to_next_lower<'a>(
    from: Arc<DeviceObject>,
    req: RequestHandle<'a>,
) -> (RequestHandle<'a>, DriverStatus) {
    let res = unsafe { kernel_sys::pnp_forward_request_to_next_lower(from, req).await };
    let status = res.handle.status();
    (res.handle, status)
}

pub async fn pnp_forward_request_to_next_upper<'a>(
    from: Arc<DeviceObject>,
    req: RequestHandle<'a>,
) -> (RequestHandle<'a>, DriverStatus) {
    let res = unsafe { kernel_sys::pnp_forward_request_to_next_upper(from, req).await };
    let status = res.handle.status();
    (res.handle, status)
}

pub async fn pnp_send_request_via_symlink<'a>(
    link_path: String,
    req: RequestHandle<'a>,
) -> (RequestHandle<'a>, DriverStatus) {
    let res = unsafe { kernel_sys::pnp_send_request_via_symlink(link_path, req).await };
    let status = res.handle.status();
    (res.handle, status)
}

pub async fn pnp_ioctl_via_symlink<'a>(
    link_path: String,
    control_code: u32,
    req: RequestHandle<'a>,
) -> (RequestHandle<'a>, DriverStatus) {
    let res = unsafe { kernel_sys::pnp_ioctl_via_symlink(link_path, control_code, req).await };
    let status = res.handle.status();
    (res.handle, status)
}

pub async fn pnp_send_request_to_stack_top<'a>(
    dev_node_weak: Weak<DevNode>,
    req: RequestHandle<'a>,
) -> (RequestHandle<'a>, DriverStatus) {
    let res = unsafe { kernel_sys::pnp_send_request_to_stack_top(dev_node_weak, req).await };
    let status = res.handle.status();
    (res.handle, status)
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
