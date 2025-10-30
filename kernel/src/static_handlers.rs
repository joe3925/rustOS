use core::alloc::{GlobalAlloc, Layout};

use acpi::{AcpiTable, AcpiTables};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use spin::{Mutex, RwLock};

use crate::{
    console::CONSOLE,
    drivers::{
        drive::vfs::Vfs,
        driver_install::DriverError,
        interrupt_index::wait_millis,
        pnp::{
            device::{DevNode, DeviceIds},
            driver_object::{
                ClassAddCallback, DeviceInit, DeviceObject, DeviceRelationType, DriverObject,
                DriverStatus, EvtDriverDeviceAdd, EvtDriverUnload, Request,
            },
            manager::PNP_MANAGER,
            request::{DpcFn, IoTarget},
        },
        ACPI::{ACPIImpl, ACPI, ACPI_TABLES},
    },
    file_system::{
        file::{File, FileStatus, OpenFlags},
        file_provider::install_file_provider,
    },
    memory::{allocator::ALLOCATOR, paging::constants::KERNEL_STACK_SIZE},
    registry::{
        reg::{self, rebind_and_persist_after_provider_switch},
        Data, RegDelta, RegError,
    },
    scheduling::{
        scheduler::{TaskError, SCHEDULER},
        task::Task,
    },
    util::boot_info,
};
#[unsafe(no_mangle)]

pub extern "win64" fn create_kernel_task(entry: usize, name: String) -> u64 {
    let task = Task::new_kernel_mode(entry, KERNEL_STACK_SIZE, name, 0);
    SCHEDULER.add_task(task)
}
#[unsafe(no_mangle)]

pub extern "win64" fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError> {
    SCHEDULER.delete_task(id)
}
#[unsafe(no_mangle)]

pub extern "win64" fn kernel_alloc(layout: Layout) -> *mut u8 {
    unsafe { GlobalAlloc::alloc(&ALLOCATOR, layout) }
}
#[unsafe(no_mangle)]

pub extern "win64" fn kernel_free(ptr: *mut u8, layout: Layout) {
    unsafe {
        GlobalAlloc::dealloc(&ALLOCATOR, ptr, layout);
    };
}
#[unsafe(no_mangle)]

pub extern "win64" fn print(str: &[u8]) {
    CONSOLE.lock().print(str);
}
#[unsafe(no_mangle)]

pub extern "win64" fn wait_ms(ms: u64) {
    wait_millis(ms);
}
#[no_mangle]
pub extern "win64" fn file_open(path: &str, flags: &[OpenFlags]) -> Result<File, FileStatus> {
    File::open(path, flags)
}

#[no_mangle]
pub extern "win64" fn fs_list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
    File::list_dir(path)
}

#[no_mangle]
pub extern "win64" fn fs_remove_dir(path: &str) -> Result<(), FileStatus> {
    File::remove_dir(path.to_string())
}

#[no_mangle]
pub extern "win64" fn fs_make_dir(path: &str) -> Result<(), FileStatus> {
    File::make_dir(path.to_string())
}

#[no_mangle]
pub extern "win64" fn file_read(file: &File) -> Result<Vec<u8>, FileStatus> {
    file.read()
}

#[no_mangle]
pub extern "win64" fn file_write(file: &mut File, data: &[u8]) -> Result<(), FileStatus> {
    file.write(data)
}

#[no_mangle]
pub extern "win64" fn file_delete(file: &mut File) -> Result<(), FileStatus> {
    file.delete()
}
#[no_mangle]
pub extern "win64" fn reg_get_value(key_path: &str, name: &str) -> Option<Data> {
    reg::get_value(key_path, name)
}

#[no_mangle]
pub extern "win64" fn reg_set_value(
    key_path: &str,
    name: &str,
    data: Data,
) -> Result<(), RegError> {
    reg::set_value(key_path, name, data)
}

#[no_mangle]
pub extern "win64" fn reg_create_key(path: &str) -> Result<(), RegError> {
    reg::create_key(path)
}

#[no_mangle]
pub extern "win64" fn reg_delete_key(path: &str) -> Result<bool, RegError> {
    reg::delete_key(path)
}

#[no_mangle]
pub extern "win64" fn reg_delete_value(key_path: &str, name: &str) -> Result<bool, RegError> {
    reg::delete_value(key_path, name)
}

#[no_mangle]
pub extern "win64" fn reg_list_keys(base_path: &str) -> Result<Vec<String>, RegError> {
    reg::list_keys(base_path)
}

#[no_mangle]
pub extern "win64" fn reg_list_values(base_path: &str) -> Result<Vec<String>, RegError> {
    reg::list_values(base_path)
}
pub extern "win64" fn get_acpi_tables() -> Arc<AcpiTables<ACPIImpl>> {
    return ACPI_TABLES.get_tables();
}
pub extern "win64" fn pnp_create_pdo(
    parent_devnode: &Arc<DevNode>,
    name: String,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
) -> (Arc<DevNode>, Arc<DeviceObject>) {
    PNP_MANAGER.create_child_devnode_and_pdo(parent_devnode, name, instance_path, ids, class)
}
pub extern "win64" fn pnp_bind_and_start(dn: &Arc<DevNode>) -> Result<(), DriverError> {
    PNP_MANAGER.bind_and_start(dn)
}

pub extern "win64" fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget> {
    PNP_MANAGER.get_device_target(instance_path)
}

pub extern "win64" fn pnp_forward_request_to_next_lower(
    from: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    PNP_MANAGER.send_request_to_next_lower(from, req)
}

pub extern "win64" fn pnp_send_request(
    target: &IoTarget,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    PNP_MANAGER.send_request(target, req)
}

pub extern "win64" fn pnp_complete_request(req: &Arc<RwLock<Request>>) {
    PNP_MANAGER.complete_request(req);
}

pub extern "win64" fn pnp_queue_dpc(func: DpcFn, arg: usize) {
    PNP_MANAGER.queue_dpc(func, arg)
}
pub extern "win64" fn driver_get_name(driver: &Arc<DriverObject>) -> String {
    driver.driver_name.clone()
}

pub extern "win64" fn driver_get_flags(driver: &Arc<DriverObject>) -> u32 {
    driver.flags
}

pub extern "win64" fn driver_set_evt_device_add(
    driver: &Arc<DriverObject>,
    callback: EvtDriverDeviceAdd,
) {
    let driver_mut = unsafe { &mut *(Arc::as_ptr(driver) as *mut DriverObject) };
    driver_mut.evt_device_add = Some(callback);
}

pub extern "win64" fn driver_set_evt_driver_unload(
    driver: &Arc<DriverObject>,
    callback: EvtDriverUnload,
) {
    let driver_mut = unsafe { &mut *(Arc::as_ptr(driver) as *mut DriverObject) };
    driver_mut.evt_driver_unload = Some(callback);
}
pub extern "win64" fn get_rsdp() -> u64 {
    boot_info().rsdp_addr.into_option().unwrap()
}
pub extern "win64" fn pnp_create_child_devnode_and_pdo_with_init(
    parent: &Arc<DevNode>,
    name: String,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
    init: DeviceInit,
) -> (Arc<DevNode>, Arc<DeviceObject>) {
    PNP_MANAGER.create_child_devnode_and_pdo_with_init(
        parent,
        name,
        instance_path,
        ids,
        class,
        init,
    )
}
#[no_mangle]
pub extern "win64" fn InvalidateDeviceRelations(
    device: &Arc<DeviceObject>,
    relation: DeviceRelationType,
) -> DriverStatus {
    let mgr = &*PNP_MANAGER;
    let Some(dn) = device.dev_node.upgrade() else {
        return DriverStatus::NoSuchDevice;
    };
    mgr.invalidate_device_relations_for_node(&dn, relation)
}
#[inline]
fn map_om_result(res: Result<(), crate::object_manager::OmError>) -> DriverStatus {
    use crate::object_manager::OmError as OE;
    match res {
        Ok(()) => DriverStatus::Success,
        Err(OE::InvalidPath) => DriverStatus::InvalidParameter,
        Err(OE::NotFound) => DriverStatus::NoSuchDevice,
        Err(OE::AlreadyExists) => DriverStatus::Unsuccessful,
        Err(
            OE::NotDirectory | OE::IsDirectory | OE::IsSymlink | OE::Unsupported | OE::LoopDetected,
        ) => DriverStatus::Unsuccessful,
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_create_symlink(link_path: String, target_path: String) -> DriverStatus {
    map_om_result(PNP_MANAGER.create_symlink(link_path, target_path))
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_replace_symlink(link_path: String, target_path: String) -> DriverStatus {
    map_om_result(PNP_MANAGER.replace_symlink(link_path, target_path))
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_create_device_symlink_top(
    instance_path: String,
    link_path: String,
) -> DriverStatus {
    map_om_result(PNP_MANAGER.create_device_symlink_top(instance_path, link_path))
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_remove_symlink(link_path: String) -> DriverStatus {
    match PNP_MANAGER.remove_symlink(link_path) {
        Ok(()) => DriverStatus::Success,
        Err(_) => DriverStatus::NoSuchDevice,
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_send_request_via_symlink(
    link_path: String,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    PNP_MANAGER.send_request_via_symlink(link_path, req)
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_ioctl_via_symlink(
    link_path: String,
    control_code: u32,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    PNP_MANAGER.ioctl_via_symlink(link_path, control_code, req)
}
#[unsafe(no_mangle)]
pub extern "win64" fn pnp_load_service(name: String) -> Option<Arc<DriverObject>> {
    PNP_MANAGER.load_service(&name)
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_create_control_device_with_init(
    name: String,
    init: DeviceInit,
) -> Arc<DeviceObject> {
    let (dev, _) = PNP_MANAGER.create_control_device_with_init(name, init);
    dev
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_create_control_device_and_link(
    name: String,
    init: DeviceInit,
    link_path: String,
) -> Arc<DeviceObject> {
    PNP_MANAGER.create_control_device_and_link(name, init, link_path)
}
#[unsafe(no_mangle)]
pub extern "win64" fn pnp_add_class_listener(
    class: String,
    callback: ClassAddCallback,
    dev_obj: Arc<DeviceObject>,
) {
    PNP_MANAGER.add_class_listener(class, dev_obj.clone(), callback);
}
#[unsafe(no_mangle)]
pub extern "win64" fn pnp_wait_for_request(req: &Arc<RwLock<Request>>) {
    loop {
        if let Some(r) = req.try_read() {
            if r.completed {
                return;
            }
        }
        let _ = PNP_MANAGER.pump_queue_once();
        core::hint::spin_loop();
    }
}
#[no_mangle]
pub extern "win64" fn pnp_create_devnode_over_pdo_with_function(
    parent_dn: &Arc<DevNode>,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
    function_service: &str,
    function_fdo: &Arc<DeviceObject>,
    init_pdo: DeviceInit,
) -> Result<(Arc<DevNode>, Arc<DeviceObject>), DriverError> {
    PNP_MANAGER.create_devnode_over_pdo_with_function(
        parent_dn.clone(),
        instance_path,
        ids,
        class,
        function_service,
        function_fdo.clone(),
        init_pdo,
    )
}
