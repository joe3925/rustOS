use core::{
    alloc::{GlobalAlloc, Layout},
    arch::asm,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

use acpi::{AcpiTable, AcpiTables};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    task::Wake,
    vec::Vec,
};
use kernel_types::{
    async_ffi::{FfiFuture, FutureExt},
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    fs::OpenFlags,
    pnp::{DeviceIds, DeviceRelationType},
    request::{Request, RequestFuture},
    status::{Data, DriverStatus, FileStatus, RegError},
    ClassAddCallback, EvtDriverDeviceAdd, EvtDriverUnload,
};
use spin::{Mutex, Once, RwLock};
use x86_64::instructions::hlt;

use crate::{
    console::CONSOLE,
    drivers::{
        drive::vfs::Vfs,
        driver_install::DriverError,
        interrupt_index::wait_millis,
        pnp::{
            manager::{PnpManager, PNP_MANAGER},
            request::{DpcFn, IoTarget},
        },
        ACPI::{ACPIImpl, ACPI, ACPI_TABLES},
    },
    file_system::{
        file::{switch_to_vfs, File},
        file_provider::install_file_provider,
    },
    memory::{allocator::ALLOCATOR, paging::constants::KERNEL_STACK_SIZE},
    registry::{
        reg::{self, rebind_and_persist_after_provider_switch},
        RegDelta,
    },
    scheduling::{
        executer::{BLOCKING_POOL, RUNTIME_POOL},
        scheduler::{TaskError, SCHEDULER},
        task::Task,
    },
    util::boot_info,
};

// TODO: block on needs to be removed from this file
#[unsafe(no_mangle)]
pub extern "win64" fn create_kernel_task(
    entry: extern "win64" fn(usize),
    ctx: usize,
    name: String,
) -> u64 {
    let task = Task::new_kernel_mode(entry, ctx, KERNEL_STACK_SIZE, name, 0);
    SCHEDULER.add_task(task)
}

pub unsafe extern "win64" fn sleep_self() {
    SCHEDULER.sleep();
}

pub unsafe extern "win64" fn sleep_self_and_yield() {
    SCHEDULER.sleep_and_yield();
}

pub extern "win64" fn wake_task(id: u64) {
    if let Some(task) = SCHEDULER.get_task_by_id(id) {
        SCHEDULER.wake_task(&task);
    }
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
pub extern "win64" fn print(str: &str) {
    CONSOLE.lock().print(str.as_bytes());
}

#[unsafe(no_mangle)]
pub extern "win64" fn wait_ms(ms: u64) {
    wait_millis(ms);
}

#[no_mangle]
pub extern "win64" fn file_open(
    path: &str,
    flags: &[OpenFlags],
) -> FfiFuture<Result<File, FileStatus>> {
    let path = path.to_string();
    let flags_vec: Vec<OpenFlags> = flags.to_vec();

    async move { File::open(path.as_str(), &flags_vec).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn fs_list_dir(path: &str) -> FfiFuture<Result<Vec<String>, FileStatus>> {
    let path = path.to_string();

    async move { File::list_dir(path.as_str()).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn fs_remove_dir(path: &str) -> FfiFuture<Result<(), FileStatus>> {
    let path = path.to_string();

    async move { File::remove_dir(path).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn fs_make_dir(path: &str) -> FfiFuture<Result<(), FileStatus>> {
    let path = path.to_string();

    async move { File::make_dir(path).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn reg_get_value(key_path: &str, name: &str) -> FfiFuture<Option<Data>> {
    let key_path = key_path.to_string();
    let name = name.to_string();

    async move { reg::get_value(key_path.as_str(), name.as_str()).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn reg_set_value(
    key_path: &str,
    name: &str,
    data: Data,
) -> FfiFuture<Result<(), RegError>> {
    let key_path = key_path.to_string();
    let name = name.to_string();

    async move { reg::set_value(key_path.as_str(), name.as_str(), data).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn reg_create_key(path: &str) -> FfiFuture<Result<(), RegError>> {
    let path = path.to_string();

    async move { reg::create_key(path).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn reg_delete_key(path: &str) -> FfiFuture<Result<bool, RegError>> {
    let path = path.to_string();

    async move { reg::delete_key(path.as_str()).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn reg_delete_value(
    key_path: &str,
    name: &str,
) -> FfiFuture<Result<bool, RegError>> {
    let key_path = key_path.to_string();
    let name = name.to_string();

    async move { reg::delete_value(key_path.as_str(), name.as_str()).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn reg_list_keys(base_path: &str) -> FfiFuture<Result<Vec<String>, RegError>> {
    let base_path = base_path.to_string();

    async move { reg::list_keys(base_path.as_str()).await }.into_ffi()
}

#[no_mangle]
pub extern "win64" fn reg_list_values(base_path: &str) -> FfiFuture<Result<Vec<String>, RegError>> {
    let base_path = base_path.to_string();

    async move { reg::list_values(base_path.as_str()).await }.into_ffi()
}

pub extern "win64" fn get_acpi_tables() -> Arc<AcpiTables<ACPIImpl>> {
    ACPI_TABLES.get_tables()
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

pub extern "win64" fn pnp_bind_and_start(dn: &Arc<DevNode>) -> FfiFuture<Result<(), DriverError>> {
    let dn = dn.clone();

    async move { PNP_MANAGER.bind_and_start(&dn).await }.into_ffi()
}

pub extern "win64" fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget> {
    PNP_MANAGER.get_device_target(instance_path)
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_forward_request_to_next_lower(
    from: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> Result<RequestFuture, DriverStatus> {
    PNP_MANAGER.send_request_to_next_lower(from, req)
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_send_request(
    target: &IoTarget,
    req: Arc<RwLock<Request>>,
) -> Result<RequestFuture, DriverStatus> {
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
) -> Result<RequestFuture, DriverStatus> {
    let mgr = &*PNP_MANAGER;
    let Some(dn) = device.dev_node.get() else {
        return Err(DriverStatus::NoSuchDevice);
    };
    mgr.invalidate_device_relations_for_node(&dn.upgrade().unwrap(), relation)
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
) -> Result<RequestFuture, DriverStatus> {
    PNP_MANAGER.send_request_via_symlink(link_path, req)
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_ioctl_via_symlink(
    link_path: String,
    control_code: u32,
    req: Arc<RwLock<Request>>,
) -> Result<RequestFuture, DriverStatus> {
    PNP_MANAGER.ioctl_via_symlink(link_path, control_code, req)
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_load_service(name: String) -> FfiFuture<Option<Arc<DriverObject>>> {
    async move { PNP_MANAGER.load_service(&name).await }.into_ffi()
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

#[no_mangle]
pub extern "win64" fn pnp_create_devnode_over_pdo_with_function(
    parent_dn: &Arc<DevNode>,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
    function_service: &str,
    function_fdo: &Arc<DeviceObject>,
    init_pdo: DeviceInit,
) -> FfiFuture<Result<(Arc<DevNode>, Arc<DeviceObject>), DriverError>> {
    let parent_dn = parent_dn.clone();
    let instance_path = instance_path;
    let ids = ids;
    let class = class;
    let function_service = function_service.to_string();
    let function_fdo = function_fdo.clone();
    let init_pdo = init_pdo;

    async move {
        PNP_MANAGER
            .create_devnode_over_pdo_with_function(
                parent_dn,
                instance_path,
                ids,
                class,
                function_service.as_str(),
                function_fdo,
                init_pdo,
            )
            .await
    }
    .into_ffi()
}

#[unsafe(no_mangle)]
pub extern "win64" fn pnp_send_request_to_next_upper(
    from: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> Result<RequestFuture, DriverStatus> {
    PNP_MANAGER.send_request_to_next_upper(from, req)
}

#[no_mangle]
pub extern "win64" fn pnp_send_request_to_stack_top(
    dev_node_weak: &alloc::sync::Weak<DevNode>,
    req: Arc<RwLock<Request>>,
) -> Result<RequestFuture, DriverStatus> {
    PNP_MANAGER.send_request_to_stack_top(dev_node_weak, req)
}

#[no_mangle]
pub unsafe extern "win64" fn submit_runtime_internal(
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    RUNTIME_POOL.submit(trampoline, ctx);
}

static BLOCKING_INIT: Once = Once::new();

#[no_mangle]
pub unsafe extern "win64" fn submit_blocking_internal(
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    BLOCKING_INIT.call_once(|| {
        BLOCKING_POOL.enable_dynamic(16);
    });

    BLOCKING_POOL.submit(trampoline, ctx);
}

#[no_mangle]
pub unsafe extern "win64" fn task_yield() {
    unsafe { asm!("int 0x80") };
}

pub unsafe extern "win64" fn switch_to_vfs_async() -> FfiFuture<Result<(), RegError>> {
    switch_to_vfs().into_ffi()
}
