use core::alloc::{GlobalAlloc, Layout};

use acpi::{AcpiTable, AcpiTables};
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use crate::{
    console::CONSOLE,
    drivers::{
        driver_install::DriverError,
        interrupt_index::wait_millis,
        pnp::{
            driver_object::{DeviceInit, DeviceObject, DriverObject, DriverStatus, Request},
            pnp_manager::{DevNode, DeviceIds, DpcFn, IoTarget, PNP_MANAGER},
        },
        ACPI::{ACPIImpl, ACPI, ACPI_TABLES},
    },
    file_system::file::{File, FileStatus, OpenFlags},
    memory::{allocator::ALLOCATOR, paging::constants::KERNEL_STACK_SIZE},
    scheduling::{
        scheduler::{TaskError, SCHEDULER},
        task::Task,
    },
};

pub extern "win64" fn create_kernel_task(entry: usize, name: String) -> u64 {
    let task = Task::new_kernel_mode(entry, KERNEL_STACK_SIZE, name, 0);
    SCHEDULER.lock().add_task(task)
}
pub extern "win64" fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError> {
    SCHEDULER.lock().delete_task(id)
}
pub extern "win64" fn kernel_alloc(layout: Layout) -> *mut u8 {
    unsafe { GlobalAlloc::alloc(&ALLOCATOR, layout) }
}
pub extern "win64" fn kernel_free(ptr: *mut u8, layout: Layout) {
    unsafe {
        GlobalAlloc::dealloc(&ALLOCATOR, ptr, layout);
    };
}
pub extern "win64" fn print(str: &[u8]) {
    CONSOLE.lock().print(str);
}
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
pub extern "win64" fn get_acpi_tables() -> Arc<AcpiTables<ACPIImpl>> {
    return ACPI_TABLES.get_tables();
}
pub extern "win64" fn pnp_create_pdo(
    parent_devnode: &Arc<DevNode>,
    bus_driver: &Arc<DriverObject>,
    name: String,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
) -> (Arc<DevNode>, Arc<DeviceObject>) {
    PNP_MANAGER.create_child_devnode_and_pdo(
        parent_devnode,
        bus_driver,
        name,
        instance_path,
        ids,
        class,
    )
}

pub extern "win64" fn pnp_bind_and_start(dn: &Arc<DevNode>) -> Result<(), DriverError> {
    PNP_MANAGER.bind_and_start(dn)
}

pub extern "win64" fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget> {
    PNP_MANAGER.get_device_target(instance_path)
}

pub extern "win64" fn pnp_forward_request_to_next_lower(
    from: &Arc<DeviceObject>,
    req: &mut Request,
) -> DriverStatus {
    PNP_MANAGER.send_request_to_next_lower(from, req)
}

pub extern "win64" fn pnp_send_request(target: &IoTarget, req: &mut Request) -> DriverStatus {
    PNP_MANAGER.send_request(target, req)
}

pub extern "win64" fn pnp_complete_request(req: &mut Request) {
    PNP_MANAGER.complete_request(req);
}

pub extern "win64" fn pnp_queue_dpc(func: DpcFn, arg: usize) {
    PNP_MANAGER.queue_dpc(func, arg)
}
