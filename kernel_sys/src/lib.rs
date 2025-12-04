#![no_std]
#![allow(improper_ctypes, improper_ctypes_definitions)]
extern crate alloc;

use acpi::PhysicalMapping;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;
use core::ptr::NonNull;
use kernel_types::async_ffi::FfiFuture;
use spin::RwLock;

use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::structures::paging::PageTableFlags;

use kernel_types::device::{DevNode, DeviceInit, DeviceObject, DriverObject};
use kernel_types::fs::{File, OpenFlags};
use kernel_types::io::IoTarget;
use kernel_types::pnp::{DeviceIds, DeviceRelationType};
use kernel_types::request::{Request, RequestFuture};
use kernel_types::status::{
    Data, DriverError, DriverStatus, FileStatus, PageMapError, RegError, TaskError,
};
use kernel_types::{ClassAddCallback, DpcFn, EvtDriverDeviceAdd, EvtDriverUnload};

#[link(name = "KRNL")]
unsafe extern "win64" {
    // =========================================================================
    // Memory / Core
    // =========================================================================
    pub fn kernel_alloc(layout: Layout) -> *mut u8;
    pub fn kernel_free(ptr: *mut u8, layout: Layout);
    pub fn print(s: &str);
    pub fn panic_common(mod_name: &'static str, info: &PanicInfo) -> !;
    pub fn random_number() -> u64;
    pub fn wait_ms(ms: u64);
    pub fn get_rsdp() -> u64;

    // =========================================================================
    // Tasking
    // =========================================================================
    pub fn create_kernel_task(entry: extern "win64" fn(usize), ctx: usize, name: String) -> u64;
    pub fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError>;
    pub fn pnp_queue_dpc(func: DpcFn, arg: usize);
    pub fn submit_runtime_internal(trampoline: extern "win64" fn(usize), ctx: usize);
    pub fn submit_blocking_internal(trampoline: extern "win64" fn(usize), ctx: usize);
    pub unsafe fn sleep_self();
    pub unsafe fn sleep_self_and_yield();
    pub unsafe fn wake_task(id: u64);

    // =========================================================================
    // Paging / VMM
    // =========================================================================
    pub fn allocate_auto_kernel_range_mapped(
        size: u64,
        flags: PageTableFlags,
    ) -> Result<VirtAddr, PageMapError>;
    pub fn allocate_kernel_range_mapped(
        base: u64,
        size: u64,
        flags: PageTableFlags,
    ) -> Result<VirtAddr, PageMapError>;
    pub fn deallocate_kernel_range(addr: VirtAddr, size: u64);
    pub fn unmap_range(virtual_addr: VirtAddr, size: u64);
    pub fn identity_map_page(frame_addr: PhysAddr, flags: PageTableFlags);
    pub fn map_mmio_region(mmio_base: PhysAddr, mmio_size: u64) -> Result<VirtAddr, PageMapError>;
    pub fn virt_to_phys(addr: VirtAddr) -> Option<PhysAddr>;

    // =========================================================================
    // Registry (async FFI)
    // =========================================================================
    pub fn reg_get_value(key_path: &str, name: &str) -> FfiFuture<Option<Data>>;
    pub fn reg_set_value(key_path: &str, name: &str, data: Data)
    -> FfiFuture<Result<(), RegError>>;
    pub fn reg_create_key(path: &str) -> FfiFuture<Result<(), RegError>>;
    pub fn reg_delete_key(path: &str) -> FfiFuture<Result<bool, RegError>>;
    pub fn reg_delete_value(key_path: &str, name: &str) -> FfiFuture<Result<bool, RegError>>;
    pub fn reg_list_keys(base_path: &str) -> FfiFuture<Result<Vec<String>, RegError>>;
    pub fn reg_list_values(base_path: &str) -> FfiFuture<Result<Vec<String>, RegError>>;
    pub fn switch_to_vfs_async() -> FfiFuture<Result<(), RegError>>;

    // =========================================================================
    // File System (async FFI)
    // =========================================================================
    pub fn file_open(path: &str, flags: &[OpenFlags]) -> FfiFuture<Result<File, FileStatus>>;
    pub fn fs_list_dir(path: &str) -> FfiFuture<Result<Vec<String>, FileStatus>>;
    pub fn fs_remove_dir(path: &str) -> FfiFuture<Result<(), FileStatus>>;
    pub fn fs_make_dir(path: &str) -> FfiFuture<Result<(), FileStatus>>;
    pub fn file_read(file: &File) -> FfiFuture<Result<Vec<u8>, FileStatus>>;
    pub fn file_write(file: &mut File, data: &[u8]) -> FfiFuture<Result<(), FileStatus>>;
    pub fn file_delete(file: &mut File) -> FfiFuture<Result<(), FileStatus>>;

    // =========================================================================
    // PnP / Device Management
    // =========================================================================
    pub fn driver_get_name(driver: &Arc<DriverObject>) -> String;
    pub fn driver_get_flags(driver: &Arc<DriverObject>) -> u32;
    pub fn driver_set_evt_device_add(driver: &Arc<DriverObject>, callback: EvtDriverDeviceAdd);
    pub fn driver_set_evt_driver_unload(driver: &Arc<DriverObject>, callback: EvtDriverUnload);

    pub fn pnp_create_pdo(
        parent_devnode: &Arc<DevNode>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
    ) -> (Arc<DevNode>, Arc<DeviceObject>);

    pub fn pnp_create_child_devnode_and_pdo_with_init(
        parent: &Arc<DevNode>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        init: DeviceInit,
    ) -> (Arc<DevNode>, Arc<DeviceObject>);

    pub fn pnp_bind_and_start(dn: &Arc<DevNode>) -> FfiFuture<Result<(), DriverError>>;
    pub fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget>;

    pub fn pnp_forward_request_to_next_lower(
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus>;

    pub fn pnp_send_request(
        target: &IoTarget,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus>;

    pub fn pnp_complete_request(req: &Arc<RwLock<Request>>);

    pub fn pnp_create_symlink(link_path: String, target_path: String) -> DriverStatus;
    pub fn pnp_replace_symlink(link_path: String, target_path: String) -> DriverStatus;
    pub fn pnp_create_device_symlink_top(instance_path: String, link_path: String) -> DriverStatus;
    pub fn pnp_remove_symlink(link_path: String) -> DriverStatus;

    pub fn pnp_send_request_via_symlink(
        link_path: String,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus>;

    pub fn pnp_ioctl_via_symlink(
        link_path: String,
        control_code: u32,
        request: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus>;

    pub fn pnp_load_service(name: String) -> FfiFuture<Option<Arc<DriverObject>>>;

    pub fn pnp_create_control_device_with_init(name: String, init: DeviceInit)
    -> Arc<DeviceObject>;

    pub fn pnp_create_control_device_and_link(
        name: String,
        init: DeviceInit,
        link_path: String,
    ) -> Arc<DeviceObject>;

    pub fn pnp_add_class_listener(
        class: String,
        callback: ClassAddCallback,
        dev_obj: Arc<DeviceObject>,
    );

    pub fn pnp_create_devnode_over_pdo_with_function(
        parent_dn: &Arc<DevNode>,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        function_service: &str,
        function_fdo: &Arc<DeviceObject>,
        init_pdo: DeviceInit,
    ) -> FfiFuture<Result<(Arc<DevNode>, Arc<DeviceObject>), DriverError>>;

    pub fn pnp_send_request_to_next_upper(
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus>;

    pub fn pnp_send_request_to_stack_top(
        dev_node_weak: &Weak<DevNode>,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus>;

    pub fn InvalidateDeviceRelations(
        device: &Arc<DeviceObject>,
        relation: DeviceRelationType,
    ) -> Result<RequestFuture, DriverStatus>;

    pub fn get_acpi_tables() -> Arc<acpi::AcpiTables<KernelAcpiHandler>>;
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct KernelAcpiHandler;

impl acpi::AcpiHandler for KernelAcpiHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        let virt_addr = unsafe {
            crate::map_mmio_region(PhysAddr::new(physical_address as u64), size as u64)
                .expect("failed to map io space for ACPI")
        };

        unsafe {
            PhysicalMapping::new(
                physical_address,
                NonNull::new(virt_addr.as_mut_ptr()).unwrap(),
                size,
                size,
                self.clone(),
            )
        }
    }

    fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>) {
        unsafe {
            crate::unmap_range(
                VirtAddr::new(region.virtual_start().as_ptr() as u64),
                region.region_length() as u64,
            )
        }
    }
}
