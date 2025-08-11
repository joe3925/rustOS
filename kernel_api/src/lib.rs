#![no_std]

// Conditionally enable the `alloc` crate if the feature is set.
pub extern crate alloc;

// Re-export dependencies for drivers that use this API
pub use acpi;
pub use x86_64;

use core::alloc::{GlobalAlloc, Layout};
use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::structures::paging::PageTableFlags;

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        kernel_alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        kernel_free(ptr, layout)
    }
}

#[repr(C)]
pub struct DeviceObject {
    _private: [u8; 0],
}
#[repr(C)]
pub struct DevNode {
    _private: [u8; 0],
}
#[repr(C)]
pub struct DriverObject {
    _private: [u8; 0],
}
#[repr(C)]
pub struct IoTarget {
    _private: [u8; 0],
}
#[repr(C)]
pub struct Request {
    _private: [u8; 0],
}
#[repr(C)]
pub struct File {
    _private: [u8; 0],
}

// --- Enums ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DriverStatus {
    Success,
    Pending,
    IoError,
    NoSuchDevice,
    InvalidParameter,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DriverError {
    LoadError,
    BindError,
    StartError,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PageMapError {
    NoMemory,
    AlreadyMapped,
    HugePage,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TaskError {
    NotFound,
    InvalidId,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootType {
    Boot = 0,
    System = 1,
    Demand = 2,
    Disabled = 3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpMinorFunction {
    StartDevice,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileStatus {
    Success = 0x00,
    FileAlreadyExist = 0x01,
    PathNotFound = 0x02,
    UnknownFail = 0x03,
    NotFat = 0x04,
    DriveNotFound,
    IncompatibleFlags,
    CorruptFat,
    InternalError,
    BadPath,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFlags {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Create,
    CreateNew,
    Open,
}

// --- Function Pointer Type Aliases ---
pub type DpcFn = fn(usize);

//======================================================================================
// SECTION 3: `alloc` FEATURE-GATED DEFINITIONS AND APIs
//======================================================================================

pub mod alloc_api {
    use super::*;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    // --- `alloc`-dependent Data Structs ---
    #[derive(Debug, Clone)]
    pub struct DeviceIds {
        pub hardware: Vec<String>,
        pub compatible: Vec<String>,
    }

    #[repr(C)]
    #[derive(Debug)]
    pub struct DeviceInit {
        pub dev_ext_size: usize,
        pub io_read: Option<EvtIoRead>,
        pub io_write: Option<EvtIoWrite>,
        pub io_device_control: Option<EvtIoDeviceControl>,
        pub evt_device_prepare_hardware: Option<EvtDevicePrepareHardware>,
        pub evt_pnp: Option<fn(&Arc<DeviceObject>, &mut Request)>,
    }

    #[derive(Debug, Clone)]
    pub struct PnpRequest {
        pub minor_function: PnpMinorFunction,
    }
    #[derive(Debug, Clone)]
    pub struct KernelAcpiHandler;
    impl acpi::AcpiHandler for KernelAcpiHandler {
        unsafe fn map_physical_region<T>(
            &self,
            _: usize,
            _: usize,
        ) -> acpi::PhysicalMapping<Self, T> {
            panic!("Drivers cannot map physical regions via this API.");
        }
        fn unmap_physical_region<T>(_: &acpi::PhysicalMapping<Self, T>) {}
    }

    // --- `alloc`-dependent Function Pointers ---
    pub type EvtDriverDeviceAdd =
        extern "win64" fn(driver: &Arc<DriverObject>, init: &mut DeviceInit) -> DriverStatus;

    pub type EvtDriverUnload = extern "win64" fn(driver: &Arc<DriverObject>);

    pub type EvtIoRead = extern "win64" fn(&Arc<DeviceObject>, &mut Request, usize);
    pub type EvtIoWrite = extern "win64" fn(&Arc<DeviceObject>, &mut Request, usize);
    pub type EvtIoDeviceControl = extern "win64" fn(&Arc<DeviceObject>, &mut Request, u32);
    pub type EvtDevicePrepareHardware = extern "win64" fn(&Arc<DeviceObject>) -> DriverStatus;
    // --- Private FFI bindings for `alloc` functions ---
    mod ffi {
        use super::*;
        #[link(name = "KRNL")]
        #[no_mangle]
        extern "win64" {
            pub(super) fn create_kernel_task(entry: usize, name: String) -> u64;
            pub(super) fn file_open(path: &str, flags: &[OpenFlags]) -> Result<File, FileStatus>;
            pub(super) fn fs_list_dir(path: &str) -> Result<Vec<String>, FileStatus>;
            pub(super) fn fs_remove_dir(path: &str) -> Result<(), FileStatus>;
            pub(super) fn fs_make_dir(path: &str) -> Result<(), FileStatus>;
            pub(super) fn file_read(file: &File) -> Result<Vec<u8>, FileStatus>;
            pub(super) fn file_write(file: &mut File, data: &[u8]) -> Result<(), FileStatus>;
            pub(super) fn file_delete(file: &mut File) -> Result<(), FileStatus>;
            pub(super) fn pnp_create_pdo(
                parent_devnode: &Arc<DevNode>,
                bus_driver: &Arc<DriverObject>,
                name: String,
                instance_path: String,
                ids: DeviceIds,
                class: Option<String>,
            ) -> (Arc<DevNode>, Arc<DeviceObject>);
            pub(super) fn pnp_bind_and_start(dn: &Arc<DevNode>) -> Result<(), DriverError>;
            pub(super) fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget>;
            pub(super) fn pnp_forward_request_to_next_lower(
                from: &Arc<DeviceObject>,
                req: &mut Request,
            ) -> DriverStatus;
            pub(super) fn pnp_send_request(target: &IoTarget, req: &mut Request) -> DriverStatus;
            pub(super) fn pnp_complete_request(req: &mut Request);
            pub(super) fn driver_get_name(driver: &Arc<DriverObject>) -> String;
            pub(super) fn driver_get_flags(driver: &Arc<DriverObject>) -> u32;
            pub(super) fn driver_set_evt_device_add(
                driver: &Arc<DriverObject>,
                callback: EvtDriverDeviceAdd,
            );
            pub(super) fn driver_set_evt_driver_unload(
                driver: &Arc<DriverObject>,
                callback: EvtDriverUnload,
            );
            pub(super) fn get_acpi_tables() -> Arc<acpi::AcpiTables<KernelAcpiHandler>>;
        }
    }

    // --- Public Safe Wrappers for `alloc` functions ---
    pub fn create_kernel_task(entry: usize, name: String) -> u64 {
        unsafe { ffi::create_kernel_task(entry, name) }
    }
    pub fn file_open(path: &str, flags: &[OpenFlags]) -> Result<File, FileStatus> {
        unsafe { ffi::file_open(path, flags) }
    }
    pub fn fs_list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
        unsafe { ffi::fs_list_dir(path) }
    }
    pub fn fs_remove_dir(path: &str) -> Result<(), FileStatus> {
        unsafe { ffi::fs_remove_dir(path) }
    }
    pub fn fs_make_dir(path: &str) -> Result<(), FileStatus> {
        unsafe { ffi::fs_make_dir(path) }
    }
    pub fn file_read(file: &File) -> Result<Vec<u8>, FileStatus> {
        unsafe { ffi::file_read(file) }
    }
    pub fn file_write(file: &mut File, data: &[u8]) -> Result<(), FileStatus> {
        unsafe { ffi::file_write(file, data) }
    }
    pub fn file_delete(file: &mut File) -> Result<(), FileStatus> {
        unsafe { ffi::file_delete(file) }
    }
    pub fn pnp_create_pdo(
        /*...args...*/ parent_devnode: &Arc<DevNode>,
        bus_driver: &Arc<DriverObject>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
    ) -> (Arc<DevNode>, Arc<DeviceObject>) {
        unsafe { ffi::pnp_create_pdo(parent_devnode, bus_driver, name, instance_path, ids, class) }
    }
    pub fn pnp_bind_and_start(dn: &Arc<DevNode>) -> Result<(), DriverError> {
        unsafe { ffi::pnp_bind_and_start(dn) }
    }
    pub fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget> {
        unsafe { ffi::pnp_get_device_target(instance_path) }
    }
    pub fn pnp_forward_request_to_next_lower(
        from: &Arc<DeviceObject>,
        req: &mut Request,
    ) -> DriverStatus {
        unsafe { ffi::pnp_forward_request_to_next_lower(from, req) }
    }
    pub fn pnp_send_request(target: &IoTarget, req: &mut Request) -> DriverStatus {
        unsafe { ffi::pnp_send_request(target, req) }
    }
    pub fn pnp_complete_request(req: &mut Request) {
        unsafe { ffi::pnp_complete_request(req) }
    }
    pub fn driver_get_name(driver: &Arc<DriverObject>) -> String {
        unsafe { ffi::driver_get_name(driver) }
    }
    pub fn driver_get_flags(driver: &Arc<DriverObject>) -> u32 {
        unsafe { ffi::driver_get_flags(driver) }
    }
    pub fn driver_set_evt_device_add(driver: &Arc<DriverObject>, callback: EvtDriverDeviceAdd) {
        unsafe { ffi::driver_set_evt_device_add(driver, callback) }
    }
    pub fn driver_set_evt_driver_unload(driver: &Arc<DriverObject>, callback: EvtDriverUnload) {
        unsafe { ffi::driver_set_evt_driver_unload(driver, callback) }
    }
    pub fn get_acpi_tables() -> Arc<acpi::AcpiTables<KernelAcpiHandler>> {
        unsafe { ffi::get_acpi_tables() }
    }
}

mod ffi {
    use super::*;
    #[link(name = "KRNL")]
    #[no_mangle]

    extern "win64" {
        pub(super) fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError>;
        pub(super) fn allocate_auto_kernel_range_mapped(
            size: u64,
            flags: PageTableFlags,
        ) -> Result<VirtAddr, PageMapError>;
        pub(super) fn allocate_kernel_range_mapped(
            base: u64,
            size: u64,
            flags: PageTableFlags,
        ) -> Result<VirtAddr, PageMapError>;
        pub(super) fn deallocate_kernel_range(addr: VirtAddr, size: u64);
        pub(super) fn unmap_range(virtual_addr: VirtAddr, size: u64);
        pub(super) fn identity_map_page(frame_addr: PhysAddr, flags: PageTableFlags);
        pub(super) fn map_mmio_region(
            mmio_base: PhysAddr,
            mmio_size: u64,
        ) -> Result<VirtAddr, PageMapError>;
        pub(super) fn virt_to_phys(addr: VirtAddr) -> Option<PhysAddr>;
        pub(super) fn kernel_alloc(layout: Layout) -> *mut u8;
        pub(super) fn kernel_free(ptr: *mut u8, layout: Layout);
        pub(super) fn pnp_queue_dpc(func: DpcFn, arg: usize);

        pub(super) fn print(s: &str);
        pub(super) fn wait_ms(ms: u64);
    }
}

pub fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError> {
    unsafe { ffi::kill_kernel_task_by_id(id) }
}
pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { ffi::allocate_auto_kernel_range_mapped(size, flags) }
}
pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { ffi::allocate_kernel_range_mapped(base, size, flags) }
}
pub fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    unsafe { ffi::deallocate_kernel_range(addr, size) }
}
pub fn unmap_range(virtual_addr: VirtAddr, size: u64) {
    unsafe { ffi::unmap_range(virtual_addr, size) }
}
pub fn identity_map_page(frame_addr: PhysAddr, flags: PageTableFlags) {
    unsafe { ffi::identity_map_page(frame_addr, flags) }
}
pub fn map_mmio_region(mmio_base: PhysAddr, mmio_size: u64) -> Result<VirtAddr, PageMapError> {
    unsafe { ffi::map_mmio_region(mmio_base, mmio_size) }
}
pub fn virt_to_phys(addr: VirtAddr) -> Option<PhysAddr> {
    unsafe { ffi::virt_to_phys(addr) }
}
pub fn kernel_alloc(layout: Layout) -> *mut u8 {
    unsafe { ffi::kernel_alloc(layout) }
}
pub fn kernel_free(ptr: *mut u8, layout: Layout) {
    unsafe { ffi::kernel_free(ptr, layout) }
}
pub fn pnp_queue_dpc(func: DpcFn, arg: usize) {
    unsafe { ffi::pnp_queue_dpc(func, arg) }
}
#[inline(never)]
pub fn print(s: &str) {
    unsafe { ffi::print(s) }
}
pub fn wait_ms(ms: u64) {
    unsafe { ffi::wait_ms(ms) }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        $crate::print(&$crate::alloc::format!($($arg)*));
    });
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", $crate::alloc::format!($($arg)*)));
}
