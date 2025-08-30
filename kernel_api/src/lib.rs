#![no_std]
#![allow(improper_ctypes, improper_ctypes_definitions)]
pub extern crate alloc;

pub use acpi;
use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use alloc_api::{CompletionRoutine, DeviceInit, PnpRequest};
use ffi::random_number;
use spin::{Mutex, RwLock};
pub use x86_64;
use x86_64::structures::paging::mapper::MapToError;

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, AtomicU8};
use strum::Display;
use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::structures::paging::{PageTableFlags, Size1GiB, Size2MiB, Size4KiB};

use crate::alloc_api::DeviceIds;

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ffi::kernel_alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ffi::kernel_free(ptr, layout)
    }
}

#[derive(Debug)]
#[repr(C)]

pub struct DeviceObject {
    pub lower_device: Option<Arc<DeviceObject>>,
    pub upper_device: RwLock<Option<alloc::sync::Weak<DeviceObject>>>,
    pub dev_ext: Box<[u8]>,
    pub dev_init: DeviceInit,
    pub queue: Mutex<VecDeque<Arc<spin::Mutex<Request>>>>,

    pub dispatch_scheduled: AtomicBool,
    pub dev_node: Weak<DevNode>,
}
#[derive(Debug)]
#[repr(C)]
pub struct DevNode {
    pub name: String,
    pub parent: RwLock<Option<alloc::sync::Weak<DevNode>>>,
    pub children: RwLock<Vec<Arc<DevNode>>>,
    pub instance_path: String,
    pub ids: DeviceIds,
    pub class: Option<String>,
    pub state: AtomicU8,

    pub pdo: RwLock<Option<Arc<DeviceObject>>>,
    pub stack: RwLock<Option<DeviceStack>>,
}
#[repr(C)]
pub struct DriverObject {
    _private: [u8; 0],
}
#[derive(Debug)]
#[repr(C)]

pub struct DeviceStack {
    _private: [u8; 0],
}
#[repr(C)]
pub struct IoTarget {
    _private: [u8; 0],
}
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum RequestType {
    Read { offset: u64, len: usize },
    Write { offset: u64, len: usize },
    DeviceControl(u32),

    Pnp,

    Dummy,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GptHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub _reserved: u32,
    pub _current_lba: u64,
    pub _backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub _partition_crc32: u32,
    pub_reserved_block: [u8; 420],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GptPartitionEntry {
    pub partition_type_guid: [u8; 16],
    pub unique_partition_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub _attr: u64,
    pub name_utf16: [u16; 36],
}

#[derive(Debug)]
#[repr(C)]
pub struct Request {
    pub id: u64,
    pub kind: RequestType,
    pub data: Box<[u8]>,
    pub completed: bool,
    pub status: DriverStatus,

    pub pnp: Option<PnpRequest>,

    pub completion_routine: Option<CompletionRoutine>,
    pub completion_context: usize,
}
impl Request {
    #[inline]
    pub fn new(kind: RequestType, data: Box<[u8]>) -> Self {
        Self {
            id: unsafe { random_number() },
            kind,
            data,
            completed: false,
            status: DriverStatus::Pending,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
        }
    }
    #[inline]
    pub fn empty() -> Self {
        let dummy_kind = RequestType::Dummy;

        Self {
            id: 0,
            kind: dummy_kind,
            data: Box::new([]),
            completed: true,
            status: DriverStatus::Success,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
        }
    }
    pub fn set_completion(&mut self, routine: CompletionRoutine, context: usize) {
        self.completion_routine = Some(routine);
        self.completion_context = context;
    }
}
#[repr(C)]
pub struct File {
    _private: [u8; 0],
}

#[repr(i32)]
#[derive(Display, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverStatus {
    Success = 0x0000_0000,
    Pending = 0x0000_0103,
    Waiting = 0x0000_0104,
    NotImplemented = 0xC000_0002u32 as i32,
    InvalidParameter = 0xC000_000Du32 as i32,
    InsufficientResources = 0xC000_009Au32 as i32,
    NoSuchDevice = 0xC000_000Eu32 as i32,
    NoSuchFile = 0xC000_000Fu32 as i32,
    DeviceNotReady = 0xC000_00A3u32 as i32,
    Unsuccessful = 0xC000_0001u32 as i32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DriverError {
    LoadError,
    BindError,
    StartError,
}
#[derive(Debug)]
#[repr(u32)]

pub enum PageMapError {
    Page4KiB(MapToError<Size4KiB>),
    Page2MiB(MapToError<Size2MiB>),
    Page1GiB(MapToError<Size1GiB>),
    NoMemory(),
    NoMemoryMap(),
}

impl From<MapToError<Size4KiB>> for PageMapError {
    fn from(e: MapToError<Size4KiB>) -> Self {
        PageMapError::Page4KiB(e)
    }
}
impl From<MapToError<Size2MiB>> for PageMapError {
    fn from(e: MapToError<Size2MiB>) -> Self {
        PageMapError::Page2MiB(e)
    }
}
impl From<MapToError<Size1GiB>> for PageMapError {
    fn from(e: MapToError<Size1GiB>) -> Self {
        PageMapError::Page1GiB(e)
    }
}
#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
    BadName,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]

pub enum BootType {
    Boot = 0,
    System = 1,
    Demand = 2,
    Disabled = 3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceRelationType {
    BusRelations,
    EjectionRelations,
    RemovalRelations,
    TargetDeviceRelation,
    PowerRelations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QueryIdType {
    DeviceId,
    HardwareIds,
    CompatibleIds,
    InstanceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PnpMinorFunction {
    StartDevice,
    QueryDeviceRelations,
    QueryId,
    QueryResources,
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
#[repr(u32)]

pub enum OpenFlags {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Create,
    CreateNew,
    Open,
}
#[derive(Debug, Clone)]
pub enum Data {
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
    Bool(bool),
    Str(String),
}

#[derive(Debug, Clone)]
pub enum RegError {
    File(FileStatus),
    KeyAlreadyExists,
    KeyNotFound,
    ValueNotFound,
    PersistenceFailed,
    EncodingFailed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResourceKind {
    Memory = 1,
    Port = 2,
    Interrupt = 3,
}
pub type DpcFn = extern "win64" fn(usize);

pub mod alloc_api {
    use core::ptr::NonNull;

    use super::*;
    use acpi::PhysicalMapping;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    #[repr(C)]
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
        pub evt_bus_enumerate_devices: Option<EvtDeviceEnumerateDevices>,
        pub evt_pnp: Option<extern "win64" fn(&Arc<DeviceObject>, &mut Request)>,
    }

    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct PnpRequest {
        pub minor_function: PnpMinorFunction,
        pub relation: DeviceRelationType,
        pub id_type: QueryIdType,

        pub ids_out: Vec<String>,
        pub blob_out: Vec<u8>,
    }
    #[derive(Debug, Clone)]
    pub struct KernelAcpiHandler;

    impl acpi::AcpiHandler for KernelAcpiHandler {
        unsafe fn map_physical_region<T>(
            &self,
            physical_address: usize,
            size: usize,
        ) -> PhysicalMapping<Self, T> {
            use crate::ffi::map_mmio_region;
            let virt_addr = map_mmio_region(PhysAddr::new(physical_address as u64), size as u64)
                .expect("failed to map io space for ACPI");
            PhysicalMapping::new(
                physical_address,
                NonNull::new(virt_addr.as_mut_ptr()).unwrap(),
                size,
                size,
                self.clone(),
            )
        }

        fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>) {
            use crate::ffi::unmap_range;
            unsafe {
                unmap_range(
                    VirtAddr::new(region.virtual_start().as_ptr() as u64),
                    region.region_length() as u64,
                )
            }
        }
    }

    pub type EvtDriverDeviceAdd =
        extern "win64" fn(driver: &Arc<DriverObject>, init: &mut DeviceInit) -> DriverStatus;

    pub type EvtDriverUnload = extern "win64" fn(driver: &Arc<DriverObject>);

    pub type EvtIoRead = extern "win64" fn(&Arc<DeviceObject>, &mut Request, usize);
    pub type EvtIoWrite = extern "win64" fn(&Arc<DeviceObject>, &mut Request, usize);
    pub type EvtIoDeviceControl = extern "win64" fn(&Arc<DeviceObject>, &mut Request);
    pub type EvtDevicePrepareHardware = extern "win64" fn(&Arc<DeviceObject>) -> DriverStatus;
    pub type EvtDeviceEnumerateDevices =
        extern "win64" fn(&Arc<DeviceObject>, &mut Request) -> DriverStatus;
    pub type ClassAddCallback =
        extern "win64" fn(node: &Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
    pub type CompletionRoutine = extern "win64" fn(request: &mut Request, context: usize);
    pub mod ffi {
        use super::*;
        #[link(name = "KRNL")]
        pub mod reg {
            use super::*;

            extern "win64" {
                pub fn reg_get_value(key_path: &str, name: &str) -> Option<Data>;
                pub fn reg_set_value(
                    key_path: &str,
                    name: &str,
                    data: Data,
                ) -> Result<(), RegError>;
                pub fn reg_create_key(path: &str) -> Result<(), RegError>;
                pub fn reg_delete_key(path: &str) -> Result<bool, RegError>;
                pub fn reg_delete_value(key_path: &str, name: &str) -> Result<bool, RegError>;
                pub fn reg_list_keys(base_path: &str) -> Result<Vec<String>, RegError>;
                pub fn reg_list_values(base_path: &str) -> Result<Vec<String>, RegError>;
            }

            // Small safe-ish wrappers for convenience (just forward to externs)
            #[inline]
            pub fn get_value(k: &str, n: &str) -> Option<Data> {
                unsafe { reg_get_value(k, n) }
            }
            #[inline]
            pub fn set_value(k: &str, n: &str, d: Data) -> Result<(), RegError> {
                unsafe { reg_set_value(k, n, d) }
            }
            #[inline]
            pub fn create_key(p: &str) -> Result<(), RegError> {
                unsafe { reg_create_key(p) }
            }
            #[inline]
            pub fn delete_key(p: &str) -> Result<bool, RegError> {
                unsafe { reg_delete_key(p) }
            }
            #[inline]
            pub fn delete_value(k: &str, n: &str) -> Result<bool, RegError> {
                unsafe { reg_delete_value(k, n) }
            }
            #[inline]
            pub fn list_keys(b: &str) -> Result<Vec<String>, RegError> {
                unsafe { reg_list_keys(b) }
            }
            #[inline]
            pub fn list_values(b: &str) -> Result<Vec<String>, RegError> {
                unsafe { reg_list_values(b) }
            }
        }
        extern "win64" {
            pub fn create_kernel_task(entry: usize, name: String) -> u64;
            pub fn file_open(path: &str, flags: &[OpenFlags]) -> Result<File, FileStatus>;
            pub fn fs_list_dir(path: &str) -> Result<Vec<String>, FileStatus>;
            pub fn fs_remove_dir(path: &str) -> Result<(), FileStatus>;
            pub fn fs_make_dir(path: &str) -> Result<(), FileStatus>;
            pub fn file_read(file: &File) -> Result<Vec<u8>, FileStatus>;
            pub fn file_write(file: &mut File, data: &[u8]) -> Result<(), FileStatus>;
            pub fn file_delete(file: &mut File) -> Result<(), FileStatus>;
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
            pub fn pnp_bind_and_start(dn: &Arc<DevNode>) -> Result<(), DriverError>;
            pub fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget>;
            pub fn pnp_forward_request_to_next_lower(
                from: &Arc<DeviceObject>,
                req: &mut Request,
            ) -> DriverStatus;
            pub fn pnp_send_request(target: &IoTarget, req: &mut Request) -> DriverStatus;
            pub fn pnp_complete_request(req: &mut Request);
            pub fn pnp_create_symlink(link_path: String, target_path: String) -> DriverStatus;
            pub fn pnp_replace_symlink(link_path: String, target_path: String) -> DriverStatus;
            pub fn pnp_create_device_symlink_top(
                instance_path: String,
                link_path: String,
            ) -> DriverStatus;
            pub fn pnp_remove_symlink(link_path: String) -> DriverStatus;

            pub fn pnp_send_request_via_symlink(
                link_path: String,
                req: &mut Request,
            ) -> DriverStatus;

            pub fn pnp_ioctl_via_symlink(
                link_path: String,
                control_code: u32,
                request: &mut Request,
            ) -> DriverStatus;
            pub fn pnp_load_service(name: String) -> Option<Arc<DriverObject>>;
            pub fn pnp_create_control_device_with_init(
                name: alloc::string::String,
                init: DeviceInit,
            ) -> Arc<DeviceObject>;
            pub fn pnp_create_control_device_and_link(
                name: alloc::string::String,
                init: DeviceInit,
                link_path: alloc::string::String,
            ) -> Arc<DeviceObject>;
            pub fn pnp_add_class_listener(
                class: String,
                callback: ClassAddCallback,
                dev_obj: Arc<DeviceObject>,
            );

            pub fn InvalidateDeviceRelations(
                device: &Arc<DeviceObject>,
                relation: DeviceRelationType,
            ) -> DriverStatus;
            pub fn driver_get_name(driver: &Arc<DriverObject>) -> String;
            pub fn driver_get_flags(driver: &Arc<DriverObject>) -> u32;
            pub fn driver_set_evt_device_add(
                driver: &Arc<DriverObject>,
                callback: EvtDriverDeviceAdd,
            );
            pub fn driver_set_evt_driver_unload(
                driver: &Arc<DriverObject>,
                callback: EvtDriverUnload,
            );
            pub fn get_acpi_tables() -> Arc<acpi::AcpiTables<KernelAcpiHandler>>;
        }
    }
}

pub mod ffi {
    use super::*;
    #[link(name = "KRNL")]

    extern "win64" {
        pub fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError>;
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
        pub fn map_mmio_region(
            mmio_base: PhysAddr,
            mmio_size: u64,
        ) -> Result<VirtAddr, PageMapError>;
        pub fn virt_to_phys(addr: VirtAddr) -> Option<PhysAddr>;
        pub fn kernel_alloc(layout: Layout) -> *mut u8;
        pub fn kernel_free(ptr: *mut u8, layout: Layout);
        pub fn pnp_queue_dpc(func: DpcFn, arg: usize);
        pub fn get_rsdp() -> u64;
        pub fn print(s: &str);
        pub fn wait_ms(ms: u64);
        pub fn random_number() -> u64;
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        unsafe{$crate::ffi::print(&$crate::alloc::format!($($arg)*))};
    });
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", $crate::alloc::format!($($arg)*)));
}
