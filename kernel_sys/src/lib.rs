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
use core::time::Duration;
use kernel_types::async_ffi::FfiFuture;
use kernel_types::benchmark::{
    BenchCoreId, BenchObjectId, BenchSpanId, BenchTag, BenchWindowConfig, BenchWindowHandle,
};
use kernel_types::irq::{DropHook, IrqHandlePtr, IrqIsrFn, IrqMeta, IrqWaitResult};
use spin::RwLock;

use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::structures::paging::PageTableFlags;

use kernel_types::device::{DevNode, DeviceInit, DeviceObject, DriverObject};
use kernel_types::fs::{File, OpenFlags, Path};
use kernel_types::io::IoTarget;
use kernel_types::pnp::{DeviceIds, DeviceRelationType};
use kernel_types::request::Request;
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
    pub fn wait_duration(time: Duration);
    pub fn get_rsdp() -> u64;
    pub unsafe fn get_current_cpu_id() -> usize;
    // =========================================================================
    // Tasking
    // =========================================================================
    pub fn create_kernel_task(entry: extern "win64" fn(usize), ctx: usize, name: String) -> u64;
    pub fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError>;
    pub fn pnp_queue_dpc(func: DpcFn, arg: usize);
    pub fn submit_runtime_internal(trampoline: extern "win64" fn(usize), ctx: usize);
    pub fn submit_blocking_internal(trampoline: extern "win64" fn(usize), ctx: usize);
    pub fn try_steal_blocking_one() -> bool;
    pub unsafe fn park_self_and_yield();
    pub unsafe fn wake_task(id: u64);
    // =========================================================================
    // IRQ
    // =========================================================================
    pub fn kernel_irq_register(vector: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandlePtr;
    pub fn kernel_irq_signal(handle: IrqHandlePtr, meta: IrqMeta);
    pub fn kernel_irq_signal_n(handle: IrqHandlePtr, meta: IrqMeta, n: u32);
    pub fn irq_handle_create(drop_hook: DropHook) -> IrqHandlePtr;

    pub fn irq_handle_clone(h: IrqHandlePtr) -> IrqHandlePtr;
    pub fn irq_handle_drop(h: IrqHandlePtr);

    pub fn irq_handle_unregister(h: IrqHandlePtr);
    pub fn irq_handle_is_closed(h: IrqHandlePtr) -> bool;

    pub fn irq_handle_set_user_ctx(h: IrqHandlePtr, v: usize);
    pub fn irq_handle_get_user_ctx(h: IrqHandlePtr) -> usize;

    pub fn irq_handle_wait_ffi(h: IrqHandlePtr, meta: IrqMeta) -> FfiFuture<IrqWaitResult>;
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
    pub fn unmap_mmio_region(mmio_base: VirtAddr, mmio_size: u64) -> Result<(), PageMapError>;
    pub fn virt_to_phys(addr: VirtAddr) -> PhysAddr;

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
    pub fn file_open(path: &Path, flags: &[OpenFlags]) -> FfiFuture<Result<File, FileStatus>>;
    pub fn fs_list_dir(path: &Path) -> FfiFuture<Result<Vec<String>, FileStatus>>;
    pub fn fs_remove_dir(path: &Path) -> FfiFuture<Result<(), FileStatus>>;
    pub fn fs_make_dir(path: &Path) -> FfiFuture<Result<(), FileStatus>>;
    pub fn file_read(file: &File) -> FfiFuture<Result<Vec<u8>, FileStatus>>;
    pub fn file_write(file: &mut File, data: &[u8]) -> FfiFuture<Result<(), FileStatus>>;
    pub fn file_delete(file: &mut File) -> FfiFuture<Result<(), FileStatus>>;
    pub fn vfs_notify_label_published(
        label_ptr: *const u8,
        label_len: usize,
        symlink_ptr: *const u8,
        symlink_len: usize,
    );

    pub fn vfs_notify_label_unpublished(label_ptr: *const u8, label_len: usize);
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
        from: Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> FfiFuture<DriverStatus>;

    pub fn pnp_forward_request_to_next_upper(
        from: Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> FfiFuture<DriverStatus>;

    pub fn pnp_send_request(target: IoTarget, req: Arc<RwLock<Request>>)
    -> FfiFuture<DriverStatus>;

    pub fn pnp_complete_request(req: Arc<RwLock<Request>>) -> DriverStatus;

    pub fn pnp_create_symlink(link_path: String, target_path: String) -> DriverStatus;
    pub fn pnp_replace_symlink(link_path: String, target_path: String) -> DriverStatus;
    pub fn pnp_create_device_symlink_top(instance_path: String, link_path: String) -> DriverStatus;
    pub fn pnp_remove_symlink(link_path: String) -> DriverStatus;

    pub fn pnp_send_request_via_symlink(
        link_path: String,
        req: Arc<RwLock<Request>>,
    ) -> FfiFuture<DriverStatus>;

    pub fn pnp_ioctl_via_symlink(
        link_path: String,
        control_code: u32,
        request: Arc<RwLock<Request>>,
    ) -> FfiFuture<DriverStatus>;

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

    pub fn pnp_send_request_to_stack_top(
        dev_node_weak: Weak<DevNode>,
        req: Arc<RwLock<Request>>,
    ) -> FfiFuture<DriverStatus>;

    pub fn InvalidateDeviceRelations(
        device: Arc<DeviceObject>,
        relation: DeviceRelationType,
    ) -> FfiFuture<DriverStatus>;
    pub fn get_acpi_tables() -> Arc<acpi::AcpiTables<KernelAcpiHandler>>;
    // =========================================================================
    // Bench (drivers)
    // =========================================================================
    pub fn bench_kernel_window_create(cfg: BenchWindowConfig) -> BenchWindowHandle;
    pub fn bench_kernel_window_destroy(handle: BenchWindowHandle) -> bool;
    pub fn bench_kernel_window_start(handle: BenchWindowHandle) -> bool;
    pub fn bench_kernel_window_stop(handle: BenchWindowHandle) -> bool;
    pub fn bench_kernel_window_persist(handle: BenchWindowHandle) -> FfiFuture<bool>;

    pub fn bench_kernel_submit_rip_sample(
        core: BenchCoreId,
        rip: u64,
        stack_ptr: *const u64,
        stack_len: usize,
    );
    pub fn bench_kernel_span_begin(tag: BenchTag, object_id: BenchObjectId) -> BenchSpanGuard;
    pub fn bench_kernel_span_end(span_id: BenchSpanId, tag: BenchTag, object_id: BenchObjectId);

    // =========================================================================
    // Async Runtime (global)
    // =========================================================================
    pub fn kernel_spawn_ffi(fut: FfiFuture<()>);
    pub fn kernel_async_submit(trampoline: extern "win64" fn(usize), ctx: usize);
    pub fn kernel_spawn_detached_ffi(fut: FfiFuture<()>);
    pub fn kernel_block_on_ffi(fut: FfiFuture<()>);
    pub fn kernel_spawn_blocking_raw(trampoline: extern "win64" fn(usize), ctx: usize);

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
#[repr(C)]
#[derive(Debug)]
pub struct BenchSpanGuard {
    span_id: BenchSpanId,
    tag: BenchTag,
    object_id: BenchObjectId,
    enabled: bool,
}

impl BenchSpanGuard {
    #[inline]
    pub fn disabled(tag: BenchTag, object_id: BenchObjectId) -> Self {
        BenchSpanGuard {
            span_id: BenchSpanId(0),
            tag,
            object_id,
            enabled: false,
        }
    }

    #[inline]
    pub fn enabled(span_id: BenchSpanId, tag: BenchTag, object_id: BenchObjectId) -> Self {
        BenchSpanGuard {
            span_id,
            tag,
            object_id,
            enabled: true,
        }
    }

    #[inline]
    pub fn span_id(&self) -> BenchSpanId {
        self.span_id
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[inline]
    pub fn tag(&self) -> BenchTag {
        self.tag
    }

    #[inline]
    pub fn object_id(&self) -> BenchObjectId {
        self.object_id
    }
}

impl Drop for BenchSpanGuard {
    fn drop(&mut self) {
        if self.enabled {
            unsafe { bench_kernel_span_end(self.span_id, self.tag, self.object_id) };
        }
    }
}
