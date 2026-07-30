use core::{
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use kernel_executor::global_async::GlobalAsyncExecutor;
use kernel_executor::runtime::runtime::{
    block_on as kernel_block_on, spawn_blocking as kernel_spawn_blocking,
    spawn_detached as kernel_spawn_detached, spawn_join_owned as kernel_spawn,
};
use kernel_types::dma::DeviceMmuPlatformDeviceIdentity;
use kernel_types::dma::IoBufferBacking;
use kernel_types::object_manager::OmError;

use crate::memory::heap::allocator::KernelAllocator;
use crate::scheduling::task::TaskError;
use crate::{
    benchmarking::{
        bench_log_span_end, bench_span_guard, bench_submit_rip_sample, BenchSpanGuard, BenchWindow,
    },
    console::CONSOLE,
    drivers::{
        pnp::{device::DevNodeExt, manager::PNP_MANAGER, request::DpcFn},
        ACPI::ACPIImpl,
    },
    file_system::{
        file::{self, File},
        file_provider::VFS_PROVIDER,
    },
    idt::{
        irq_alloc_vector, irq_borrowed_ensure_signal, irq_borrowed_signal, irq_borrowed_signal_all,
        irq_borrowed_signal_n, irq_free_vector, irq_register, irq_register_gsi, irq_signal,
        irq_signal_all, irq_signal_exactly, irq_signal_n,
    },
    memory::{dma, paging::stack::StackSize},
    registry::reg,
    scheduling::{self, scheduler::SCHEDULER, task::Task},
    structs::stopwatch::Stopwatch,
    util::boot_info,
};
use acpi::AcpiTables;
use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{
        BenchCoreId, BenchMetricDirection, BenchMetricUnit, BenchObjectId, BenchRunHandle,
        BenchSpanId, BenchSuiteDescriptor, BenchTag, BenchWindowConfig, BenchWindowHandle,
    },
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    dma::{
        DmaBufferView, DmaDeviceHandle, DmaDeviceState, DmaMapError, DmaMappedBuffer,
        DmaMappingStrategy, DmaPciDeviceIdentity,
    },
    error::{DriverErrorKind, KernelError},
    fdt::FdtHeader,
    fs::{OpenFlags, Path},
    io::IoTarget,
    irq::{IrqBorrowedHandle, IrqHandle, IrqIsrFn, IrqMeta, MsiMessage, MsiRequest},
    pci::PciConfigAddress,
    pnp::{DeviceIds, DeviceRelationType},
    runtime::BlockOnThreadState,
    status::{Data, PageMapError},
    ClassEventCallback, EvtDriverDeviceAdd, EvtDriverProbeDevice, EvtDriverUnload,
};
use spin::{Mutex, Once};

#[unsafe(no_mangle)]
pub extern "C" fn create_kernel_task(entry: extern "C" fn(usize), ctx: usize, name: String) -> u64 {
    let task = Task::new_kernel_mode(entry, ctx, StackSize::Tiny, name, 0);
    SCHEDULER.add_task(task)
}

pub unsafe extern "C" fn park_self_and_yield() {
    SCHEDULER.park_current();
}
pub extern "C" fn get_current_platform_cpu_id() -> usize {
    crate::platform::current_logical_id()
}

pub extern "C" fn wake_task(id: u64) {
    if let Some(task) = SCHEDULER.get_task_by_id(id) {
        SCHEDULER.unpark(&task);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError> {
    SCHEDULER.delete_task(id)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_alloc(layout: Layout) -> *mut u8 {
    unsafe { GlobalAlloc::alloc(&crate::memory::heap::ALLOCATOR, layout) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_free(ptr: *mut u8, layout: Layout) {
    unsafe {
        GlobalAlloc::dealloc(&crate::memory::heap::ALLOCATOR, ptr, layout);
    };
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_irq_register(vector: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandle {
    irq_register(vector, isr, ctx)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_irq_register_gsi(gsi: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandle {
    irq_register_gsi(gsi, isr, ctx)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_irq_alloc_vector() -> i32 {
    irq_alloc_vector().map(|v| v as i32).unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_irq_free_vector(vector: u8) -> bool {
    irq_free_vector(vector)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_irq_compose_msi_message(
    request: &MsiRequest,
    out: &mut MsiMessage,
) -> bool {
    match crate::platform::compose_msi_message(request) {
        Some(message) => {
            *out = message;
            true
        }
        None => false,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pci_read_config_u32(address: PciConfigAddress, out: &mut u32) -> bool {
    match crate::platform::read_pci_config_u32(address) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pci_write_config_u32(address: PciConfigAddress, value: u32) -> bool {
    crate::platform::write_pci_config_u32(address, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_irq_borrowed_signal(handle: IrqBorrowedHandle, meta: IrqMeta) {
    unsafe {
        irq_borrowed_signal(handle, meta);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_irq_borrowed_ensure_signal(
    handle: IrqBorrowedHandle,
    meta: IrqMeta,
) {
    unsafe {
        irq_borrowed_ensure_signal(handle, meta);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_irq_borrowed_signal_n(
    handle: IrqBorrowedHandle,
    meta: IrqMeta,
    n: u32,
) {
    unsafe {
        irq_borrowed_signal_n(handle, meta, n);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_irq_borrowed_signal_all(handle: IrqBorrowedHandle, meta: IrqMeta) {
    unsafe {
        irq_borrowed_signal_all(handle, meta);
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_dma_base_page_size() -> u64 {
    dma::get_info()
        .capabilities
        .base_page_size()
        .expect("expected a valid base page size")
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_dma_register_pci_pdo(
    pdo: &Arc<DeviceObject>,
    identity: DmaPciDeviceIdentity,
) -> Result<(), DriverErrorKind> {
    dma::register_pci_pdo(pdo, identity)
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_dma_register_platform_pdo(
    pdo: &Arc<DeviceObject>,
    identity: DeviceMmuPlatformDeviceIdentity,
) -> Result<(), DriverErrorKind> {
    dma::register_platform_pdo(pdo, identity)
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_dma_open_device_handle(
    device: &Arc<DeviceObject>,
) -> Result<DmaDeviceHandle, DriverErrorKind> {
    dma::open_device_handle(device)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_dma_query_device_state(
    device: &Arc<DeviceObject>,
) -> Option<DmaDeviceState> {
    dma::query_device_state(device)
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_dma_map_buffer<'regions, 'frames>(
    device: &Arc<DeviceObject>,
    buffer: &DmaBufferView<'regions>,
    strategy: DmaMappingStrategy,
) -> Result<DmaMappedBuffer, DmaMapError> {
    dma::map_buffer(device, buffer, strategy)
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_dma_map_persistent_contiguous_backing(
    device: &Arc<DeviceObject>,
    backing: &IoBufferBacking<'_>,
) -> Result<(), DmaMapError> {
    crate::memory::dma::map_persistent_contiguous_backing(device, backing)
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_platform_cpu_ids() -> Vec<u8> {
    crate::platform::cpu_topology_ids()
}
#[unsafe(no_mangle)]
pub extern "C" fn print(str: &str) {
    crate::platform::serial_write_bytes(str.as_bytes());
    CONSOLE.lock().print(str.as_bytes());
}
#[unsafe(no_mangle)]
pub fn routing_print_impl(s: &str) {
    crate::platform::serial_write_bytes(s.as_bytes());
    CONSOLE.lock().print(s.as_bytes());
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_duration(time: Duration) {
    crate::platform::wait_duration(time);
}
#[unsafe(no_mangle)]
pub extern "C" fn stopwatch_new() -> Stopwatch {
    Stopwatch::start()
}
#[unsafe(no_mangle)]
pub extern "C" fn elapsed(s: &Stopwatch) -> Duration {
    s.elapsed()
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_cycle_counter() -> u64 {
    crate::platform::cycle_counter()
}
#[unsafe(no_mangle)]
pub extern "C" fn kernel_cycle_counter_frequency_hz() -> u64 {
    crate::platform::cycle_counter_frequency_hz()
}
#[unsafe(no_mangle)]
pub extern "C" fn file_open(
    path: &Path,
    flags: &[OpenFlags],
) -> AbiFuture<Result<File, KernelError>> {
    let path = path.clone();
    let flags_vec: Vec<OpenFlags> = flags.to_vec();

    async move { File::open(&path, &flags_vec).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_list_dir(path: &Path) -> AbiFuture<Result<Vec<String>, KernelError>> {
    let path = path.clone();

    async move { File::list_dir(&path).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_remove_dir(path: &Path) -> AbiFuture<Result<(), KernelError>> {
    let path = path.clone();

    async move { File::remove_dir(&path).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_make_dir(path: &Path) -> AbiFuture<Result<(), KernelError>> {
    let path = path.clone();

    async move { File::make_dir(&path).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_get_value(key_path: &str, name: &str) -> AbiFuture<Option<Data>> {
    let key_path = key_path.to_string();
    let name = name.to_string();

    async move { reg::get_value(key_path.as_str(), name.as_str()).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_set_value(
    key_path: &str,
    name: &str,
    data: Data,
) -> AbiFuture<Result<(), KernelError>> {
    let key_path = key_path.to_string();
    let name = name.to_string();

    async move { reg::set_value(key_path.as_str(), name.as_str(), data).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_create_key(path: &str) -> AbiFuture<Result<(), KernelError>> {
    let path = path.to_string();

    async move { reg::create_key(path).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_delete_key(path: &str) -> AbiFuture<Result<bool, KernelError>> {
    let path = path.to_string();

    async move { reg::delete_key(path.as_str()).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_delete_value(
    key_path: &str,
    name: &str,
) -> AbiFuture<Result<bool, KernelError>> {
    let key_path = key_path.to_string();
    let name = name.to_string();

    async move { reg::delete_value(key_path.as_str(), name.as_str()).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_list_keys(base_path: &str) -> AbiFuture<Result<Vec<String>, KernelError>> {
    let base_path = base_path.to_string();

    async move { reg::list_keys(base_path.as_str()).await }.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_list_values(base_path: &str) -> AbiFuture<Result<Vec<String>, KernelError>> {
    let base_path = base_path.to_string();

    async move { reg::list_values(base_path.as_str()).await }.into_abi()
}

pub extern "C" fn get_acpi_tables() -> Arc<AcpiTables<ACPIImpl>> {
    crate::machine::machine_info()
        .firmware()
        .acpi_tables()
        .expect("ACPI tables were not supplied by bootloader")
}

pub extern "C" fn get_device_tree_blob() -> Option<*const FdtHeader> {
    crate::machine::machine_info().firmware().fdt_header()
}

pub extern "C" fn pnp_create_pdo(
    parent_devnode: &Arc<DevNode>,
    name: String,
    instance_path: String,
    ids: DeviceIds,
    class: Option<String>,
) -> (Arc<DevNode>, Arc<DeviceObject>) {
    PNP_MANAGER.create_child_devnode_and_pdo(parent_devnode, name, instance_path, ids, class)
}

pub extern "C" fn pnp_bind_and_start(dn: &Arc<DevNode>) -> AbiFuture<Result<(), KernelError>> {
    let dn = dn.clone();

    async move { PNP_MANAGER.bind_and_start(&dn).await }.into_abi()
}

pub extern "C" fn pnp_get_device_target(instance_path: &str) -> Option<IoTarget> {
    PNP_MANAGER.get_device_target(instance_path)
}

pub extern "C" fn pnp_set_preferred_function_driver(
    instance_path: &str,
    driver_name: &str,
) -> AbiFuture<Result<(), KernelError>> {
    let instance_path = instance_path.to_string();
    let driver_name = driver_name.to_string();
    async move {
        PNP_MANAGER
            .set_preferred_function_driver(&instance_path, &driver_name)
            .await
    }
    .into_abi()
}

pub extern "C" fn pnp_queue_dpc(func: DpcFn, arg: usize) {
    PNP_MANAGER.queue_dpc(func, arg)
}

pub extern "C" fn driver_get_name(driver: &Arc<DriverObject>) -> String {
    driver.driver_name.clone()
}

pub extern "C" fn driver_get_flags(driver: &Arc<DriverObject>) -> u32 {
    driver.flags
}

pub extern "C" fn driver_set_evt_device_add(
    driver: &Arc<DriverObject>,
    callback: EvtDriverDeviceAdd,
) {
    *driver.evt_device_add.write() = Some(callback);
}

pub extern "C" fn driver_set_evt_probe_device(
    driver: &Arc<DriverObject>,
    callback: EvtDriverProbeDevice,
) {
    *driver.evt_probe_device.write() = Some(callback);
}

pub extern "C" fn driver_set_evt_driver_unload(
    driver: &Arc<DriverObject>,
    callback: EvtDriverUnload,
) {
    *driver.evt_driver_unload.write() = Some(callback);
}

pub extern "C" fn get_rsdp() -> u64 {
    boot_info().rsdp_addr.into_option().unwrap_or(0)
}

pub extern "C" fn pnp_create_child_devnode_and_pdo_with_init(
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

#[unsafe(no_mangle)]
pub extern "C" fn pnp_invalidate_device_relations(
    device: &Arc<DeviceObject>,
    relation: DeviceRelationType,
) -> AbiFuture<Result<(), KernelError>> {
    let device = device.clone();
    async move {
        let Some(dn) = device.dev_node.get() else {
            return Err(crate::error::error(DriverErrorKind::NoSuchDevice));
        };
        let Some(up) = dn.upgrade() else {
            return Err(crate::error::error(DriverErrorKind::NoSuchDevice));
        };
        PNP_MANAGER
            .invalidate_device_relations_for_node(&up, relation)
            .await
    }
    .into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn pnp_create_symlink(
    link_path: String,
    target_path: String,
) -> Result<(), OmError> {
    PNP_MANAGER.create_symlink(link_path, target_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn pnp_replace_symlink(
    link_path: String,
    target_path: String,
) -> Result<(), OmError> {
    PNP_MANAGER.replace_symlink(link_path, target_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn pnp_create_device_symlink_top(
    instance_path: String,
    link_path: String,
) -> Result<(), OmError> {
    PNP_MANAGER.create_device_symlink_top(instance_path, link_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn pnp_remove_symlink(link_path: String) -> Result<(), DriverErrorKind> {
    match PNP_MANAGER.remove_symlink(link_path) {
        Ok(()) => Ok(()),
        Err(_) => Err(DriverErrorKind::NoSuchDevice),
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn pnp_create_control_device_with_init(
    name: String,
    init: DeviceInit,
) -> Arc<DeviceObject> {
    let (dev, _) = PNP_MANAGER.create_control_device_with_init(name, init);
    dev
}

#[unsafe(no_mangle)]
pub extern "C" fn pnp_create_control_device_and_link(
    name: String,
    init: DeviceInit,
    link_path: String,
) -> Arc<DeviceObject> {
    PNP_MANAGER.create_control_device_and_link(name, init, link_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn pnp_add_class_listener(
    class: String,
    callback: ClassEventCallback,
    dev_obj: &Arc<DeviceObject>,
) {
    PNP_MANAGER.add_class_listener(class, dev_obj.clone(), callback);
}

static BLOCKING_INIT: Once = Once::new();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_yield() {
    crate::platform::with_interrupts_disabled(|| {
        crate::platform::request_task_yield();
    });
}

pub unsafe extern "C" fn switch_to_vfs_async() -> AbiFuture<Result<(), KernelError>> {
    file::switch_to_vfs().into_abi()
}

/// Notify VFS that a drive label has been published.
/// Called by mount manager when a new label symlink is created.
#[unsafe(no_mangle)]
pub extern "C" fn vfs_notify_label_published(
    label_ptr: *const u8,
    label_len: usize,
    symlink_ptr: *const u8,
    symlink_len: usize,
) {
    if label_ptr.is_null() || symlink_ptr.is_null() {
        return;
    }
    let label = unsafe { core::slice::from_raw_parts(label_ptr, label_len) };
    let symlink = unsafe { core::slice::from_raw_parts(symlink_ptr, symlink_len) };

    let Ok(label_str) = core::str::from_utf8(label) else {
        return;
    };
    let Ok(symlink_str) = core::str::from_utf8(symlink) else {
        return;
    };

    VFS_PROVIDER.set_label(label_str.to_string(), symlink_str.to_string());
}

/// Notify VFS that a drive label has been unpublished.
/// Called by mount manager when a label symlink is removed.
#[unsafe(no_mangle)]
pub extern "C" fn vfs_notify_label_unpublished(label_ptr: *const u8, label_len: usize) {
    if label_ptr.is_null() {
        return;
    }
    let label = unsafe { core::slice::from_raw_parts(label_ptr, label_len) };

    let Ok(label_str) = core::str::from_utf8(label) else {
        return;
    };

    VFS_PROVIDER.remove_label(label_str);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_spawn_abi(fut: AbiFuture<()>) {
    kernel_executor::runtime::abi_spawn::kernel_spawn_abi_internal(fut);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_spawn_joinable_abi(fut: AbiFuture<()>) -> AbiFuture<()> {
    let handle = kernel_spawn(fut);
    handle.into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_spawn_detached_abi(fut: AbiFuture<()>) {
    kernel_spawn_detached(async move {
        fut.await;
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_block_on_abi(fut: AbiFuture<()>) {
    kernel_block_on(fut);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_block_on_thread_state() -> Arc<BlockOnThreadState> {
    scheduling::tls::current_block_on_thread_state()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_spawn_blocking_raw(trampoline: extern "C" fn(usize), ctx: usize) {
    // Wrap the raw trampoline in the kernel-side blocking executor
    kernel_spawn_blocking(move || {
        (trampoline)(ctx);
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_async_submit(trampoline: extern "C" fn(usize), ctx: usize) {
    GlobalAsyncExecutor::global().submit(trampoline, ctx);
}

static BENCH_WINDOWS: Once<Mutex<BTreeMap<u32, BenchWindow>>> = Once::new();
static NEXT_BENCH_WINDOW: AtomicU32 = AtomicU32::new(1);

fn bench_windows() -> &'static Mutex<BTreeMap<u32, BenchWindow>> {
    BENCH_WINDOWS.call_once(|| Mutex::new(BTreeMap::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_window_create(cfg: BenchWindowConfig) -> BenchWindowHandle {
    let w = BenchWindow::new(cfg);
    let id = NEXT_BENCH_WINDOW.fetch_add(1, Ordering::Relaxed);
    bench_windows().lock().insert(id, w);
    BenchWindowHandle(id)
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_window_destroy(handle: BenchWindowHandle) -> bool {
    bench_windows().lock().remove(&handle.0).is_some()
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_window_start(handle: BenchWindowHandle) -> bool {
    let w = bench_windows().lock().get(&handle.0).cloned();
    if let Some(w) = w {
        w.start();
        true
    } else {
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_window_stop(handle: BenchWindowHandle) -> bool {
    let w = bench_windows().lock().get(&handle.0).cloned();
    if let Some(w) = w {
        w.stop();
        true
    } else {
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_window_persist(handle: BenchWindowHandle) -> AbiFuture<bool> {
    let w = bench_windows().lock().get(&handle.0).cloned();
    async move {
        if let Some(w) = w {
            w.persist().await;
            true
        } else {
            false
        }
    }
    .into_abi()
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_suite_register(descriptor: BenchSuiteDescriptor) -> bool {
    #[cfg(feature = "kernel-bench")]
    {
        crate::benchmarking::register_suite(descriptor)
    }
    #[cfg(not(feature = "kernel-bench"))]
    {
        let _ = descriptor;
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_case_start(handle: BenchRunHandle, case: String) -> bool {
    #[cfg(feature = "kernel-bench")]
    {
        crate::benchmarking::bench_case_start(handle, case)
    }
    #[cfg(not(feature = "kernel-bench"))]
    {
        let _ = (handle, case);
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_case_end(handle: BenchRunHandle) -> bool {
    #[cfg(feature = "kernel-bench")]
    {
        crate::benchmarking::bench_case_end(handle)
    }
    #[cfg(not(feature = "kernel-bench"))]
    {
        let _ = handle;
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_case_fail(handle: BenchRunHandle, reason: String) -> bool {
    #[cfg(feature = "kernel-bench")]
    {
        crate::benchmarking::bench_case_fail(handle, reason)
    }
    #[cfg(not(feature = "kernel-bench"))]
    {
        let _ = (handle, reason);
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_measure(
    handle: BenchRunHandle,
    metric: String,
    value: f64,
    unit: BenchMetricUnit,
    direction: BenchMetricDirection,
    tolerance_percent: f64,
) -> bool {
    let tolerance = tolerance_percent.is_finite().then_some(tolerance_percent);
    #[cfg(feature = "kernel-bench")]
    {
        crate::benchmarking::bench_measure_with_tolerance(
            handle, metric, value, unit, direction, tolerance,
        )
    }
    #[cfg(not(feature = "kernel-bench"))]
    {
        let _ = (handle, metric, value, unit, direction, tolerance);
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_submit_rip_sample(
    core: BenchCoreId,
    rip: u64,
    stack_ptr: *const u64,
    stack_len: usize,
) {
    let stack = if stack_ptr.is_null() || stack_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(stack_ptr, stack_len) }
    };

    bench_submit_rip_sample(core.0 as usize, rip, stack);
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_span_begin(
    tag: BenchTag,
    object_id: BenchObjectId,
) -> BenchSpanGuard {
    bench_span_guard(tag, object_id.0)
}

#[unsafe(no_mangle)]
pub extern "C" fn bench_kernel_span_end(
    span_id: BenchSpanId,
    tag: BenchTag,
    object_id: BenchObjectId,
) {
    bench_log_span_end(span_id.0, tag, object_id.0);
}

#[unsafe(no_mangle)]
pub extern "C" fn get_current_cpu_id() -> usize {
    crate::platform::current_cpu_id()
}
#[unsafe(no_mangle)]
pub extern "C" fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageFlags,
) -> Result<VirtAddr, PageMapError> {
    crate::memory::paging::allocate_auto_kernel_range_mapped(size, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn allocate_auto_kernel_range_mapped_contiguous(
    size: u64,
    flags: PageFlags,
) -> Result<VirtAddr, PageMapError> {
    crate::memory::paging::allocate_auto_kernel_range_mapped_contiguous(size, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageFlags,
) -> Result<VirtAddr, PageMapError> {
    crate::memory::paging::allocate_kernel_range_mapped(base, size, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    unsafe { crate::memory::paging::deallocate_kernel_range(addr, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unmap_range(virtual_addr: VirtAddr, size: u64) {
    unsafe { crate::memory::paging::unmap_range(virtual_addr, size) }
}

#[unsafe(no_mangle)]
pub extern "C" fn identity_map_page(frame_addr: PhysAddr, flags: PageFlags) {
    let _ = crate::memory::paging::identity_map_page(
        frame_addr,
        crate::memory::paging::base_page_size() as usize,
        flags,
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn map_physical_pages(
    phys: PhysAddr,
    size: u64,
    cache: kernel_types::memory::PhysicalMappingCache,
) -> Result<VirtAddr, PageMapError> {
    crate::memory::paging::map_physical_pages(phys, size, cache)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unmap_physical_pages(
    base: VirtAddr,
    size: u64,
) -> Result<(), PageMapError> {
    unsafe { crate::memory::paging::unmap_physical_pages(base, size) }
}

#[unsafe(no_mangle)]
pub extern "C" fn virt_to_phys(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    crate::memory::paging::virt_to_phys(addr)
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    let result = crate::memory::paging::resolve_virtual_range_frame(addr);
    result
}

// ============================================================================
// Routing functions - linker seams for kernel_routing crate (kernel_link feature)
// and FFI exports for drivers
// ============================================================================

/// Resolve a symlink/path to a device target
/// Linker seam for kernel_routing when compiled with kernel_link feature
#[unsafe(no_mangle)]
pub fn routing_resolve_path_to_device_impl(path: &str) -> Option<IoTarget> {
    PNP_MANAGER.resolve_targetio_from_symlink(path.to_string())
}

/// Get the top device from a weak DevNode reference
/// Linker seam for kernel_routing when compiled with kernel_link feature
#[unsafe(no_mangle)]
pub fn routing_get_stack_top_from_weak_impl(
    dev_node_weak: &alloc::sync::Weak<DevNode>,
) -> Option<Arc<DeviceObject>> {
    let dn = dev_node_weak.upgrade()?;
    let stack_top = dn
        .stack
        .read()
        .as_ref()
        .and_then(|s| s.get_top_device_object());
    stack_top.or_else(|| dn.get_pdo())
}

#[unsafe(no_mangle)]
pub fn routing_capture_error_backtrace_impl(output: &mut kernel_types::error::ErrorBacktrace) {
    *output = crate::error::capture();
}

// FFI exports for drivers (extern "C" ABI)
#[unsafe(no_mangle)]
pub extern "C" fn routing_resolve_path_to_device(path: &str) -> Option<IoTarget> {
    routing_resolve_path_to_device_impl(path)
}

#[unsafe(no_mangle)]
pub extern "C" fn routing_get_stack_top_from_weak(
    dev_node_weak: &alloc::sync::Weak<DevNode>,
) -> Option<Arc<DeviceObject>> {
    routing_get_stack_top_from_weak_impl(dev_node_weak)
}
