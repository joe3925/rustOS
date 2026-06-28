use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::drivers::ACPI::ACPIImpl;
use crate::machine::MachineInfo;
use crate::machine::MachineInterruptInfo;
use crate::memory::device_mmu::{
    DeviceMmuDiscoveryError, DeviceMmuDiscoveryResult, DeviceMmuSystem,
};
use crate::memory::paging::types::UserVmLayout;
use acpi::AcpiTables;
use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::irq::{MsiMessage, MsiRequest};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::pci::PciConfigAddress;
use kernel_types::runtime::BlockOnThreadState;
use kernel_types::status::PageMapError;

use crate::memory::paging::{
    KernelVirtualLayout, LocalTlbFlush, MappingSize, PagingCapabilities, ResolvedMapping,
    UnmapFrameDisposition,
};

pub type ActivePlatform = crate::arch::PlatformImpl;

pub trait Platform {
    type BootArchInfo: kernel_abi::BootArchInfo;

    const NAME: &'static str;
    const KERNEL_IMAGE_BASE: u64;

    fn init_boot_processor();
}

pub trait CpuPlatform: Platform {
    const MAX_CPUS: usize;

    fn current_cpu_id() -> usize;
    fn current_logical_id() -> usize;
    fn cpu_topology_ids() -> Vec<u8>;
    fn processor_count() -> usize;
    fn init_current_cpu_local_state(logical_id: u32);
    fn start_secondary_cpus() -> bool;
    fn halt() -> !;
    fn broadcast_panic_stop();
}

pub trait InterruptPlatform: CpuPlatform {
    type InterruptFrame;

    const DYNAMIC_VECTOR_START: u8;
    const DYNAMIC_VECTOR_END: u8;

    fn scheduler_ipi_vector() -> u8;
    fn timer_interrupt_vector() -> u8;
    fn tlb_shootdown_vector() -> u8;

    fn interrupts_enabled() -> bool;
    fn current_is_in_interrupt() -> bool;
    fn disable_interrupts();
    fn enable_interrupts();
    fn with_interrupts_disabled<T>(f: impl FnOnce() -> T) -> T;
    fn enable_interrupts_and_halt();
    fn end_interrupt(vector: u8);
    fn send_ipi(target_platform_cpu_id: usize, vector: u8) -> bool;
    fn compose_msi_message(request: &MsiRequest) -> Option<MsiMessage>;
    fn is_reserved_vector(vector: u8) -> bool;

    fn is_dynamic_vector(vector: u8) -> bool {
        vector >= Self::DYNAMIC_VECTOR_START
            && vector <= Self::DYNAMIC_VECTOR_END
            && !Self::is_reserved_vector(vector)
    }

    fn gsi_to_vector(gsi: u8) -> Option<u8>;
    fn vector_to_gsi(vector: u8) -> Option<u8>;
    fn unmask_gsi_any_cpu(gsi: u8, vector: u8);
    fn enter_interrupt() -> bool;
    fn leave_interrupt(was_in_interrupt: bool);
}

pub trait TimerPlatform: Platform {
    fn wait_duration(time: core::time::Duration);
    fn calibrate_boot_timer();
    fn init_periodic_timer();
    fn cycle_counter() -> u64;
    fn ordered_cycle_counter() -> u64;
    fn cycle_counter_frequency_hz() -> u64;
    fn timer_tick_count() -> usize;
    fn scheduler_time_ns(cpu_id: usize) -> u64;
    fn context_switch_count(cpu_id: usize) -> u64;
}

pub trait AddressSpacePlatform: Platform {
    type Root: Copy + Eq;

    fn init_kernel_root();
    fn kernel_root() -> Self::Root;
    fn current_root() -> Self::Root;

    unsafe fn switch_root(root: Self::Root);

    fn root_to_phys(root: Self::Root) -> PhysAddr;

    fn create_user_root<A: PageTableFrameAllocator>(
        allocator: &mut A,
    ) -> Result<Self::Root, PageMapError>;

    unsafe fn destroy_user_root<A: PageTableFrameAllocator>(
        root: Self::Root,
        allocator: &mut A,
    ) -> Result<(), PageMapError>;
}

pub trait PageTableFrameAllocator {
    fn allocate_page_table_frame(&mut self) -> Option<PhysAddr>;
    fn free_page_table_frame(&mut self, phys: PhysAddr);
}

pub trait PagingPlatform: AddressSpacePlatform {
    fn paging_capabilities() -> PagingCapabilities;
    fn kernel_virtual_layout() -> KernelVirtualLayout;
    fn user_virtual_layout() -> UserVmLayout;
    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: VirtAddr,
        phys: PhysAddr,
        size: MappingSize,
        flags: PageFlags,
        cache: Option<PhysicalMappingCache>,
        flush: LocalTlbFlush,
    ) -> Result<(), PageMapError>;

    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: VirtAddr,
        size: MappingSize,
        disposition: UnmapFrameDisposition,
        flush: LocalTlbFlush,
    ) -> Result<Option<PhysAddr>, PageMapError>;

    fn resolve_mapping(virt: VirtAddr) -> Option<ResolvedMapping>;

    fn local_flush_tlb_all();
    fn local_flush_tlb_range(start: VirtAddr, size: u64, stride: u64);

    fn broadcast_tlb_shootdown() -> bool;
}

pub trait PciConfigPlatform: Platform {
    fn read_pci_config_u32(address: PciConfigAddress) -> Option<u32>;
    fn write_pci_config_u32(address: PciConfigAddress, value: u32) -> bool;
}

pub trait DeviceMmuPlatform: Platform {
    fn discover_device_mmu(
        machine: &MachineInfo,
    ) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>>;
}

pub trait MachinePlatform: Platform {
    fn discover_interrupt_info_from_acpi(
        tables: &AcpiTables<ACPIImpl>,
    ) -> Option<MachineInterruptInfo>;
}

pub trait TaskPlatform: CpuPlatform {
    type TaskEntry: Copy + Send + Sync + 'static;
    type TaskContext: Copy + Debug + Send + Sync + 'static;
    type FpuState: Default + Debug + Send + Sync + 'static;
    type KernelTls: Debug + Send + Sync + 'static;

    fn idle_task_entry() -> Self::TaskEntry;
    fn new_user_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext;
    fn new_kernel_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext;
    fn mark_idle_task_context(context: &mut Self::TaskContext);
    unsafe fn restore_task_context(context: &Self::TaskContext, target: *mut Self::TaskContext);

    fn save_fpu_state(state: &mut Self::FpuState);
    fn restore_fpu_state(state: &Self::FpuState);

    fn new_kernel_tls() -> Option<Self::KernelTls>;
    fn kernel_tls_thread_pointer(tls: &Self::KernelTls) -> u64;
    unsafe fn activate_kernel_tls(thread_pointer: u64);
    fn ensure_current_thread_runtime_initialized();
    fn current_block_on_thread_state() -> Arc<BlockOnThreadState>;
    fn request_task_yield();
}

pub trait DebugPlatform: Platform {
    fn breakpoint();
    fn fatal_reset() -> !;
}

pub const MAX_CPUS: usize = <ActivePlatform as CpuPlatform>::MAX_CPUS;

pub fn user_vm_layout() -> UserVmLayout {
    <ActivePlatform as PagingPlatform>::user_virtual_layout()
}
pub fn current_cpu_id() -> usize {
    <ActivePlatform as CpuPlatform>::current_cpu_id()
}

pub fn current_logical_id() -> usize {
    <ActivePlatform as CpuPlatform>::current_logical_id()
}

pub fn cpu_topology_ids() -> Vec<u8> {
    <ActivePlatform as CpuPlatform>::cpu_topology_ids()
}

pub fn processor_count() -> usize {
    <ActivePlatform as CpuPlatform>::processor_count()
}

pub fn init_boot_processor() {
    <ActivePlatform as Platform>::init_boot_processor();
}

pub fn init_current_cpu_local_state(logical_id: u32) {
    <ActivePlatform as CpuPlatform>::init_current_cpu_local_state(logical_id);
}

pub fn start_secondary_cpus() -> bool {
    <ActivePlatform as CpuPlatform>::start_secondary_cpus()
}

pub fn halt() -> ! {
    <ActivePlatform as CpuPlatform>::halt()
}

pub fn broadcast_panic_stop() {
    <ActivePlatform as CpuPlatform>::broadcast_panic_stop();
}

pub fn disable_interrupts() {
    <ActivePlatform as InterruptPlatform>::disable_interrupts();
}

pub fn interrupts_enabled() -> bool {
    <ActivePlatform as InterruptPlatform>::interrupts_enabled()
}

pub fn current_is_in_interrupt() -> bool {
    <ActivePlatform as InterruptPlatform>::current_is_in_interrupt()
}

pub fn enable_interrupts() {
    <ActivePlatform as InterruptPlatform>::enable_interrupts();
}

pub fn with_interrupts_disabled<T>(f: impl FnOnce() -> T) -> T {
    <ActivePlatform as InterruptPlatform>::with_interrupts_disabled(f)
}

pub fn enable_interrupts_and_halt() {
    <ActivePlatform as InterruptPlatform>::enable_interrupts_and_halt();
}

pub fn scheduler_ipi_vector() -> u8 {
    <ActivePlatform as InterruptPlatform>::scheduler_ipi_vector()
}

pub fn timer_interrupt_vector() -> u8 {
    <ActivePlatform as InterruptPlatform>::timer_interrupt_vector()
}

pub fn tlb_shootdown_vector() -> u8 {
    <ActivePlatform as InterruptPlatform>::tlb_shootdown_vector()
}

pub fn end_interrupt(vector: u8) {
    <ActivePlatform as InterruptPlatform>::end_interrupt(vector);
}

pub fn send_ipi(target_platform_cpu_id: usize, vector: u8) -> bool {
    <ActivePlatform as InterruptPlatform>::send_ipi(target_platform_cpu_id, vector)
}

pub fn compose_msi_message(request: &MsiRequest) -> Option<MsiMessage> {
    <ActivePlatform as InterruptPlatform>::compose_msi_message(request)
}

pub fn is_reserved_vector(vector: u8) -> bool {
    <ActivePlatform as InterruptPlatform>::is_reserved_vector(vector)
}

pub fn is_dynamic_vector(vector: u8) -> bool {
    <ActivePlatform as InterruptPlatform>::is_dynamic_vector(vector)
}

pub fn dynamic_vector_range() -> core::ops::RangeInclusive<u8> {
    <ActivePlatform as InterruptPlatform>::DYNAMIC_VECTOR_START
        ..=<ActivePlatform as InterruptPlatform>::DYNAMIC_VECTOR_END
}

pub fn gsi_to_vector(gsi: u8) -> Option<u8> {
    <ActivePlatform as InterruptPlatform>::gsi_to_vector(gsi)
}

pub fn vector_to_gsi(vector: u8) -> Option<u8> {
    <ActivePlatform as InterruptPlatform>::vector_to_gsi(vector)
}

pub fn unmask_gsi_any_cpu(gsi: u8, vector: u8) {
    <ActivePlatform as InterruptPlatform>::unmask_gsi_any_cpu(gsi, vector);
}

pub fn enter_interrupt() -> bool {
    <ActivePlatform as InterruptPlatform>::enter_interrupt()
}

pub fn leave_interrupt(was_in_interrupt: bool) {
    <ActivePlatform as InterruptPlatform>::leave_interrupt(was_in_interrupt);
}

pub fn wait_duration(time: core::time::Duration) {
    <ActivePlatform as TimerPlatform>::wait_duration(time);
}

pub fn calibrate_boot_timer() {
    <ActivePlatform as TimerPlatform>::calibrate_boot_timer();
}

pub fn init_periodic_timer() {
    <ActivePlatform as TimerPlatform>::init_periodic_timer();
}

pub fn cycle_counter() -> u64 {
    <ActivePlatform as TimerPlatform>::cycle_counter()
}

pub fn ordered_cycle_counter() -> u64 {
    <ActivePlatform as TimerPlatform>::ordered_cycle_counter()
}

pub fn cycle_counter_frequency_hz() -> u64 {
    <ActivePlatform as TimerPlatform>::cycle_counter_frequency_hz()
}

pub fn timer_tick_count() -> usize {
    <ActivePlatform as TimerPlatform>::timer_tick_count()
}

pub fn scheduler_time_ns(cpu_id: usize) -> u64 {
    <ActivePlatform as TimerPlatform>::scheduler_time_ns(cpu_id)
}

pub fn context_switch_count(cpu_id: usize) -> u64 {
    <ActivePlatform as TimerPlatform>::context_switch_count(cpu_id)
}

pub fn read_pci_config_u32(address: PciConfigAddress) -> Option<u32> {
    <ActivePlatform as PciConfigPlatform>::read_pci_config_u32(address)
}

pub fn write_pci_config_u32(address: PciConfigAddress, value: u32) -> bool {
    <ActivePlatform as PciConfigPlatform>::write_pci_config_u32(address, value)
}

pub fn discover_device_mmu(
    machine: &MachineInfo,
) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>> {
    <ActivePlatform as DeviceMmuPlatform>::discover_device_mmu(machine)
}

pub fn discover_interrupt_info_from_acpi(
    tables: &AcpiTables<ACPIImpl>,
) -> Option<MachineInterruptInfo> {
    <ActivePlatform as MachinePlatform>::discover_interrupt_info_from_acpi(tables)
}

pub fn discover_required_device_mmu(machine: &MachineInfo) -> DeviceMmuSystem {
    match discover_device_mmu(machine) {
        Ok(Some(device_mmu)) => device_mmu,
        Ok(None) => {
            panic!("mandatory device-MMU policy: no device-MMU was discovered for this platform")
        }
        Err(DeviceMmuDiscoveryError::FirmwareUnavailable) => {
            panic!("mandatory device-MMU policy: required firmware tables were unavailable")
        }
        Err(DeviceMmuDiscoveryError::NotPresent) => {
            panic!("mandatory device-MMU policy: device-MMU is not present")
        }
        Err(DeviceMmuDiscoveryError::Unsupported) => {
            panic!("mandatory device-MMU policy: discovered device-MMU is unsupported")
        }
        Err(DeviceMmuDiscoveryError::MalformedFirmware) => {
            panic!("mandatory device-MMU policy: firmware device-MMU tables are malformed")
        }
        Err(DeviceMmuDiscoveryError::Backend(err)) => {
            panic!(
                "mandatory device-MMU policy: device-MMU backend initialization failed: {:?}",
                err
            )
        }
    }
}

pub fn idle_task_entry() -> <ActivePlatform as TaskPlatform>::TaskEntry {
    <ActivePlatform as TaskPlatform>::idle_task_entry()
}

pub fn new_user_task_context(
    entry_point: <ActivePlatform as TaskPlatform>::TaskEntry,
    context: usize,
    stack_top: VirtAddr,
) -> <ActivePlatform as TaskPlatform>::TaskContext {
    <ActivePlatform as TaskPlatform>::new_user_task_context(entry_point, context, stack_top)
}

pub fn new_kernel_task_context(
    entry_point: <ActivePlatform as TaskPlatform>::TaskEntry,
    context: usize,
    stack_top: VirtAddr,
) -> <ActivePlatform as TaskPlatform>::TaskContext {
    <ActivePlatform as TaskPlatform>::new_kernel_task_context(entry_point, context, stack_top)
}

pub fn mark_idle_task_context(context: &mut <ActivePlatform as TaskPlatform>::TaskContext) {
    <ActivePlatform as TaskPlatform>::mark_idle_task_context(context);
}

pub unsafe fn restore_task_context(
    context: &<ActivePlatform as TaskPlatform>::TaskContext,
    target: *mut <ActivePlatform as TaskPlatform>::TaskContext,
) {
    unsafe { <ActivePlatform as TaskPlatform>::restore_task_context(context, target) };
}

pub fn save_fpu_state(state: &mut <ActivePlatform as TaskPlatform>::FpuState) {
    <ActivePlatform as TaskPlatform>::save_fpu_state(state);
}

pub fn restore_fpu_state(state: &<ActivePlatform as TaskPlatform>::FpuState) {
    <ActivePlatform as TaskPlatform>::restore_fpu_state(state);
}

pub fn new_kernel_tls() -> Option<<ActivePlatform as TaskPlatform>::KernelTls> {
    <ActivePlatform as TaskPlatform>::new_kernel_tls()
}

pub fn kernel_tls_thread_pointer(tls: &<ActivePlatform as TaskPlatform>::KernelTls) -> u64 {
    <ActivePlatform as TaskPlatform>::kernel_tls_thread_pointer(tls)
}

pub unsafe fn activate_kernel_tls(thread_pointer: u64) {
    unsafe { <ActivePlatform as TaskPlatform>::activate_kernel_tls(thread_pointer) };
}

pub fn ensure_current_thread_runtime_initialized() {
    <ActivePlatform as TaskPlatform>::ensure_current_thread_runtime_initialized();
}

pub fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
    <ActivePlatform as TaskPlatform>::current_block_on_thread_state()
}

pub fn request_task_yield() {
    <ActivePlatform as TaskPlatform>::request_task_yield();
}

pub fn breakpoint() {
    <ActivePlatform as DebugPlatform>::breakpoint();
}

pub fn fatal_reset() -> ! {
    <ActivePlatform as DebugPlatform>::fatal_reset()
}
