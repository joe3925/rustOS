use alloc::vec::Vec;

use crate::memory::dma::PlatformIommuInfo;
use kernel_types::arch::{PageFlags, PhysAddr as AbiPhysAddr, VirtAddr as AbiVirtAddr};
use kernel_types::irq::{MsiMessage, MsiRequest};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::pci::PciConfigAddress;
use kernel_types::status::PageMapError;

pub type ActivePlatform = crate::arch::PlatformImpl;
pub type AddressSpaceRoot = <ActivePlatform as AddressSpacePlatform>::Root;

pub trait Platform {
    const NAME: &'static str;

    fn init_boot_processor();
}

pub trait CpuPlatform: Platform {
    fn current_cpu_id() -> usize;
    fn current_logical_id() -> usize;
    fn cpu_topology_ids() -> Vec<u8>;
    fn processor_count() -> usize;
    fn init_current_cpu_local_state(logical_id: u32);
    fn start_secondary_cpus() -> bool;
    fn halt() -> !;
    fn broadcast_panic_stop();
}

pub trait InterruptPlatform: Platform {
    fn interrupts_enabled() -> bool;
    fn current_is_in_interrupt() -> bool;
    fn disable_interrupts();
    fn enable_interrupts();
    fn with_interrupts_disabled<T>(f: impl FnOnce() -> T) -> T;
    fn enable_interrupts_and_halt();
    fn end_interrupt(vector: u8);
    fn send_ipi(target_platform_cpu_id: usize, vector: u8) -> bool;
    fn compose_msi_message(request: &MsiRequest) -> Option<MsiMessage>;
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
    type Root: Copy;

    fn init_kernel_root();
    fn kernel_root() -> Self::Root;
    fn current_root() -> Self::Root;
    unsafe fn switch_root(root: Self::Root);
    fn root_to_phys(root: Self::Root) -> u64;
}

pub trait PagingPlatform: Platform {
    fn allocate_auto_kernel_range_mapped(
        size: u64,
        flags: PageFlags,
    ) -> Result<AbiVirtAddr, PageMapError>;
    fn allocate_auto_kernel_range_mapped_contiguous(
        size: u64,
        flags: PageFlags,
    ) -> Result<AbiVirtAddr, PageMapError>;
    fn allocate_kernel_range_mapped(
        base: u64,
        size: u64,
        flags: PageFlags,
    ) -> Result<AbiVirtAddr, PageMapError>;
    fn deallocate_kernel_range(addr: AbiVirtAddr, size: u64);
    fn unmap_range(virtual_addr: AbiVirtAddr, size: u64);
    fn identity_map_page(frame_addr: AbiPhysAddr, flags: PageFlags);
    fn map_physical_pages(
        phys: AbiPhysAddr,
        size: u64,
        cache: PhysicalMappingCache,
    ) -> Result<AbiVirtAddr, PageMapError>;
    fn unmap_physical_pages(base: AbiVirtAddr, size: u64) -> Result<(), PageMapError>;
    fn virt_to_phys(addr: AbiVirtAddr) -> Option<(u64, AbiPhysAddr)>;
    fn resolve_virtual_range_frame(addr: AbiVirtAddr) -> Option<(u64, AbiPhysAddr)>;
}

pub trait PciConfigPlatform: Platform {
    fn read_pci_config_u32(address: PciConfigAddress) -> Option<u32>;
    fn write_pci_config_u32(address: PciConfigAddress, value: u32) -> bool;
}

pub trait DeviceMmuPlatform: Platform {
    fn discover_required_device_mmu() -> PlatformIommuInfo;
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

pub fn end_interrupt(vector: u8) {
    <ActivePlatform as InterruptPlatform>::end_interrupt(vector);
}

pub fn send_ipi(target_platform_cpu_id: usize, vector: u8) -> bool {
    <ActivePlatform as InterruptPlatform>::send_ipi(target_platform_cpu_id, vector)
}

pub fn compose_msi_message(request: &MsiRequest) -> Option<MsiMessage> {
    <ActivePlatform as InterruptPlatform>::compose_msi_message(request)
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

pub fn init_kernel_address_space_root() {
    <ActivePlatform as AddressSpacePlatform>::init_kernel_root();
}

pub fn kernel_address_space_root() -> <ActivePlatform as AddressSpacePlatform>::Root {
    <ActivePlatform as AddressSpacePlatform>::kernel_root()
}

pub fn current_address_space_root() -> <ActivePlatform as AddressSpacePlatform>::Root {
    <ActivePlatform as AddressSpacePlatform>::current_root()
}

pub unsafe fn switch_address_space_root(root: <ActivePlatform as AddressSpacePlatform>::Root) {
    unsafe {
        <ActivePlatform as AddressSpacePlatform>::switch_root(root);
    }
}

pub fn address_space_root_phys(root: <ActivePlatform as AddressSpacePlatform>::Root) -> u64 {
    <ActivePlatform as AddressSpacePlatform>::root_to_phys(root)
}

pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageFlags,
) -> Result<AbiVirtAddr, PageMapError> {
    <ActivePlatform as PagingPlatform>::allocate_auto_kernel_range_mapped(size, flags)
}

pub fn allocate_auto_kernel_range_mapped_contiguous(
    size: u64,
    flags: PageFlags,
) -> Result<AbiVirtAddr, PageMapError> {
    <ActivePlatform as PagingPlatform>::allocate_auto_kernel_range_mapped_contiguous(size, flags)
}

pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageFlags,
) -> Result<AbiVirtAddr, PageMapError> {
    <ActivePlatform as PagingPlatform>::allocate_kernel_range_mapped(base, size, flags)
}

pub fn deallocate_kernel_range(addr: AbiVirtAddr, size: u64) {
    <ActivePlatform as PagingPlatform>::deallocate_kernel_range(addr, size);
}

pub fn unmap_range(virtual_addr: AbiVirtAddr, size: u64) {
    <ActivePlatform as PagingPlatform>::unmap_range(virtual_addr, size);
}

pub fn identity_map_page(frame_addr: AbiPhysAddr, flags: PageFlags) {
    <ActivePlatform as PagingPlatform>::identity_map_page(frame_addr, flags);
}

pub fn map_physical_pages(
    phys: AbiPhysAddr,
    size: u64,
    cache: PhysicalMappingCache,
) -> Result<AbiVirtAddr, PageMapError> {
    <ActivePlatform as PagingPlatform>::map_physical_pages(phys, size, cache)
}

pub fn unmap_physical_pages(base: AbiVirtAddr, size: u64) -> Result<(), PageMapError> {
    <ActivePlatform as PagingPlatform>::unmap_physical_pages(base, size)
}

pub fn virt_to_phys(addr: AbiVirtAddr) -> Option<(u64, AbiPhysAddr)> {
    <ActivePlatform as PagingPlatform>::virt_to_phys(addr)
}

pub fn resolve_virtual_range_frame(addr: AbiVirtAddr) -> Option<(u64, AbiPhysAddr)> {
    <ActivePlatform as PagingPlatform>::resolve_virtual_range_frame(addr)
}

pub fn read_pci_config_u32(address: PciConfigAddress) -> Option<u32> {
    <ActivePlatform as PciConfigPlatform>::read_pci_config_u32(address)
}

pub fn write_pci_config_u32(address: PciConfigAddress, value: u32) -> bool {
    <ActivePlatform as PciConfigPlatform>::write_pci_config_u32(address, value)
}

pub fn discover_required_device_mmu() -> PlatformIommuInfo {
    <ActivePlatform as DeviceMmuPlatform>::discover_required_device_mmu()
}
