use alloc::vec::Vec;

use crate::memory::dma::PlatformIommuInfo;

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
}

pub trait TimerPlatform: Platform {
    fn wait_duration(time: core::time::Duration);
    fn calibrate_boot_timer();
    fn init_periodic_timer();
}

pub trait AddressSpacePlatform: Platform {
    type Root: Copy;

    fn init_kernel_root();
    fn kernel_root() -> Self::Root;
    fn current_root() -> Self::Root;
    unsafe fn switch_root(root: Self::Root);
    fn root_to_phys(root: Self::Root) -> u64;
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

pub fn init_boot_processor() {
    <ActivePlatform as Platform>::init_boot_processor();
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

pub fn wait_duration(time: core::time::Duration) {
    <ActivePlatform as TimerPlatform>::wait_duration(time);
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

pub fn discover_required_device_mmu() -> PlatformIommuInfo {
    <ActivePlatform as DeviceMmuPlatform>::discover_required_device_mmu()
}
