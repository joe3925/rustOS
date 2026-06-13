use alloc::vec::Vec;
use core::time::Duration;

use super::memory::iommu::X86DeviceMmu;
use crate::machine::MachineInfo;
use crate::memory::device_mmu::{
    DeviceMmuDiscoveryError, DeviceMmuDiscoveryResult, DeviceMmuSystem,
};
use crate::memory::paging::types::UserVmLayout;
use crate::memory::paging::{
    KernelVirtualLayout, LocalTlbFlush, MappingSize, PagingCapabilities, ResolvedMapping,
    UnmapFrameDisposition,
};
use kernel_types::irq::{
    MsiMessage, MsiRequest, MSI_KIND_MSI, MSI_KIND_MSIX, MSI_TARGET_ANY, MSI_TARGET_PLATFORM_CPU,
};
use kernel_types::pci::PciConfigAddress;
use kernel_types::{
    arch::{PageFlags, PhysAddr as AbiPhysAddr, VirtAddr as AbiVirtAddr},
    memory::PhysicalMappingCache,
    status::PageMapError,
};
use spin::Mutex;
use x86_64::instructions::port::Port;
use x86_64::structures::paging::{PageSize, Size1GiB, Size2MiB, Size4KiB};

use crate::arch::drivers::interrupt_index::{
    apic_calibrate_ticks_per_ns_via_wait, apic_logical_ids, apic_program_period_ns, calibrate_tsc,
    current_cpu_id as x86_current_cpu_id, current_is_in_interrupt_atomic,
    get_current_logical_id as x86_current_logical_id, init_percpu_gs, send_eoi as x86_send_eoi,
    wait_duration as x86_wait_duration, wait_using_pit_50ms, ApicImpl, IpiDest, IpiKind, LocalApic,
    APIC, APIC_START_PERIOD, PICS, TSC_HZ,
};
use crate::arch::drivers::timer_driver::{NUM_CORES, PER_CORE_SWITCHES, TIMER, TIMER_TIME_SCHED};
use crate::cpu::get_cpu_info;
use crate::gdt::PER_CPU_GDT;
use crate::idt::load_idt;
use crate::platform::{
    AddressSpacePlatform, CpuPlatform, DeviceMmuPlatform, InterruptPlatform,
    PageTableFrameAllocator, PagingPlatform, PciConfigPlatform, Platform, TimerPlatform,
};
use crate::println;
use crate::structs::stopwatch::Stopwatch;
use crate::syscalls::syscall::syscall_init;

pub struct X86Platform;

const PCI_CFG1_ADDR: u16 = 0xCF8;
const PCI_CFG1_DATA: u16 = 0xCFC;
static PCI_CFG1_LOCK: Mutex<()> = Mutex::new(());

#[inline]
fn pci_cfg1_addr(address: PciConfigAddress) -> Option<u32> {
    if address.segment != 0
        || address.device >= 32
        || address.function >= 8
        || address.offset > 0xFFC
    {
        return None;
    }

    Some(
        0x8000_0000
            | ((address.bus as u32) << 16)
            | ((address.device as u32) << 11)
            | ((address.function as u32) << 8)
            | ((address.aligned_u32_offset() as u32) & !3),
    )
}

impl Platform for X86Platform {
    const NAME: &'static str = "x86_64";

    fn init_boot_processor() {
        load_idt();
        Self::init_kernel_root();
        unsafe {
            PER_CPU_GDT.lock().init_gdt();
            PICS.lock().initialize();
        }
        Self::disable_interrupts();
        syscall_init();
    }
}

impl CpuPlatform for X86Platform {
    fn current_cpu_id() -> usize {
        x86_current_cpu_id()
    }

    fn current_logical_id() -> usize {
        x86_current_logical_id() as usize
    }

    fn cpu_topology_ids() -> Vec<u8> {
        apic_logical_ids()
    }

    fn processor_count() -> usize {
        NUM_CORES.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn init_current_cpu_local_state(logical_id: u32) {
        init_percpu_gs(logical_id);
    }

    fn start_secondary_cpus() -> bool {
        let apic_time = Stopwatch::start();
        let started = match ApicImpl::init_apic_full() {
            Ok(_) => {
                APIC.lock().as_ref().unwrap().start_aps();
                true
            }
            Err(err) => {
                println!("APIC transition failed {}!", err.to_str());
                false
            }
        };

        if started {
            println!(
                "APIC init and AP start successful in {} s!",
                apic_time.elapsed_sec()
            );
        }

        started
    }

    fn halt() -> ! {
        unsafe {
            loop {
                core::arch::asm!("hlt;", options(nomem, nostack, preserves_flags));
            }
        }
    }

    fn broadcast_panic_stop() {
        unsafe {
            if let Some(a) = APIC.lock().as_ref() {
                a.lapic.send_ipi(IpiDest::AllExcludingSelf, IpiKind::Nmi);
            }
        }
    }
}

impl InterruptPlatform for X86Platform {
    fn interrupts_enabled() -> bool {
        x86_64::instructions::interrupts::are_enabled()
    }

    fn current_is_in_interrupt() -> bool {
        current_is_in_interrupt_atomic().load(core::sync::atomic::Ordering::Relaxed)
    }

    fn disable_interrupts() {
        x86_64::instructions::interrupts::disable();
    }

    fn enable_interrupts() {
        x86_64::instructions::interrupts::enable();
    }

    fn with_interrupts_disabled<T>(f: impl FnOnce() -> T) -> T {
        x86_64::instructions::interrupts::without_interrupts(f)
    }

    fn enable_interrupts_and_halt() {
        x86_64::instructions::interrupts::enable_and_hlt();
    }

    fn end_interrupt(vector: u8) {
        x86_send_eoi(vector);
    }

    fn send_ipi(target_platform_cpu_id: usize, vector: u8) -> bool {
        if target_platform_cpu_id > u8::MAX as usize {
            return false;
        }

        let in_interrupt =
            current_is_in_interrupt_atomic().load(core::sync::atomic::Ordering::Acquire);

        if in_interrupt {
            let Some(apic) = APIC.try_lock() else {
                return false;
            };

            if let Some(a) = apic.as_ref() {
                unsafe {
                    a.lapic.send_ipi(
                        IpiDest::ApicId(target_platform_cpu_id as u8),
                        IpiKind::Fixed { vector },
                    );
                }
                return true;
            }

            return false;
        }

        unsafe {
            if let Some(a) = APIC.lock().as_ref() {
                a.lapic.send_ipi(
                    IpiDest::ApicId(target_platform_cpu_id as u8),
                    IpiKind::Fixed { vector },
                );
                return true;
            }
        }

        false
    }

    fn compose_msi_message(request: &MsiRequest) -> Option<MsiMessage> {
        match request.kind {
            MSI_KIND_MSI | MSI_KIND_MSIX => {}
            _ => return None,
        }

        let destination = match request.target.mode {
            MSI_TARGET_ANY => x86_current_logical_id() as u32,
            MSI_TARGET_PLATFORM_CPU => request.target.platform_cpu_id,
            _ => return None,
        };

        if destination > u8::MAX as u32 {
            return None;
        }

        let address = 0xFEE0_0000u64 | ((destination as u64) << 12);
        let data = request.vector as u32;

        Some(MsiMessage::new(address, data))
    }
}

impl TimerPlatform for X86Platform {
    fn wait_duration(time: Duration) {
        x86_wait_duration(time);
    }

    fn calibrate_boot_timer() {
        let tsc_start = crate::cpu::get_cycles();
        wait_using_pit_50ms();
        let tsc_end = crate::cpu::get_cycles();
        calibrate_tsc(tsc_start, tsc_end, 50);
    }

    fn init_periodic_timer() {
        apic_calibrate_ticks_per_ns_via_wait(10);
        apic_program_period_ns(APIC_START_PERIOD);
    }

    fn cycle_counter() -> u64 {
        crate::cpu::get_cycles()
    }

    fn ordered_cycle_counter() -> u64 {
        crate::cpu::get_ordered_cycles()
    }

    fn cycle_counter_frequency_hz() -> u64 {
        TSC_HZ.load(core::sync::atomic::Ordering::SeqCst)
    }

    fn timer_tick_count() -> usize {
        TIMER.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn scheduler_time_ns(cpu_id: usize) -> u64 {
        unsafe { TIMER_TIME_SCHED.iter() }
            .nth(cpu_id)
            .map(|value| value.load(core::sync::atomic::Ordering::SeqCst) as u64)
            .unwrap_or(0)
    }

    fn context_switch_count(cpu_id: usize) -> u64 {
        unsafe { PER_CORE_SWITCHES.iter() }
            .nth(cpu_id)
            .map(|value| value.load(core::sync::atomic::Ordering::SeqCst) as u64)
            .unwrap_or(0)
    }
}

impl AddressSpacePlatform for X86Platform {
    type Root = crate::arch::memory::paging::address_space::Root;

    fn init_kernel_root() {
        crate::arch::memory::paging::address_space::init_kernel_root();
    }

    fn kernel_root() -> Self::Root {
        crate::arch::memory::paging::address_space::kernel_root()
    }

    fn current_root() -> Self::Root {
        crate::arch::memory::paging::address_space::current_root()
    }

    unsafe fn switch_root(root: Self::Root) {
        unsafe { crate::arch::memory::paging::address_space::switch_root(root) }
    }

    fn root_to_phys(root: Self::Root) -> AbiPhysAddr {
        crate::arch::memory::paging::address_space::root_to_phys(root)
    }

    fn create_user_root<A: PageTableFrameAllocator>(
        allocator: &mut A,
    ) -> Result<Self::Root, PageMapError> {
        crate::arch::memory::paging::address_space::create_user_root(allocator)
    }

    unsafe fn destroy_user_root<A: PageTableFrameAllocator>(
        root: Self::Root,
        allocator: &mut A,
    ) -> Result<(), PageMapError> {
        unsafe { crate::arch::memory::paging::address_space::destroy_user_root(root, allocator) }
    }
}

impl PagingPlatform for X86Platform {
    fn paging_capabilities() -> PagingCapabilities {
        let supports_1g = get_cpu_info()
            .get_extended_processor_and_feature_identifiers()
            .is_some_and(|features| features.has_1gib_pages());

        PagingCapabilities {
            base_page_size: Size4KiB::SIZE,
            leaf_mapping_sizes: if supports_1g {
                &X86_MAPPING_SIZES_WITH_1G
            } else {
                &X86_MAPPING_SIZES_WITHOUT_1G
            },
            supports_global_mappings: true,
            supports_execute_disable: true,
            supports_cache_attributes: true,
        }
    }
    fn user_virtual_layout() -> crate::memory::paging::types::UserVmLayout {
        const USER_VA_START: u64 = 0x0000_0000_0000_0000;
        const USER_VA_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

        UserVmLayout {
            start: USER_VA_START + Size4KiB::SIZE,
            end: USER_VA_END_EXCLUSIVE,
            base_page_size: Size4KiB::SIZE,
            stack_alignment: 16,
        }
    }
    fn kernel_virtual_layout() -> KernelVirtualLayout {
        crate::arch::memory::paging::layout::kernel_virtual_layout()
    }

    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: AbiVirtAddr,
        phys: AbiPhysAddr,
        size: MappingSize,
        flags: PageFlags,
        cache: Option<PhysicalMappingCache>,
        flush: LocalTlbFlush,
    ) -> Result<(), PageMapError> {
        unsafe {
            crate::arch::memory::paging::mapper::map_leaf(
                allocator, virt, phys, size, flags, cache, flush,
            )
        }
    }

    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: AbiVirtAddr,
        size: MappingSize,
        disposition: UnmapFrameDisposition,
        flush: LocalTlbFlush,
    ) -> Result<Option<AbiPhysAddr>, PageMapError> {
        unsafe {
            crate::arch::memory::paging::mapper::unmap_leaf(
                allocator,
                virt,
                size,
                disposition,
                flush,
            )
        }
    }

    fn resolve_mapping(virt: AbiVirtAddr) -> Option<ResolvedMapping> {
        crate::arch::memory::paging::mapper::resolve_mapping(virt)
    }

    fn local_flush_tlb_all() {
        crate::arch::memory::paging::tlb::local_flush_tlb_all();
    }

    fn local_flush_tlb_range(start: AbiVirtAddr, size: u64, stride: u64) {
        crate::arch::memory::paging::tlb::local_flush_tlb_range(start, size, stride);
    }

    fn broadcast_tlb_shootdown() -> bool {
        crate::arch::memory::paging::tlb::broadcast_tlb_shootdown()
    }
}

const X86_MAPPING_SIZES_WITH_1G: [MappingSize; 3] = [
    MappingSize {
        bytes: Size1GiB::SIZE,
    },
    MappingSize {
        bytes: Size2MiB::SIZE,
    },
    MappingSize {
        bytes: Size4KiB::SIZE,
    },
];

const X86_MAPPING_SIZES_WITHOUT_1G: [MappingSize; 2] = [
    MappingSize {
        bytes: Size2MiB::SIZE,
    },
    MappingSize {
        bytes: Size4KiB::SIZE,
    },
];

impl PciConfigPlatform for X86Platform {
    fn read_pci_config_u32(address: PciConfigAddress) -> Option<u32> {
        let cfg_addr = pci_cfg1_addr(address)?;
        let _guard = PCI_CFG1_LOCK.lock();

        unsafe {
            let mut addr = Port::<u32>::new(PCI_CFG1_ADDR);
            let mut data = Port::<u32>::new(PCI_CFG1_DATA);
            addr.write(cfg_addr);
            Some(data.read())
        }
    }

    fn write_pci_config_u32(address: PciConfigAddress, value: u32) -> bool {
        let Some(cfg_addr) = pci_cfg1_addr(address) else {
            return false;
        };
        let _guard = PCI_CFG1_LOCK.lock();

        unsafe {
            let mut addr = Port::<u32>::new(PCI_CFG1_ADDR);
            let mut data = Port::<u32>::new(PCI_CFG1_DATA);
            addr.write(cfg_addr);
            data.write(value);
        }

        true
    }
}

impl DeviceMmuPlatform for X86Platform {
    fn discover_device_mmu(
        machine: &MachineInfo,
    ) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>> {
        let Some(tables) = machine.firmware().acpi_tables() else {
            return Ok(None);
        };

        let Some(backend) = X86DeviceMmu::try_init_from_acpi(tables.as_ref())? else {
            return Ok(None);
        };

        Ok(Some(DeviceMmuSystem::from_backend(backend)))
    }
}
