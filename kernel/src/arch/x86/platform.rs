use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::memory::iommu::X86DeviceMmu;
use super::scheduling::state::{FpuState, State};
use super::scheduling::{idle_task, task_return_trampoline, TaskEntry};
use crate::drivers::ACPI::ACPIImpl;
use crate::machine::MachineInfo;
use crate::machine::MachineInterruptInfo;
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
use kernel_types::runtime::BlockOnThreadState;
use kernel_types::{
    arch::{PageFlags, PhysAddr, VirtAddr},
    memory::PhysicalMappingCache,
    status::PageMapError,
};
use spin::Mutex;
use x86_64::instructions::port::Port;
use x86_64::structures::paging::{PageSize, Size1GiB, Size2MiB, Size4KiB};

use super::cpu::get_cpu_info;
use super::drivers::interrupt_index::{
    apic_calibrate_ticks_per_ns_via_wait, apic_logical_ids, apic_program_period_ns, calibrate_tsc,
    current_cpu_id as x86_current_cpu_id, current_is_in_interrupt_atomic,
    get_current_logical_id as x86_current_logical_id, init_percpu_gs, send_eoi as x86_send_eoi,
    wait_duration as x86_wait_duration, wait_using_pit_50ms, ApicImpl, IpiDest, IpiKind, LocalApic,
    APIC, APIC_START_PERIOD, PICS, TSC_HZ,
};
use super::drivers::timer_driver::{NUM_CORES, PER_CORE_SWITCHES, TIMER, TIMER_TIME_SCHED};
use super::gdt::PER_CPU_GDT;
use super::idt::load_idt;
use crate::platform::{
    AddressSpacePlatform, CpuPlatform, DebugPlatform, DeviceMmuPlatform, InterruptPlatform,
    MachinePlatform, PageTableFrameAllocator, PagingPlatform, PciConfigPlatform, Platform,
    TaskPlatform, TimerPlatform,
};
use crate::println;
use crate::structs::stopwatch::Stopwatch;
use acpi::AcpiTables;
use x86_64::structures::idt::InterruptStackFrame;

pub struct X86Platform;

const C_SHADOW_SPACE_BYTES: u64 = 32;
const RETURN_ADDRESS_BYTES: u64 = 8;
const C_ENTRY_FRAME_BYTES: u64 = RETURN_ADDRESS_BYTES + C_SHADOW_SPACE_BYTES;
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
    type BootArchInfo = kernel_abi::arch::X86BootArchInfo;

    const NAME: &'static str = "x86_64";
    const KERNEL_IMAGE_BASE: u64 = kernel_abi::arch::KERNEL_PE_BASE;

    fn init_boot_processor() {
        load_idt();
        Self::init_kernel_root();
        unsafe {
            PER_CPU_GDT.lock().init_gdt();
            PICS.lock().initialize();
        }
        Self::disable_interrupts();
        super::syscalls::syscall::syscall_init();
        super::debug_meta::init_debug_metadata_transport();
    }
}

impl CpuPlatform for X86Platform {
    const MAX_CPUS: usize = super::MAX_CPUS;

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
                super::debug_meta::poll_rx_once();
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
    type InterruptFrame = InterruptStackFrame;

    const DYNAMIC_VECTOR_START: u8 = super::idt::DYNAMIC_VECTOR_START;
    const DYNAMIC_VECTOR_END: u8 = super::idt::DYNAMIC_VECTOR_END;

    fn scheduler_ipi_vector() -> u8 {
        super::idt::SCHED_IPI_VECTOR
    }

    fn timer_interrupt_vector() -> u8 {
        super::drivers::interrupt_index::InterruptIndex::Timer.as_u8()
    }

    fn tlb_shootdown_vector() -> u8 {
        super::idt::TLB_FLUSH_VECTOR
    }

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

    fn is_reserved_vector(vector: u8) -> bool {
        vector == super::idt::SYSCALL_VECTOR
    }

    fn gsi_to_vector(gsi: u8) -> Option<u8> {
        if gsi < super::idt::MAX_GSI {
            Some(super::drivers::interrupt_index::InterruptIndex::Timer.as_u8() + gsi)
        } else {
            None
        }
    }

    fn vector_to_gsi(vector: u8) -> Option<u8> {
        let base = super::drivers::interrupt_index::InterruptIndex::Timer.as_u8();
        let gsi = vector.wrapping_sub(base);

        if gsi < super::idt::MAX_GSI {
            Some(gsi)
        } else {
            None
        }
    }

    fn unmask_gsi_any_cpu(gsi: u8, vector: u8) {
        APIC.lock().as_ref().unwrap().ioapic.unmask_irq_any_cpu(
            gsi,
            vector,
            x86_current_logical_id(),
        );
    }

    fn enter_interrupt() -> bool {
        current_is_in_interrupt_atomic().swap(true, core::sync::atomic::Ordering::AcqRel)
    }

    fn leave_interrupt(was_in_interrupt: bool) {
        if !was_in_interrupt {
            current_is_in_interrupt_atomic().store(false, core::sync::atomic::Ordering::Release);
        }
    }
}

impl TimerPlatform for X86Platform {
    fn wait_duration(time: Duration) {
        x86_wait_duration(time);
    }

    fn calibrate_boot_timer() {
        let tsc_start = super::cpu::get_cycles();
        wait_using_pit_50ms();
        let tsc_end = super::cpu::get_cycles();
        calibrate_tsc(tsc_start, tsc_end, 50);
    }

    fn init_periodic_timer() {
        apic_calibrate_ticks_per_ns_via_wait(10);
        apic_program_period_ns(APIC_START_PERIOD);
    }

    fn cycle_counter() -> u64 {
        super::cpu::get_cycles()
    }

    fn ordered_cycle_counter() -> u64 {
        super::cpu::get_ordered_cycles()
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
    type Root = super::memory::paging::address_space::Root;

    fn init_kernel_root() {
        super::memory::paging::address_space::init_kernel_root();
    }

    fn kernel_root() -> Self::Root {
        super::memory::paging::address_space::kernel_root()
    }

    fn current_root() -> Self::Root {
        super::memory::paging::address_space::current_root()
    }

    unsafe fn switch_root(root: Self::Root) {
        unsafe { super::memory::paging::address_space::switch_root(root) }
    }

    fn root_to_phys(root: Self::Root) -> PhysAddr {
        super::memory::paging::address_space::root_to_phys(root)
    }

    fn create_user_root<A: PageTableFrameAllocator>(
        allocator: &mut A,
    ) -> Result<Self::Root, PageMapError> {
        super::memory::paging::address_space::create_user_root(allocator)
    }

    unsafe fn destroy_user_root<A: PageTableFrameAllocator>(
        root: Self::Root,
        allocator: &mut A,
    ) -> Result<(), PageMapError> {
        unsafe { super::memory::paging::address_space::destroy_user_root(root, allocator) }
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
        super::memory::paging::layout::kernel_virtual_layout()
    }

    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: VirtAddr,
        phys: PhysAddr,
        size: MappingSize,
        flags: PageFlags,
        cache: Option<PhysicalMappingCache>,
        flush: LocalTlbFlush,
    ) -> Result<(), PageMapError> {
        unsafe {
            super::memory::paging::mapper::map_leaf(
                allocator, virt, phys, size, flags, cache, flush,
            )
        }
    }

    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: VirtAddr,
        size: MappingSize,
        disposition: UnmapFrameDisposition,
        flush: LocalTlbFlush,
    ) -> Result<Option<PhysAddr>, PageMapError> {
        unsafe {
            super::memory::paging::mapper::unmap_leaf(allocator, virt, size, disposition, flush)
        }
    }

    fn resolve_mapping(virt: VirtAddr) -> Option<ResolvedMapping> {
        super::memory::paging::mapper::resolve_mapping(virt)
    }

    fn local_flush_tlb_all() {
        super::memory::paging::tlb::local_flush_tlb_all();
    }

    fn local_flush_tlb_range(start: VirtAddr, size: u64, stride: u64) {
        super::memory::paging::tlb::local_flush_tlb_range(start, size, stride);
    }

    fn broadcast_tlb_shootdown() -> bool {
        super::memory::paging::tlb::broadcast_tlb_shootdown()
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

impl MachinePlatform for X86Platform {
    fn discover_interrupt_info_from_acpi(
        tables: &AcpiTables<ACPIImpl>,
    ) -> Option<MachineInterruptInfo> {
        super::machine::discover_interrupt_info_from_acpi(tables)
    }
}

impl TaskPlatform for X86Platform {
    type TaskEntry = TaskEntry;
    type TaskContext = State;
    type FpuState = FpuState;
    type KernelTls = super::scheduling::tls::KernelTls;

    fn idle_task_entry() -> Self::TaskEntry {
        idle_task
    }

    fn new_user_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext {
        let gdt = PER_CPU_GDT.lock();
        let platform_cpu_id = Self::current_logical_id();
        let mut state = State::new(0);
        state.rip = entry_point as u64;
        state.rcx = context as u64;
        state.rsp = initial_c_entry_rsp(stack_top.as_u64());
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = task_return_trampoline as *const () as u64;
        }

        let selectors = gdt.selectors_per_cpu.get_by_id(platform_cpu_id);
        state.cs = selectors.user_code_selector.0 as u64 | 3;
        state.ss = selectors.user_data_selector.0 as u64 | 3;
        state
    }

    fn new_kernel_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext {
        let gdt = PER_CPU_GDT.lock();
        let platform_cpu_id = Self::current_logical_id();
        let mut state = State::new(0);
        state.rip = entry_point as u64;
        state.rcx = context as u64;
        state.rsp = initial_c_entry_rsp(stack_top.as_u64());
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = task_return_trampoline as *const () as u64;
        }

        let selectors = gdt.selectors_per_cpu.get_by_id(platform_cpu_id);
        state.cs = selectors.kernel_code_selector.0 as u64;
        state.ss = selectors.kernel_data_selector.0 as u64;
        state
    }

    fn mark_idle_task_context(context: &mut Self::TaskContext) {
        context.r10 = crate::scheduling::task::IDLE_UUID_UPPER;
        context.r11 = crate::scheduling::task::IDLE_MAGIC_LOWER;
    }

    unsafe fn restore_task_context(context: &Self::TaskContext, target: *mut Self::TaskContext) {
        unsafe { context.restore(target) };
    }

    fn save_fpu_state(state: &mut Self::FpuState) {
        state.save();
    }

    fn restore_fpu_state(state: &Self::FpuState) {
        state.restore();
    }

    fn new_kernel_tls() -> Option<Self::KernelTls> {
        super::scheduling::tls::KernelTls::for_kernel_thread()
    }

    fn kernel_tls_thread_pointer(tls: &Self::KernelTls) -> u64 {
        tls.thread_pointer()
    }

    fn activate_kernel_tls(thread_pointer: u64) {
        super::scheduling::tls::activate(thread_pointer);
    }

    fn ensure_current_thread_runtime_initialized() {
        super::scheduling::tls::ensure_current_thread_runtime_initialized();
    }

    fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
        super::scheduling::tls::current_block_on_thread_state()
    }

    fn request_task_yield() {
        unsafe { super::syscalls::task_yield_interrupt() };
    }
}

impl DebugPlatform for X86Platform {
    fn breakpoint() {
        super::instructions::breakpoint();
    }

    fn fatal_reset() -> ! {
        super::instructions::triple_fault()
    }
}

fn initial_c_entry_rsp(stack_top: u64) -> u64 {
    // On the PE/COFF MSVC target, extern "C" uses the Windows x64 ABI:
    // [rsp] return address, [rsp+8..rsp+40) caller-allocated shadow space.
    (stack_top & !0xf).saturating_sub(C_ENTRY_FRAME_BYTES)
}
