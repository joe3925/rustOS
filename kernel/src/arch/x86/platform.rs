use alloc::vec::Vec;
use core::time::Duration;

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::PhysFrame;

use crate::drivers::interrupt_index::{
    APIC, APIC_START_PERIOD, ApicImpl, IpiDest, IpiKind, LocalApic, PICS,
    apic_calibrate_ticks_per_ns_via_wait, apic_logical_ids, apic_program_period_ns, calibrate_tsc,
    current_cpu_id as x86_current_cpu_id, current_is_in_interrupt_atomic,
    get_current_logical_id as x86_current_logical_id, init_percpu_gs,
    wait_duration as x86_wait_duration, wait_using_pit_50ms,
};
use crate::gdt::PER_CPU_GDT;
use crate::idt::load_idt;
use crate::memory::dma::{PlatformIommuInfo, discover_platform_iommu};
use crate::memory::paging::tables::{init_kernel_cr3, kernel_cr3};
use crate::platform::{
    AddressSpacePlatform, CpuPlatform, DeviceMmuPlatform, InterruptPlatform, Platform,
    TimerPlatform,
};
use crate::println;
use crate::structs::stopwatch::Stopwatch;
use crate::syscalls::syscall::syscall_init;

pub struct X86Platform;

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
}

impl AddressSpacePlatform for X86Platform {
    type Root = PhysFrame;

    fn init_kernel_root() {
        init_kernel_cr3();
    }

    fn kernel_root() -> Self::Root {
        kernel_cr3()
    }

    fn current_root() -> Self::Root {
        let root = kernel_types::arch::current_page_table_root().expect("missing page table root");
        PhysFrame::containing_address(x86_64::PhysAddr::new(root.as_u64()))
    }

    unsafe fn switch_root(root: Self::Root) {
        unsafe {
            Cr3::write(root, Cr3::read().1);
        }
    }

    fn root_to_phys(root: Self::Root) -> u64 {
        root.start_address().as_u64()
    }
}

impl DeviceMmuPlatform for X86Platform {
    fn discover_required_device_mmu() -> PlatformIommuInfo {
        discover_platform_iommu()
    }
}
