use core::arch::{asm, x86_64::_rdtsc};
use core::sync::atomic::{AtomicBool, Ordering};
use raw_cpuid::{CpuId, CpuIdReaderNative};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

use alloc::vec::Vec;
use kernel_types::irq::PlatformCpuId;

use crate::platform::{CpuPlatform, CpuStartupError};
use crate::println;
use crate::structs::per_cpu::{PerCpu, alloc_or_get_percpu};
use crate::structs::stopwatch::Stopwatch;

use super::drivers::timer_driver::NUM_CORES;
use super::interrupts::{APIC, ApicImpl};
use super::platform::X86Platform;

#[thread_local]
static mut EXECUTOR_TASK_ID: u64 = 0;
#[thread_local]
static mut EXECUTOR_DOMAIN_ID: u64 = 0;

pub fn get_cycles() -> u64 {
    unsafe { _rdtsc() }
}

pub fn wait_cycle(cycles: u128) {
    let start = get_cycles() as u128;
    loop {
        if (get_cycles() as u128 >= cycles + start) {
            return;
        }
    }
}
pub fn wait_cycle_idle(cycles: u128) {
    let start = get_cycles() as u128;
    loop {
        //task_yield();
        let current = get_cycles();
        if (current as u128 >= cycles + start) {
            return;
        }
    }
}

pub fn get_cpu_info() -> CpuId<CpuIdReaderNative> {
    CpuId::new()
}

pub(crate) fn platform_cpu_id() -> u8 {
    let info = get_cpu_info();
    info.get_feature_info()
        .expect("cpu id not available?")
        .initial_local_apic_id()
}

const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

#[inline(always)]
fn wrmsr(msr: u32, val: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

#[inline(always)]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;

    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
    }

    ((hi as u64) << 32) | lo as u64
}

#[inline(always)]
/// # Safety
/// `percpu` must be a stable, initialized per-CPU allocation that remains live
/// while either GS base can reference it.
pub(crate) unsafe fn set_gs_bases(percpu: *const PerCpu) {
    let p = percpu as u64;

    wrmsr(IA32_GS_BASE, p);
    wrmsr(IA32_KERNEL_GS_BASE, p);
}

#[inline(always)]
pub fn current_percpu() -> &'static PerCpu {
    let ptr = rdmsr(IA32_GS_BASE) as *const PerCpu;

    debug_assert!(!ptr.is_null());

    unsafe { &*ptr }
}

#[inline(always)]
pub fn current_is_in_interrupt_atomic() -> &'static AtomicBool {
    &current_percpu().is_in_interrupt
}

extern "C" fn current_is_in_interrupt() -> bool {
    current_is_in_interrupt_atomic().load(Ordering::Acquire)
}

extern "C" fn irq_interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

extern "C" fn irq_interrupts_disable() {
    x86_64::instructions::interrupts::disable();
}

extern "C" fn irq_interrupts_enable() {
    x86_64::instructions::interrupts::enable();
}

extern "C" fn irq_interrupts_enable_and_hlt() {
    x86_64::instructions::interrupts::enable_and_hlt();
}

#[inline(always)]
pub fn current_cpu_id() -> usize {
    *current_percpu().cpu_id.get().unwrap()
}

#[inline(always)]
pub fn init_percpu_gs(cpu_id: usize) -> &'static PerCpu {
    let platform_cpu_id = platform_cpu_id() as kernel_types::irq::PlatformCpuId;
    let p: &'static PerCpu = alloc_or_get_percpu(cpu_id, platform_cpu_id);
    let ptr = p as *const PerCpu;
    p.tls_array_pointer.store(0, Ordering::Relaxed);
    unsafe { set_gs_bases(ptr) };
    kernel_types::irq::set_irq_context_query(current_is_in_interrupt);
    kernel_types::irq::set_irq_interrupt_control(
        irq_interrupts_enabled,
        irq_interrupts_disable,
        irq_interrupts_enable,
        irq_interrupts_enable_and_hlt,
    );
    p
}

/// Enable SSE/FXSR for the current CPU.
pub fn enable_sse() {
    let mut flags = Cr0::read();
    flags.remove(Cr0Flags::EMULATE_COPROCESSOR);
    flags.insert(Cr0Flags::MONITOR_COPROCESSOR);
    unsafe {
        Cr0::write(flags);
    }

    let mut flags = Cr4::read();
    flags.insert(Cr4Flags::OSFXSR);
    flags.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
    unsafe {
        Cr4::write(flags);
    }
}

impl CpuPlatform for X86Platform {
    type PerCpuState = crate::structs::per_cpu::PerCpu;

    const MAX_CPUS: usize = super::MAX_CPUS;

    fn current_cpu_id() -> usize {
        current_cpu_id()
    }

    fn current_platform_cpu_id() -> PlatformCpuId {
        platform_cpu_id() as PlatformCpuId
    }

    fn platform_cpu_ids() -> Vec<PlatformCpuId> {
        let mut ids = Vec::new();
        ids.push(platform_cpu_id().into());

        let info = crate::machine::machine_info().cpu_topology();
        for processor in info.processors.iter() {
            let id = processor.platform_cpu_id;
            if !ids.contains(&id) {
                ids.push(id);
            }
        }

        ids
    }

    fn processor_count() -> usize {
        NUM_CORES.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn init_current_cpu_local_state(cpu_id: usize) {
        init_percpu_gs(cpu_id);
    }

    fn current_percpu() -> &'static Self::PerCpuState {
        current_percpu()
    }

    fn swap_executor_context(task_id: u64, domain_id: u64) -> (u64, u64) {
        unsafe {
            let previous = (EXECUTOR_TASK_ID, EXECUTOR_DOMAIN_ID);
            EXECUTOR_TASK_ID = task_id;
            EXECUTOR_DOMAIN_ID = domain_id;
            previous
        }
    }

    fn current_executor_context() -> (u64, u64) {
        unsafe { (EXECUTOR_TASK_ID, EXECUTOR_DOMAIN_ID) }
    }

    fn start_secondary_cpus() -> Result<(), CpuStartupError> {
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
            Ok(())
        } else {
            Err(CpuStartupError {
                platform_cpu_id: None,
                reason: "APIC initialization failed",
                status: -1,
            })
        }
    }

    fn halt() -> ! {
        unsafe {
            loop {
                super::debug::poll_rx_once();
                core::arch::asm!("hlt;", options(nomem, nostack, preserves_flags));
            }
        }
    }
}
