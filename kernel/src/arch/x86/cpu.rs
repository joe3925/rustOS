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
use super::interrupts::apic::controller::{APIC, ApicImpl};
use super::platform::X86Platform;

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
    #[cfg_attr(irq_check, irq::allow_incomplete(unsafe))]
    unsafe { CpuId::new() }
}

pub(crate) fn platform_cpu_id() -> u8 {
    let info = get_cpu_info();
    let features = {
        #[cfg_attr(irq_check, irq::allow_incomplete(unsafe))]
        unsafe { info.get_feature_info() }
    };
    features
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
    let ptr: *const PerCpu;
    #[cfg_attr(irq_check, irq::trusted(unsafe))]
    unsafe {
        asm!(
            "mov {ptr}, qword ptr gs:[{offset}]",
            ptr = out(reg) ptr,
            offset = const crate::structs::per_cpu::PERCPU_SELF_POINTER_OFF,
            options(nostack, preserves_flags, readonly)
        );
        &*ptr
    }
}

#[inline(always)]
pub fn current_is_in_interrupt_atomic() -> &'static AtomicBool {
    &current_percpu().is_in_interrupt
}

#[inline(always)]
pub fn current_is_in_interrupt() -> bool {
    let value: u8;
    #[cfg_attr(irq_check, irq::trusted(unsafe))]
    unsafe {
        asm!(
            "mov {value}, byte ptr gs:[{offset}]",
            value = out(reg_byte) value,
            offset = const crate::structs::per_cpu::PERCPU_IS_IN_INTERRUPT_OFF,
            options(nostack, preserves_flags, readonly)
        );
    }
    value != 0
}

extern "C" fn irq_context_query() -> bool {
    current_is_in_interrupt()
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
    p.mimalloc_heap.store(0, Ordering::Relaxed);
    unsafe { set_gs_bases(ptr) };
    kernel_types::irq::set_irq_context_query(irq_context_query);
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

    const MAX_CPUS: usize = super::exports::MAX_CPUS;

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
        loop {
            super::debug::poll_rx_once();
            #[cfg_attr(irq_check, irq::trusted(unsafe))]
            unsafe {
                core::arch::asm!("hlt;", options(nomem, nostack, preserves_flags));
            }
        }
    }
}
