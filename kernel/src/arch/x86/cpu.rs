use core::arch::x86_64::_rdtsc;
use raw_cpuid::{CpuId, CpuIdReaderNative};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

use alloc::vec::Vec;
use kernel_types::irq::PlatformCpuId;

use crate::platform::{CpuPlatform, CpuStartupError};
use crate::println;
use crate::structs::stopwatch::Stopwatch;

use super::drivers::interrupt_index::{
    APIC, ApicImpl, current_cpu_id, get_current_logical_id, init_percpu_gs,
};
use super::drivers::timer_driver::NUM_CORES;
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
        get_current_logical_id() as PlatformCpuId
    }

    fn platform_cpu_ids() -> Vec<PlatformCpuId> {
        let mut ids = Vec::new();
        ids.push(get_current_logical_id().into());

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
        super::drivers::interrupt_index::current_percpu()
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
