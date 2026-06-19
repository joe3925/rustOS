use core::arch::asm;
use core::arch::x86_64::_rdtsc;
use raw_cpuid::{CpuId, CpuIdReaderNative};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

pub fn get_cycles() -> u64 {
    unsafe { _rdtsc() }
}

pub fn get_ordered_cycles() -> u64 {
    let low: u32;
    let high: u32;

    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }

    ((high as u64) << 32) | low as u64
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
