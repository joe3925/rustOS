use core::arch::{asm, x86_64::_rdtsc};
use raw_cpuid::{CpuId, CpuIdReaderNative};

use crate::static_handlers::task_yield;

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
        unsafe {
            //task_yield();
        }
        let current = get_cycles();
        if (current as u128 >= cycles + start) {
            return;
        }
    }
}

pub fn get_cpu_info() -> CpuId<CpuIdReaderNative> {
    let info = CpuId::new();
    info
}

#[inline(always)]
pub fn write_msr(msr: u32, val: u64) {
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
pub fn set_fs_base(base: u64) {
    const IA32_FS_BASE: u32 = 0xC000_0100;
    write_msr(IA32_FS_BASE, base);
}

#[inline(always)]
pub fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}
