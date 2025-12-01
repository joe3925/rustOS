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
