use core::arch::x86_64::_rdtsc;
use raw_cpuid::{CpuId, CpuIdReaderNative};

pub fn get_cycles() -> u64 {
    unsafe {
        _rdtsc()
    }
}
pub fn wait_cycle(cycles: u64) {
    let start = get_cycles();
    loop {
        if (get_cycles() >= cycles + start) {
            return;
        }
    }
}

pub fn get_cpu_info() -> CpuId<CpuIdReaderNative> {
    let info = CpuId::new();
    info
}

