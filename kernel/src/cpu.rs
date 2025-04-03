use core::arch::x86_64::_rdtsc;
use cpuid::CpuInfo;

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
pub fn get_cpu_info() -> Option<CpuInfo> {
    let info = cpuid::identify();
    match info {
        Ok(Info) => { Some(Info) }
        Err(_) => { None }
    }
}

