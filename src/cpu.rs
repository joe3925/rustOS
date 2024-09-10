use core::arch::x86_64::_rdtsc;


pub fn get_cycles() -> u64 {
    unsafe {
        _rdtsc()
    }
}
pub fn wait_cycle(cycles: u64){
    let start = get_cycles();
    loop{
        if(get_cycles() >= cycles + start){
            return;
        }
    }
}
