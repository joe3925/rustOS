use core::time::Duration;

use alloc::boxed::Box;

#[inline]
pub fn print(s: &str) {
    unsafe { kernel_sys::print(s) };
}

#[inline]
pub fn random_number() -> u64 {
    unsafe { kernel_sys::random_number() }
}

#[inline]
pub fn wait_duration(time: Duration) {
    unsafe { kernel_sys::wait_duration(time) };
}
#[inline]
pub fn get_current_cpu_id() -> usize {
    unsafe { kernel_sys::get_current_cpu_id() }
}
#[inline]
pub fn get_current_lapic_id() -> usize {
    unsafe { kernel_sys::get_current_lapic_id() }
}
#[inline]
pub fn panic_common(mod_name: &'static str, info: &core::panic::PanicInfo) -> ! {
    unsafe { kernel_sys::panic_common(mod_name, info) }
}
