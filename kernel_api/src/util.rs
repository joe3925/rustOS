use core::{arch::asm, time::Duration};

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
/// Converts a Box<[u8]> back into a concrete typed Box<T>.
///
/// # Safety
/// The byte slice must have been created from a `Box<T>` originally (or have compatible layout)
/// and must be the exact size of `T`.
pub unsafe fn bytes_to_box<T>(b: Box<[u8]>) -> Box<T> {
    assert_eq!(
        b.len(),
        core::mem::size_of::<T>(),
        "Size mismatch in bytes_to_box"
    );
    let ptr = Box::into_raw(b) as *mut u8 as *mut T;
    Box::from_raw(ptr)
}
pub fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]> {
    let len = size_of::<T>();
    let p = Box::into_raw(b) as *mut u8;
    unsafe { Box::from_raw(core::slice::from_raw_parts_mut(p, len)) }
}
