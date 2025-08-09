#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]

mod include;
mod msvc_shims;
use core::panic::PanicInfo;

use include::function;
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(export_name = "driver_entry")]
unsafe extern "C" fn driver_entry() -> u64 {
    unsafe { function(110) as u64 }
}
pub fn test_runner(tests: &[&dyn Fn()]) {
    for test in tests {
        test();
    }
}
