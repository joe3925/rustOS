#![no_std]

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
