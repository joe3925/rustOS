#![no_std]
#![no_main]

mod msvc_shims;
mod include;
use core::panic::PanicInfo;
use crate::include::function;
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(export_name = "driver_entry")]
extern "win64" fn driver_entry() {
    unsafe{function(2)};
}
