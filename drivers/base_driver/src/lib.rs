#![no_std]

mod include;
mod msvc_shims;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

//#[unsafe(export_name = "driver_entry")]
#[unsafe(no_mangle)]
fn driver_entry() {}
