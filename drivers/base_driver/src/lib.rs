#![no_std]
#![no_main]

mod include;
mod msvc_shims;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(export_name = "driver_entry")]
extern "win64" fn driver_entry() {}
