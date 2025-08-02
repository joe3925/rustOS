
#![no_std]
#![no_main]

mod msvc_shims;

use core::arch::asm;
use core::panic::PanicInfo;
use rustos_api::sys_print;


#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    sys_print("syscall");
    loop {}
}