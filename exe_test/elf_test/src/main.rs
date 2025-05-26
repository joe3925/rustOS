#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::arch::asm;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    loop {    
        sys_print("Hello world");
    }
}
pub fn sys_print(string: &str) {
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 1,
        in("r8") string.as_ptr() as u64,
        );
    }
}