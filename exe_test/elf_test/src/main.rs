#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    sys_print("Calling syscall");
    unsafe {
        asm!("sysenter");
    }
    loop {}
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
