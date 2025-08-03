
#![no_std]
#![no_main]

mod msvc_shims;

use core::arch::asm;
use core::panic::PanicInfo;
use rustos_api::sys_get_task_id;
use rustos_api::println;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    let tid = sys_get_task_id();
    println!("syscall from tid {}", tid);
    loop{}
}