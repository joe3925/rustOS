#![feature(trusted_random_access)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(non_snake_case)]

mod idt;
mod console;
mod util;

use core::panic::PanicInfo;
mod drivers {
    pub mod kbdDriver;
}
use crate::idt::load_idt;
#[panic_handler]
fn panic(_info: &PanicInfo) -> !{
    loop {}
}

#[no_mangle]
pub extern "C"  fn _start() -> ! {

    let mut console = console::Console{
        currentCharSize: 0,
        vga_width: 80,
        vga_height: 25,
        vga_buffer: 0xB8000 as *mut u8,
        currentLine: 0,
        cursor_pose: 0
    };
    let mut defaultEntry = idt::IdtEntry{
        offset_low: 0,
        selector: 0,
        ist: 0,
        options: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };
    let mut idt: [idt::IdtEntry; 256] = [defaultEntry; 256];
    idt[33].set(drivers::kbdDriver::keyboard_interrupt_handler as u64, 0x08, 0x8E);
    load_idt(&idt);
    loop {
        console.print("test \n".as_ref());
    }
}
