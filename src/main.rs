#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(non_snake_case)]

mod idt;
pub mod gdt;

mod console;
mod util;

use core::panic::PanicInfo;
use x86_64::instructions::interrupts;
use crate::console::clear_vga_buffer;
use crate::drivers::interrupt_index;

mod drivers {
    pub mod kbdDriver;
    pub mod interrupt_index;
    pub mod timerDriver;
}
mod exception_handlers {
    pub mod exception_handlers;
}
use crate::idt::load_idt;

#[panic_handler]
fn panic(info: &PanicInfo) -> !{
    //clear_vga_buffer();
    println!("{}", info);
    loop{}
}
#[no_mangle]
pub extern "C"  fn _start() -> ! {
    gdt::init();
    load_idt();
    unsafe { interrupt_index::PICS.lock().initialize() }; // new
    x86_64::instructions::interrupts::enable();
    loop {

    }
}
