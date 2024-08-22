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
    println!("loaded GDT");
    load_idt();
    println!("loaded IDT");
    unsafe { interrupt_index::PICS.lock().initialize() }; // new
    x86_64::instructions::interrupts::enable();
    loop {
        //clear_vga_buffer();
    }
}
