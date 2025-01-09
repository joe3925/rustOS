#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![feature(ascii_char)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

mod idt;
pub mod gdt;

mod console;
mod util;
mod cpu;
mod syscalls;
mod structs;
mod scheduling;
mod memory;
mod file_system;
mod exception_handlers;
mod drivers;

use crate::util::KERNEL_INITIALIZED;
use bootloader;
use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {

    pub static ref BOOT_INFO: Mutex<Option<&'static BootInfo>> =  Mutex::new(None);
}
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    //unsafe { Console::reset_state(); }
    *KERNEL_INITIALIZED.lock() = false;
    println!("{}", info);
    loop {}
}

entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {
    *BOOT_INFO.lock() = Some(boot_info); //RustRover will sometimes mark this as an error not sure why
    unsafe {
        util::init(boot_info);
    }

    loop {}
}

