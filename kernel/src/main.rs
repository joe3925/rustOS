#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![feature(ascii_char)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![feature(custom_test_frameworks)]
#![feature(allocator_api)]
#![feature(once_cell_get_mut)]
#![test_runner(crate::test_runner)]

extern crate alloc;

pub mod gdt;
mod idt;

mod console;
mod cpu;
mod drivers;
mod exception_handlers;
mod executable;
mod file_system;
mod memory;
mod scheduling;
mod structs;
mod syscalls;
mod util;

use crate::console::clear_screen;
use crate::util::KERNEL_INITIALIZED;

use bootloader_api::config::Mapping;
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use core::panic::PanicInfo;
use core::sync::atomic::Ordering;
use memory::paging::kernel_cr3;
use x86_64::registers::control::Cr3;

static mut BOOT_INFO: Option<&'static mut BootInfo> = None;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    x86_64::instructions::interrupts::disable();
    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };
    KERNEL_INITIALIZED.store(false, Ordering::SeqCst);
    println!("{}", info);
    loop {}
}
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 10 * 100 * 1024;
    config.mappings.kernel_stack = Mapping::Dynamic;
    config.mappings.dynamic_range_start = Some(0xFFFF_8000_0000_0000);
    config.mappings.dynamic_range_end = Some(0xFFFF_84FF_FFFF_FFFF);

    config.mappings.framebuffer = Mapping::Dynamic;
    config
};
entry_point!(_start, config = &BOOTLOADER_CONFIG);
fn _start(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        BOOT_INFO = Some(boot_info);
    }
    clear_screen();
    unsafe {
        util::init();
    }
    loop {}
}
pub fn function(x: i64) -> i64 {
    return x;
}
#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
}
