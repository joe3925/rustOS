#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![feature(const_mut_refs)]
#![feature(const_ptr_as_ref)]
#![feature(const_ptr_write)]
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

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use bootloader;
use x86_64::VirtAddr;
use crate::console::{Console, CONSOLE};
use crate::memory::heap::init_heap;
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};
use crate::scheduling::task::test_syscall;
use crate::util::{test_full_heap, KERNEL_INITIALIZED};

static mut BOOT_INFO: Option<&'static BootInfo> = None;
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    //unsafe { Console::reset_state(); }
    unsafe { KERNEL_INITIALIZED = false; }
    println!("{}", info);
    loop {  }
}

entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {
    unsafe {
        BOOT_INFO = Some(boot_info); //RustRover will sometimes mark this as an error not sure why
        util::init(boot_info);
    }

    loop {
    }
}

