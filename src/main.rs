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
use bootloader::{entry_point, BootInfo};
use x86_64::VirtAddr;
use crate::drivers::interrupt_index;

mod drivers {
    pub mod kbdDriver;
    pub mod interrupt_index;
    pub mod timerDriver;
}
mod memory{
    pub mod paging;
}
mod exception_handlers {
    pub mod exception_handlers;
}
use crate::idt::load_idt;
use crate::memory::paging::virtual_to_phys;

#[panic_handler]
fn panic(info: &PanicInfo) -> !{
    //clear_vga_buffer();
    //print!("{}", info);
    loop{}
}
entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {
    gdt::init();
    println!("loaded GDT");
    load_idt();
    println!("loaded IDT");
    unsafe { interrupt_index::PICS.lock().initialize() }; // new
    x86_64::instructions::interrupts::enable();
    let memOffset = VirtAddr::new(boot_info.physical_memory_offset);
    let addresses = [
        // the identity-mapped vga buffer page
        0xb8000,
        // some code page
        0x201008,
        // some stack page
        0x0100_0020_1a10,
        // virtual address mapped to physical address 0
        boot_info.physical_memory_offset,
    ];

    for &address in &addresses {
        let virt = VirtAddr::new(address);
        let phys = unsafe { virtual_to_phys(memOffset, virt) };
        println!("{:?} -> {:?}", virt, phys);
    }
    loop{
        //clear_vga_buffer();
    }
}

