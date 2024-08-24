#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(non_snake_case)]
extern crate alloc;

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
    pub mod heap;
    pub mod allocator;
}
mod exception_handlers {
    pub mod exception_handlers;
}
use crate::idt::load_idt;
use crate::memory::heap::init_heap;
use crate::memory::paging::{init_mapper, virtual_to_phys, BootInfoFrameAllocator};

#[panic_handler]
fn panic(info: &PanicInfo) -> !{
    //clear_vga_buffer();
    print!("{}", info);
    loop{}
}
entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {
    gdt::init();
    load_idt();
    x86_64::instructions::interrupts::enable();
    unsafe { interrupt_index::PICS.lock().initialize() }; // new

    let MEM_OFFSET: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(MEM_OFFSET);
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    init_heap(&mut mapper, &mut frame_allocator);

    loop{
    }
}

