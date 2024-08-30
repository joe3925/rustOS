#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(non_snake_case)]
#![feature(const_mut_refs)]
#![feature(const_ptr_as_ref)]
#![feature(const_ptr_write)]

extern crate alloc;

mod idt;
pub mod gdt;

mod console;
mod util;

use alloc::boxed::Box;
use alloc::vec::Vec;
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
mod structs{
    pub mod linked_list;
}
use crate::idt::load_idt;
use crate::memory::heap::{init_heap};
use crate::memory::paging::{init_mapper, virtual_to_phys, BootInfoFrameAllocator};

#[panic_handler]
fn panic(info: &PanicInfo) -> !{
    //clear_vga_buffer();
    print!("{}", info);
    loop{}
}
fn box_test(){
    let mut i = 0;
    while(i < 500){
        let _ = Box::new(i);
        i+= 1;
    }
}
fn vec_test(){
    let large_vec: Vec<u8> = Vec::with_capacity(1024 * 50); // 50 KB
    if large_vec.capacity() >= 1024 * 50 {
        println!("Large vector allocation of 50 KB succeeded.");
    } else {
        println!("Large vector allocation of 50 KB failed.");
    }
}
fn large_vec_test(){
    let large_vec: Vec<u8> = Vec::with_capacity(1024 * 50); // 50 KB
    if large_vec.capacity() >= 1024 * 50 {
        println!("Large vector allocation of 100 KB succeeded.");
    } else {
        println!("Large vector allocation of 50 KB failed.");
    }
}
entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {
    gdt::init();
    load_idt();
    x86_64::instructions::interrupts::enable();
    unsafe { interrupt_index::PICS.lock().initialize() };

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    init_heap(&mut mapper, &mut frame_allocator);
    box_test();
    // Test 1
    vec_test();
    // Test 2
    large_vec_test();
    virtual_to_phys(mem_offset, VirtAddr::new(0xb8000));

    loop{}

}

