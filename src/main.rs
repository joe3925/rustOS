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

use alloc::alloc::{alloc, dealloc};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;
use core::ptr::null_mut;
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
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::paging::{init_mapper, virtual_to_phys, BootInfoFrameAllocator};
fn many_boxes() {
    for i in 0..HEAP_SIZE * 2 {
        let x = Box::new(i);
    }
}
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
    unsafe { interrupt_index::PICS.lock().initialize() };

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    init_heap(&mut mapper, &mut frame_allocator);
    many_boxes();
    let layout_50kb = Layout::from_size_align(50 * 1024, 8).expect("Failed to create layout");
    let ptr_50kb = unsafe { alloc(layout_50kb) };
    if ptr_50kb == null_mut() {
        panic!("Failed to allocate 50KB");
    }
    println!("Successfully allocated 50KB");
    unsafe { dealloc(ptr_50kb, layout_50kb); }
    //TODO: find out why the global dealloc is not called for Vec
    // Test 2: Allocate a large array
    let large_vec: Vec<u8> = Vec::with_capacity(1024 * 50); // 50 KB
    if large_vec.capacity() >= 1024 * 50 {
        println!("Large vector allocation of 50 KB succeeded.");
    } else {
        println!("Large vector allocation of 50 KB failed.");
    }

    // Test 3: Allocate an even larger array
    let large_vec2: Vec<u8> = Vec::with_capacity(1024 * 51); // 100 KB
    if large_vec2.capacity() >= 1024 * 100 {
        println!("Large vector allocation of 100 KB succeeded.");
    } else {
        println!("Large vector allocation of 100 KB failed.");
    }

    loop{}

}

