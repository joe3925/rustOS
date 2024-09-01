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


use core::panic::PanicInfo;
use bootloader::{entry_point, BootInfo};
use x86_64::VirtAddr;
use crate::drivers::ideDiskDriver::IdeController;
use crate::drivers::interrupt_index;
use crate::file_system::FAT::FileSystem;
use crate::idt::load_idt;
use crate::memory::heap::{init_heap};
use crate::memory::paging::{init_mapper, virtual_to_phys, BootInfoFrameAllocator};

mod drivers {
    pub mod kbdDriver;
    pub mod interrupt_index;
    pub mod timerDriver;
    pub mod ideDiskDriver;
    pub mod pci{
        pub mod device_collection;
        pub mod pci_bus;

    }
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
 mod file_system {
    pub mod FAT;
}

#[panic_handler]
fn panic(info: &PanicInfo) -> !{
    //clear_vga_buffer();
    print!("{}", info);
    loop{}
}

entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {
    let mut controller = IdeController::new();
    gdt::init();
    load_idt();
    unsafe { interrupt_index::PICS.lock().initialize() };

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    init_heap(&mut mapper, &mut frame_allocator);
    controller.init();
    controller.print_all_drives();
    let mut system = FileSystem::new();
    system.format_drive(&mut controller, "D:").expect("TODO: panic message");


    virtual_to_phys(mem_offset, VirtAddr::new(0xb8000));

    loop{}

}

