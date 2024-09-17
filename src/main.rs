#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(non_snake_case)]
#![feature(const_mut_refs)]
#![feature(const_ptr_as_ref)]
#![feature(const_ptr_write)]
#[allow(dead_code)]

extern crate alloc;

mod idt;
pub mod gdt;

mod console;
mod util;
mod cpu;

use alloc::string::{ToString};
use alloc::{format};
use alloc::vec::Vec;
use core::panic::PanicInfo;
use bootloader::{entry_point, BootInfo};
use x86_64::VirtAddr;
use crate::console::clear_vga_buffer;
use crate::drivers::ideDiskDriver::IdeController;
use crate::drivers::interrupt_index;
use crate::file_system::FAT::FileSystem;
use crate::idt::load_idt;
use crate::memory::allocator::ALLOCATOR;
use crate::memory::heap::{init_heap};
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};

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
     pub mod file;
}

#[panic_handler]
fn panic(info: &PanicInfo) -> !{
    println!("{}", info);
    loop{}
}
pub fn test_create_and_read_multicluster_file(fs: &mut FileSystem, mut ide_controller: &mut IdeController) {
    // Create a directory where the file will be stored
    let dir_path = "\\test_dir\\testing\\tester\\deep\\test";
    fs.create_dir(&mut ide_controller, dir_path);

    // Prepare test data that spans multiple clusters
    let cluster_size = 32 * 1024;
    let num_clusters = 1; // Number of clusters the file will occupy
    let total_size = cluster_size * num_clusters;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    // File name and extension
    let file_name = "multi_cl";
    let file_extension = "bin";

    // Create and write the file
    if let Some(file_entry) = fs.create_and_write_file(
        &mut ide_controller,
        file_name,
        file_extension,
        &test_data,
        dir_path,
    ) {
        println!("File created successfully: {:?}", file_entry);
    }

    // Read back the file

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
    let mut system = FileSystem::new("D:".to_string());
    system.format_drive(&mut controller).expect("TODO: panic message");


    loop{
        test_create_and_read_multicluster_file(&mut system, &mut controller);
    }
}

