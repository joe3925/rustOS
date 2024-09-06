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

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
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
pub fn test_create_multi_cluster_file(filesystem: &mut FileSystem, ide_controller: &mut IdeController) {
    // Define the file content to write, large enough to span multiple clusters
    let cluster_size = 32 as usize * 1024;
    let num_clusters = 3;
    let total_size = num_clusters * cluster_size;

    // Generate the content: A sequence of bytes for simplicity
    let file_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    let file_name = "BIGFILE";
    let file_extension = "DAT";

    println!("Creating a multi-cluster file '{}.{}'...", file_name, file_extension);

    // Write the file to the file system
    filesystem.create_and_write_file(ide_controller, file_name, file_extension, &file_data);

    println!("File '{}.{}' created successfully.", file_name, file_extension);
}
pub fn test_read_multi_cluster_file(filesystem: &mut FileSystem, ide_controller: &mut IdeController) {
    let file_name = "BIGFILE";
    let file_extension = "DAT";

    println!("Reading the multi-cluster file '{}.{}'...", file_name, file_extension);

    // Read the file from the file system
    if let Some(file_data) = filesystem.read_file(ide_controller, file_name, file_extension) {
        println!("File read successfully. Size: {} bytes", file_data.len());

        // Verify the content: Should match the original pattern
        let cluster_size = 32 as usize * 1024;
        let num_clusters = file_data.len() / cluster_size;

        let expected_data: Vec<u8> = (0..file_data.len()).map(|i| (i % 256) as u8).collect();

        if file_data == expected_data {
            println!("File content verified successfully.");
        } else {
            println!("File content does not match expected data.");
        }
    } else {
        println!("Failed to read the file '{}.{}'", file_name, file_extension);
    }
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
    system.format_drive(&mut controller).expect("");
    test_create_multi_cluster_file(&mut system, &mut controller);
    test_read_multi_cluster_file(&mut system, &mut controller);
    virtual_to_phys(mem_offset, VirtAddr::new(0xb8000));

    loop{}

}

