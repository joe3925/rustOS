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

use alloc::string::{String, ToString};
use alloc::{format};
use alloc::vec::Vec;
use core::panic::PanicInfo;
use bootloader::{entry_point, BootInfo};
use lazy_static::lazy_static;
use spin::mutex::Mutex;
use x86_64::VirtAddr;
use crate::console::clear_vga_buffer;
use crate::drivers::drive::generic_drive::DriveController;
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;
use crate::drivers::interrupt_index;
use crate::drivers::pci::pci_bus::PCIBUS;
use crate::file_system::FAT::FileSystem;
use crate::idt::load_idt;
use crate::memory::allocator::ALLOCATOR;
use crate::memory::heap::{init_heap};
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};

mod drivers {
    pub mod kbdDriver;
    pub mod interrupt_index;
    pub mod timerDriver;
    pub mod drive {
        pub mod ide_disk_driver;
        pub mod sata_disk_drivers;
        pub mod generic_drive;
    }
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
    pub mod aligned_buffer;
}
 mod file_system {
    pub mod FAT;
     pub mod file;
}
static mut BOOT_INFO: Option<&'static BootInfo> = None;
#[panic_handler]
fn panic(info: &PanicInfo) -> !{
    println!("{}", info);
    loop{}
}
pub fn test_create_and_read_multicluster_file(fs: &mut FileSystem, mut ide_controller: &mut IdeController, file_name: String, dir_path: &str) {
    // Create a directory where the file will be stored


    // Prepare test data that spans multiple clusters
    let cluster_size = 32 * 1024;
    let num_clusters = 125; // Number of clusters the file will occupy
    let total_size = cluster_size * num_clusters;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    // File name and extension
    let file_extension = "bin";

    // Create and write the file
    println!("{}",fs.create_and_write_file(
        file_name.as_str(),
        file_extension,
        &test_data,
        dir_path,
    ).to_str());

}

entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {
    unsafe { BOOT_INFO = Some(boot_info); }
    gdt::init();
    load_idt();
    unsafe { interrupt_index::PICS.lock().initialize() };

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    init_heap(&mut mapper, &mut frame_allocator);
    unsafe {
        PCIBUS.lock().enumerate_pci();
    }
    AHCIController::map(&mut mapper, &mut frame_allocator);
    AHCIController::new();
    loop{

    }
}

