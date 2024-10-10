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
use core::panic::PanicInfo;
use bootloader::{entry_point, BootInfo};
use x86_64::VirtAddr;
use crate::drivers::drive::generic_drive::{DriveController, DRIVECOLLECTION};
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::interrupt_index;
use crate::drivers::pci::pci_bus::PCIBUS;
use crate::file_system::FAT::FileSystem;
use crate::file_system::file::{File, OpenFlags};
use crate::idt::load_idt;
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
        pub mod AHCI_structs;
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
pub fn test_file_operations() {
    // Define a mock path
    let path = "B:\\test\\myfile.txt";

    // Test creating a new file
    let create_flags = &[OpenFlags::Create];
    let result = File::open(path, create_flags);
    match result {
        Ok(file) => println!("File created successfully: {:?}", file),
        Err(status) => println!("Failed to create file: {}", status.to_str()),
    }

    // Try opening the file without the Create flag (should succeed since it was just created)
    let open_flags = &[OpenFlags::ReadOnly];
    let result = File::open(path, open_flags);
    match result {
        Ok(file) => println!("File opened successfully: {:?}", file),
        Err(status) => println!("Failed to open file: {}", status.to_str()),
    }

    // Test writing data to the file
    if let Ok(mut file) = File::open(path, &[OpenFlags::WriteOnly]) {
        let data = b"Hello, World!";
        match file.write(data) {
            Ok(_) => println!("Data written successfully"),
            Err(status) => println!("Failed to write data: {}", status.to_str()),
        }
    } else {
        println!("Failed to open file for writing.");
    }

    // Test reading data from the file
    if let Ok(mut file) = File::open(path, &[OpenFlags::ReadOnly]) {
        match file.read() {
            Ok(contents) => println!("Read data: {:?}", String::from_utf8_lossy(&contents)),
            Err(status) => println!("Failed to read data: {}", status.to_str()),
        }
    } else {
        println!("Failed to open file for reading.");
    }
}



entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {

    unsafe { BOOT_INFO = Some(boot_info); } //RustRover will mark this as an error not sure why
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
    IdeController::enumerate_drives();

    DRIVECOLLECTION.lock().print_drives();
    //change this to something better
    unsafe { DRIVECOLLECTION.force_unlock(); }
    let mut fs = FileSystem::new("B:".to_string());
    fs.format_drive().expect("");
    test_file_operations();
    let mut i = 0;
    loop{
        i+= 1;
    }
}

