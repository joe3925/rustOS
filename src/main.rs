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

use core::panic::PanicInfo;
use bootloader::{entry_point, BootInfo};

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
mod executor{
    pub mod task;
    pub mod scheduler;

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

entry_point!(_start);
fn _start(boot_info: &'static BootInfo) -> ! {

    unsafe {
        util::init(boot_info);
        BOOT_INFO = Some(boot_info); //RustRover will sometimes mark this as an error not sure why
    }

    let mut i:u128 = 0;
    loop{
        i+= 1;
    }
}

