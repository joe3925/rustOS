#![no_std]
#![no_main]
extern crate alloc;

use core::panic::PanicInfo;
use kernel_api::KernelAllocator;
use kernel_api::println;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

mod fat32;
mod msvc_shims;
mod structs;

mod control;
mod volume;

mod block_dev;
pub use control::DriverEntry;
