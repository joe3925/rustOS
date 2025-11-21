#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use core::panic::PanicInfo;
use kernel_api::KernelAllocator;
use kernel_api::println;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::alloc_api::ffi::panic_common;

    unsafe { panic_common(MOD_NAME, info) }
}
mod msvc_shims;

mod control;
mod volume;

mod block_dev;
pub use control::DriverEntry;
