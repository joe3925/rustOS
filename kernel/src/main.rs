#![feature(trusted_random_access)]
#![feature(abi_x86_interrupt)]
#![feature(ascii_char)]
#![no_std]
#![no_main]
#![allow(unused_parens)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![feature(custom_test_frameworks)]
#![feature(allocator_api)]
#![feature(once_cell_get_mut)]
#![test_runner(crate::test_runner)]
#![allow(static_mut_refs)]

extern crate alloc;

pub mod gdt;
mod idt;

mod console;
mod cpu;
mod drivers;
mod exception_handlers;
mod executable;
mod file_system;
mod memory;
mod scheduling;
mod structs;
mod syscalls;
mod util;

use crate::console::clear_screen;
use crate::util::KERNEL_INITIALIZED;

use bootloader_api::config::Mapping;
use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use core::panic::PanicInfo;
use core::sync::atomic::Ordering;
use memory::paging::kernel_cr3;
use x86_64::registers::control::Cr3;

static mut BOOT_INFO: Option<&'static mut BootInfo> = None;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    x86_64::instructions::interrupts::disable();
    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };
    KERNEL_INITIALIZED.store(false, Ordering::SeqCst);
    println!("{}", info);
    loop {}
}
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 10 * 100 * 1024;
    config.mappings.kernel_stack = Mapping::Dynamic;
    config.mappings.dynamic_range_start = Some(0xFFFF_8000_0000_0000);
    config.mappings.dynamic_range_end = Some(0xFFFF_8300_0000_0000);

    config.mappings.framebuffer = Mapping::Dynamic;
    config
};
entry_point!(_start, config = &BOOTLOADER_CONFIG);

fn _start(boot_info: &'static mut BootInfo) -> ! {
    reserve_low_2mib(&mut *boot_info.memory_regions);

    unsafe {
        BOOT_INFO = Some(boot_info);
    }

    clear_screen();
    unsafe {
        util::init();
    }

    loop {}
}
#[allow(non_snake_case)]
fn reserve_low_2mib(regions: &mut [MemoryRegion]) {
    const LOW_START: u64 = 0x0;
    const LOW_END: u64 = 0x200000;

    // 1. Exact match
    if let Some(r) = regions
        .iter_mut()
        .find(|r| r.start == LOW_START && r.end == LOW_END)
    {
        r.kind = MemoryRegionKind::Bootloader;
        return;
    }

    // 2. Reuse an empty slot
    if let Some(slot) = regions.iter_mut().find(|r| r.start == 0 && r.end == 0) {
        *slot = MemoryRegion {
            start: LOW_START,
            end: LOW_END,
            kind: MemoryRegionKind::Bootloader,
        };
        return;
    }

    // 3. Fallback: re-tag the first overlapping region
    if let Some(r) = regions
        .iter_mut()
        .find(|r| r.end > LOW_START && r.start < LOW_END)
    {
        r.kind = MemoryRegionKind::Bootloader;
    }
}

pub fn function(x: i64) -> i64 {
    return x;
}
#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
}
