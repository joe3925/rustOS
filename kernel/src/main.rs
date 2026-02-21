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
#![feature(variant_count)]
#![allow(improper_ctypes_definitions)]
#![feature(try_trait_v2)]
#![feature(const_trait_impl)]
#![feature(const_option_ops)]
#![feature(adt_const_params)]
#![feature(pointer_is_aligned_to)]
#![feature(linked_list_cursors)]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod gdt;
mod idt;

mod benchmarking;
mod console;
mod cpu;
mod drivers;
mod exception_handlers;
mod executable;
mod exports;
mod file_system;
mod memory;
mod object_manager;
mod registry;
mod scheduling;
mod static_handlers;
mod structs;
mod syscalls;
mod util;
use crate::util::{panic_common, KERNEL_INITIALIZED};

use alloc::{format, vec};
use bootloader_api::config::Mapping;
use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use core::panic::PanicInfo;
use lazy_static::lazy_static;

static mut BOOT_INFO: Option<&'static mut BootInfo> = None;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panic_common(MOD_NAME, info)
}
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::FixedAddress(0xFFFF_8000_0000_0000));
    config.kernel_stack_size = 1024 * 1024;
    config.mappings.kernel_stack = Mapping::Dynamic;
    config.mappings.framebuffer = Mapping::Dynamic;
    config.mappings.dynamic_range_start = Some(0xFFFF_8100_0000_0000);
    config.mappings.dynamic_range_end = Some(0xFFFF_8500_0000_0000);
    config.mappings.framebuffer = Mapping::Dynamic;
    // config.frame_buffer.minimum_framebuffer_height = Some(1440);
    // config.frame_buffer.minimum_framebuffer_width = Some(2560);
    config
};
entry_point!(_start, config = &BOOTLOADER_CONFIG);

fn _start(boot_info_local: &'static mut BootInfo) -> ! {
    reserve_low_2mib(&mut boot_info_local.memory_regions);
    unsafe {
        BOOT_INFO = Some(boot_info_local);
    }

    unsafe {
        util::init();
    }

    loop {}
}

#[inline]
pub fn total_usable_bytes(regions: &[MemoryRegion]) -> u128 {
    regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable && r.end > r.start)
        .map(|r| (r.end - r.start) as u128)
        .sum()
}
fn reserve_low_2mib(regions: &mut [MemoryRegion]) {
    const LOW_START: u64 = 0;
    const LOW_END: u64 = 0x20_0000;

    let mut free_idx = regions.iter().position(|r| r.start == 0 && r.end == 0);

    let mut need_insert: Option<MemoryRegion> = None;
    let mut tagged_any = false;

    for i in 0..regions.len() {
        let r = &mut regions[i];

        if r.kind != MemoryRegionKind::Usable {
            continue;
        }
        if r.end <= LOW_START || r.start >= LOW_END {
            continue;
        }

        tagged_any = true;

        if r.start >= LOW_START && r.end <= LOW_END {
            r.kind = MemoryRegionKind::Bootloader;
            continue;
        }

        if r.start < LOW_END && r.end > LOW_END {
            need_insert = Some(MemoryRegion {
                start: r.start,
                end: LOW_END,
                kind: MemoryRegionKind::Bootloader,
            });

            r.start = LOW_END;

            free_idx = free_idx.filter(|_| false);
        }
    }

    if let Some(low_part) = need_insert {
        if let Some(idx) = free_idx {
            regions[idx] = low_part;
        }
    }

    if !tagged_any {
        if let Some(idx) = free_idx {
            regions[idx] = MemoryRegion {
                start: LOW_START,
                end: LOW_END,
                kind: MemoryRegionKind::Bootloader,
            };
        }
    }
}

pub extern "win64" fn function(x: i64) -> i64 {
    (x - 10) / 10
}
#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
}
const fn get_rva(addr: usize) -> usize {
    let base = 0xFFFF_8500_0000_0000usize;
    addr - base
}
#[macro_export]
macro_rules! export {
    ($($name:ident),* $(,)?) => {
        lazy_static::lazy_static! {
            pub static ref EXPORTS: Vec<(String, usize)> = vec![
                $(
                    (stringify!($name).to_string(), get_rva($name as *const () as usize)),
                )*
            ];
        }
    };
}
