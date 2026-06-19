#![feature(trusted_random_access)]
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
#![feature(thread_local)]
#![feature(specialization)]

extern crate alloc;

mod arch;

mod benchmarking;
mod console;
mod crt;
mod drivers;
mod executable;
mod exports;
mod file_system;
mod idt;
mod machine;
mod memory;
mod object_manager;
mod platform;
mod profiling;
mod registry;
mod scheduling;
mod static_handlers;
mod structs;
mod sync_platform;
mod syscalls;
mod util;

use crate::util::{panic_common, KERNEL_INITIALIZED};

use alloc::{format, vec};
use core::panic::PanicInfo;
use core::ptr::{addr_of_mut, copy_nonoverlapping};
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_abi::{
    BootInfo, FrameBuffer, KernelSection, KernelSections, KernelSymbol, KernelSymbolString,
    KernelSymbols, MemoryRegion, MemoryRegions, Optional, MAX_BOOT_MEMORY_REGIONS,
    MAX_KERNEL_EXPORT_SYMBOLS, MAX_KERNEL_IMPORT_SYMBOLS, MAX_KERNEL_SECTIONS,
    MAX_KERNEL_SYMBOL_STRING_BYTES,
};
use kernel_abi::{RUSTOS_BOOT_INFO_MAGIC, RUSTOS_BOOT_INFO_VERSION};
use lazy_static::lazy_static;

use crate::platform::{ActivePlatform, Platform};

pub type ActiveBootInfo = BootInfo<<ActivePlatform as Platform>::BootArchInfo>;

static mut BOOT_INFO: ActiveBootInfo = ActiveBootInfo::empty();

static BOOT_INFO_INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut BOOT_MEMORY_REGIONS: [MemoryRegion; MAX_BOOT_MEMORY_REGIONS] =
    [MemoryRegion::empty(); MAX_BOOT_MEMORY_REGIONS];
static mut BOOT_KERNEL_SECTIONS: [KernelSection; MAX_KERNEL_SECTIONS] =
    [KernelSection::empty(); MAX_KERNEL_SECTIONS];
static mut BOOT_KERNEL_IMPORT_SYMBOLS: [KernelSymbol; MAX_KERNEL_IMPORT_SYMBOLS] =
    [KernelSymbol::empty(); MAX_KERNEL_IMPORT_SYMBOLS];
static mut BOOT_KERNEL_EXPORT_SYMBOLS: [KernelSymbol; MAX_KERNEL_EXPORT_SYMBOLS] =
    [KernelSymbol::empty(); MAX_KERNEL_EXPORT_SYMBOLS];
static mut BOOT_KERNEL_SYMBOL_STRING_BYTES: [u8; MAX_KERNEL_SYMBOL_STRING_BYTES] =
    [0; MAX_KERNEL_SYMBOL_STRING_BYTES];
static mut BOOT_KERNEL_SYMBOL_STRING_LEN: usize = 0;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panic_common(MOD_NAME, info)
}
#[no_mangle]
pub extern "C" fn kernel_pe_entry(boot_info: *const ActiveBootInfo) -> ! {
    if boot_info.is_null() {
        panic!("kernel_pe_entry received a null boot info pointer");
    }

    let boot_info = unsafe { &*boot_info };
    if boot_info.magic != RUSTOS_BOOT_INFO_MAGIC || boot_info.version != RUSTOS_BOOT_INFO_VERSION {
        panic!("kernel_pe_entry received an incompatible boot info block");
    }
    unsafe {
        copy_boot_info(boot_info);
        BOOT_INFO_INITIALIZED.store(true, Ordering::Release);
        util::init();
    }

    loop {}
}
unsafe fn copy_boot_info(src: &ActiveBootInfo) {
    BOOT_KERNEL_SYMBOL_STRING_LEN = 0;

    let memory_regions = copy_memory_regions(&src.memory_regions);
    let kernel_imports = copy_kernel_symbols(
        &src.kernel_imports,
        addr_of_mut!(BOOT_KERNEL_IMPORT_SYMBOLS).cast::<KernelSymbol>(),
        MAX_KERNEL_IMPORT_SYMBOLS,
    );
    let kernel_exports = copy_kernel_symbols(
        &src.kernel_exports,
        addr_of_mut!(BOOT_KERNEL_EXPORT_SYMBOLS).cast::<KernelSymbol>(),
        MAX_KERNEL_EXPORT_SYMBOLS,
    );
    let kernel_sections = copy_kernel_sections(&src.kernel_sections);

    BOOT_INFO = ActiveBootInfo {
        magic: src.magic,
        version: src.version,
        flags: src.flags,
        rsdp_addr: src.rsdp_addr,
        arch_info: src.arch_info,
        memory_regions,
        framebuffer: copy_framebuffer(&src.framebuffer),
        fdt_header: src.fdt_header,
        kernel_imports,
        kernel_exports,
        ramdisk_addr: src.ramdisk_addr,
        ramdisk_len: src.ramdisk_len,
        kernel_addr: src.kernel_addr,
        kernel_len: src.kernel_len,
        kernel_image_offset: src.kernel_image_offset,
        kernel_image_base: src.kernel_image_base,
        kernel_image_size: src.kernel_image_size,
        kernel_entry: src.kernel_entry,
        kernel_text: src.kernel_text,
        kernel_sections,
        stub_base: src.stub_base,
        stub_size: src.stub_size,
    };
}

unsafe fn copy_memory_regions(src: &MemoryRegions) -> MemoryRegions {
    if src.len > MAX_BOOT_MEMORY_REGIONS {
        panic!("kernel_pe_entry received too many memory regions");
    }
    if src.len != 0 && src.ptr.is_null() {
        panic!("kernel_pe_entry received a null memory region array");
    }

    let dst = addr_of_mut!(BOOT_MEMORY_REGIONS).cast::<MemoryRegion>();
    if src.len != 0 {
        copy_nonoverlapping(src.ptr.cast_const(), dst, src.len);
    }

    MemoryRegions {
        ptr: dst,
        len: src.len,
    }
}

unsafe fn copy_kernel_symbols(
    src: &KernelSymbols,
    dst: *mut KernelSymbol,
    capacity: usize,
) -> KernelSymbols {
    if src.len > capacity {
        panic!("kernel_pe_entry received too many kernel symbols");
    }
    if src.len != 0 && src.ptr.is_null() {
        panic!("kernel_pe_entry received a null kernel symbol array");
    }

    for i in 0..src.len {
        let symbol = *src.ptr.add(i);
        dst.add(i).write(KernelSymbol {
            name: copy_kernel_symbol_string(symbol.name),
            module: copy_kernel_symbol_string(symbol.module),
        });
    }

    KernelSymbols {
        ptr: dst.cast_const(),
        len: src.len,
    }
}

unsafe fn copy_kernel_symbol_string(src: KernelSymbolString) -> KernelSymbolString {
    if src.len == 0 {
        return KernelSymbolString::empty();
    }
    if src.ptr.is_null() {
        panic!("kernel_pe_entry received a null kernel symbol string");
    }

    let start = BOOT_KERNEL_SYMBOL_STRING_LEN;
    let end = start
        .checked_add(src.len)
        .expect("kernel symbol string storage overflow");
    if end > MAX_KERNEL_SYMBOL_STRING_BYTES {
        panic!("kernel_pe_entry received too much kernel symbol string data");
    }

    let dst = addr_of_mut!(BOOT_KERNEL_SYMBOL_STRING_BYTES)
        .cast::<u8>()
        .add(start);
    copy_nonoverlapping(src.ptr, dst, src.len);
    BOOT_KERNEL_SYMBOL_STRING_LEN = end;

    KernelSymbolString {
        ptr: dst.cast_const(),
        len: src.len,
    }
}

unsafe fn copy_kernel_sections(src: &KernelSections) -> KernelSections {
    if src.len > MAX_KERNEL_SECTIONS {
        panic!("kernel_pe_entry received too many kernel sections");
    }
    if src.len != 0 && src.ptr.is_null() {
        panic!("kernel_pe_entry received a null kernel section array");
    }

    let dst = addr_of_mut!(BOOT_KERNEL_SECTIONS).cast::<KernelSection>();
    if src.len != 0 {
        copy_nonoverlapping(src.ptr, dst, src.len);
    }

    KernelSections {
        ptr: dst.cast_const(),
        len: src.len,
    }
}

fn copy_framebuffer(src: &Optional<FrameBuffer>) -> Optional<FrameBuffer> {
    match src {
        Optional::Some(fb) => Optional::Some(FrameBuffer {
            buffer_start: fb.buffer_start,
            info: fb.info,
        }),
        Optional::None => Optional::None,
    }
}

pub extern "C" fn function(x: i64) -> i64 {
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
    let base =
        <crate::platform::ActivePlatform as crate::platform::Platform>::KERNEL_IMAGE_BASE as usize;
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
