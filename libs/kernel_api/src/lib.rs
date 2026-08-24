#![no_std]
#![allow(non_upper_case_globals)]
pub extern crate alloc;

pub use kernel_types::{async_ffi, request, status};

pub use kernel_routing;
pub use kernel_types;

pub use acpi;
pub use kernel_macros::request_handler;
pub mod benchmark;
pub mod device;
pub mod dma;
pub mod error;
pub mod fs;
pub mod irq;
pub mod memory;
pub mod pci;
pub mod pnp;
pub mod reg;
pub mod runtime;
pub mod task;
pub mod util;
pub use spin;
pub const IOCTL_MOUNTMGR_UNMOUNT: u32 = 0x4D4D_0002;
pub const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;
pub const IOCTL_MOUNTMGR_RESYNC: u32 = 0x4D4D_0004;
pub const IOCTL_MOUNTMGR_LIST_FS: u32 = 0x4D4D_0005;

pub const GLOBAL_NS: &str = "\\GLOBAL";
pub const GLOBAL_CTRL_LINK: &str = "\\GLOBAL\\MountMgr";
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        unsafe{$crate::util::print(&$crate::alloc::format!($($arg)*))};
    });
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", $crate::alloc::format!($($arg)*)));
}

#[macro_export]
macro_rules! print_no_fmt {
    ($s:literal) => {{
        $crate::util::print($s);
    }};
}

#[macro_export]
macro_rules! println_no_format {
    () => {{
        unsafe {
            $crate::util::print("\n");
        }
    }};

    ($s:expr_2021) => {{
        unsafe {
            $crate::util::print($s);
            $crate::util::print("\n");
        }
    }};
}
#[unsafe(no_mangle)]
pub extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    libm::fmodf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmod(x: f64, y: f64) -> f64 {
    libm::fmod(x, y)
}
#[unsafe(no_mangle)]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    libm::fma(x, y, z)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    libm::fmaf(x, y, z)
}
