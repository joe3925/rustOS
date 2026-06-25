#![no_std]
#![cfg(target_env = "msvc")]
#![allow(non_upper_case_globals)]
pub extern crate alloc;

pub use kernel_types::{async_ffi, device, request, status};

pub use kernel_protocol::{
    open_protocol_at_stack_top, open_protocol_to_next_lower, open_protocol_to_next_upper,
    register_protocol, DriverProtocol, ProtocolHandle, ProtocolId, ProtocolVersion,
};
pub use kernel_routing;
pub use kernel_types;

pub use acpi;
pub use kernel_macros::request_handler;
pub mod benchmark;
pub mod dma;
pub mod fs;
pub mod irq;
pub mod memory;
pub mod pci;
pub mod pnp;
pub mod reg;
pub mod runtime;
pub mod task;
pub mod util;
pub const IOCTL_MOUNTMGR_REGISTER_FS: u32 = 0x4D4D_0001;
pub const IOCTL_FS_IDENTIFY: u32 = 0x4653_0002;

pub const IOCTL_MOUNTMGR_UNMOUNT: u32 = 0x4D4D_0002;
pub const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;
pub const IOCTL_MOUNTMGR_RESYNC: u32 = 0x4D4D_0004;
pub const IOCTL_MOUNTMGR_LIST_FS: u32 = 0x4D4D_0005;
pub const IOCTL_FS_CREATE_FUNCTION_FDO: u32 = 0x4653_3001;

pub const IOCTL_PCI_SETUP_MSIX: u32 = 0x5043_0001; // "PC" prefix

pub const GLOBAL_NS: &str = "\\GLOBAL";
pub const GLOBAL_CTRL_LINK: &str = "\\GLOBAL\\MountMgr";
pub const GLOBAL_VOLUMES_BASE: &str = "\\GLOBAL\\Volumes";
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

    ($s:expr) => {{
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
