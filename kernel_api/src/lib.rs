#![no_std]
#![cfg(target_env = "msvc")]
#![allow(non_upper_case_globals)]
pub extern crate alloc;

pub use kernel_types::{async_ffi, device, request, status};

pub use kernel_types;
pub use kernel_routing;

pub use x86_64;

pub use acpi;
pub use kernel_macros::request_handler;
pub mod benchmark;
pub mod fs;
pub mod irq;
pub mod memory;
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
#[unsafe(export_name = "_fltused")]
static _FLTUSED: i32 = 0;

#[unsafe(no_mangle)]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}
#[unsafe(no_mangle)]
pub extern "C" fn fma(_x: f64, _y: f64, z: f64) -> f64 {
    z
}

#[unsafe(no_mangle)]
pub extern "C" fn fmaf(_x: f32, _y: f32, z: f32) -> f32 {
    z
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __chkstk() {
    core::arch::naked_asm!(
        "test rax, rax",
        "jnz 2f",
        "mov rax, rcx",
        "2:",
        "mov r10, rax",
        "mov r11, rsp",
        "cmp r10, 0x1000",
        "jb 4f",
        "3:",
        "sub r11, 0x1000",
        "test byte ptr [r11], 0",
        "sub r10, 0x1000",
        "cmp r10, 0x1000",
        "jae 3b",
        "4:",
        "sub r11, r10",
        "test byte ptr [r11], 0",
        "ret"
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __chkstk_ms() {
    core::arch::naked_asm!(
        "test rax, rax",
        "jnz 2f",
        "mov rax, rcx",
        "2:",
        "mov r10, rax",
        "mov r11, rsp",
        "cmp r10, 0x1000",
        "jb 4f",
        "3:",
        "sub r11, 0x1000",
        "test byte ptr [r11], 0",
        "sub r10, 0x1000",
        "cmp r10, 0x1000",
        "jae 3b",
        "4:",
        "sub r11, r10",
        "test byte ptr [r11], 0",
        "ret"
    );
}
