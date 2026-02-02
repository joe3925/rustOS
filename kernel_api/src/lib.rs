#![no_std]
#![cfg(target_env = "msvc")]
#![allow(non_upper_case_globals)]
pub extern crate alloc;

use alloc::boxed::Box;
use kernel_sys::{submit_blocking_internal, submit_runtime_internal};
use kernel_types::pnp::PnpRequest;
use kernel_types::request::{Request, RequestData, RequestType, TraversalPolicy};
use kernel_types::status::DriverStatus;
pub use kernel_types::{async_ffi, device, request, status};

pub use kernel_types;

pub use x86_64;

use crate::util::random_number;
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
pub trait RequestExt {
    fn new(kind: RequestType, data: RequestData) -> Self;
    fn new_pnp(pnp: PnpRequest, data: RequestData) -> Self;
    #[inline]
    fn new_t<T: 'static>(kind: RequestType, data: T) -> Self
    where
        Self: Sized,
    {
        Self::new(kind, RequestData::from_t(data))
    }
    #[inline]
    fn new_pnp_t<T: 'static>(pnp: PnpRequest, data: T) -> Self
    where
        Self: Sized,
    {
        Self::new_pnp(pnp, RequestData::from_t(data))
    }
    #[inline]
    fn new_bytes(kind: RequestType, data: Box<[u8]>) -> Self
    where
        Self: Sized,
    {
        Self::new(kind, RequestData::from_boxed_bytes(data))
    }
    #[inline]
    fn new_pnp_bytes(pnp: PnpRequest, data: Box<[u8]>) -> Self
    where
        Self: Sized,
    {
        Self::new_pnp(pnp, RequestData::from_boxed_bytes(data))
    }
}

impl RequestExt for Request {
    fn new(kind: RequestType, data: RequestData) -> Self {
        if matches!(kind, RequestType::Pnp) {
            panic!("Request::new called with RequestType::Pnp. Use Request::new_pnp instead.");
        }

        Self {
            id: random_number(),
            kind,
            data,
            completed: false,
            status: DriverStatus::ContinueStep,
            traversal_policy: TraversalPolicy::FailIfUnhandled,
            pnp: None,
            completion_routine: None,
            completion_context: 0,

            waker: None,
        }
    }

    #[inline]
    fn new_pnp(pnp_request: PnpRequest, data: RequestData) -> Self {
        Self {
            id: random_number(),
            kind: RequestType::Pnp,
            data,
            completed: false,
            status: DriverStatus::ContinueStep,
            traversal_policy: TraversalPolicy::ForwardLower,
            pnp: Some(pnp_request),
            completion_routine: None,
            completion_context: 0,

            waker: None,
        }
    }
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
