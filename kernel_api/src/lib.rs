#![no_std]

pub extern crate alloc;

use alloc::boxed::Box;
use kernel_sys::submit_runtime_internal;
use kernel_types::pnp::PnpRequest;
use kernel_types::request::{Request, RequestFuture, RequestType, TraversalPolicy};
use kernel_types::status::DriverStatus;
pub use kernel_types::{async_ffi, device, request, status};

pub use kernel_types;

pub use x86_64;

use crate::util::random_number;
pub use acpi;
pub use kernel_macros::request_handler;
pub use nostd_runtime::block_on::*;
pub use nostd_runtime::*;

pub mod fs;
pub mod memory;
pub mod pnp;
pub mod reg;
pub mod runtime;
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
    fn new(kind: RequestType, data: Box<[u8]>) -> Self;
    fn new_pnp(pnp: PnpRequest, data: Box<[u8]>) -> Self;
}

impl RequestExt for Request {
    fn new(kind: RequestType, data: Box<[u8]>) -> Self {
        if matches!(kind, RequestType::Pnp) {
            panic!("Request::new called with RequestType::Pnp. Use Request::new_pnp instead.");
        }

        Self {
            id: random_number(),
            kind,
            data,
            completed: false,
            status: DriverStatus::Continue,
            traversal_policy: TraversalPolicy::FailIfUnhandled,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
            waker_context: None,
            waker_func: None,
        }
    }

    #[inline]
    fn new_pnp(pnp_request: PnpRequest, data: Box<[u8]>) -> Self {
        Self {
            id: random_number(),
            kind: RequestType::Pnp,
            data,
            completed: false,
            status: DriverStatus::Continue,
            traversal_policy: TraversalPolicy::ForwardLower,
            pnp: Some(pnp_request),
            completion_routine: None,
            completion_context: 0,
            waker_context: None,
            waker_func: None,
        }
    }
}
pub trait RequestResultExt {
    async fn resolve(self) -> DriverStatus;
}

impl RequestResultExt for Result<RequestFuture, DriverStatus> {
    #[inline(always)]
    async fn resolve(self) -> DriverStatus {
        match self {
            Ok(future) => future.await,
            Err(status) => status,
        }
    }
}
#[no_mangle]
pub unsafe extern "win64" fn _driver_runtime_submit_task(
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    submit_runtime_internal(trampoline, ctx);
}
