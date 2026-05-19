#![no_std]
#![feature(variant_count)]
#![feature(try_trait_v2)]
#![feature(negative_impls)]
#![feature(auto_traits)]
#![feature(const_type_name)]
#![allow(static_mut_refs)]
#![feature(generic_const_exprs)]
#![feature(const_trait_impl)]
#![feature(specialization)]
extern crate alloc;
extern crate self as kernel_types;

pub use prost::Message as ProstMessage;

pub mod async_ffi;
pub mod async_types;
pub mod bench_archive;
pub mod benchmark;
pub mod device;
pub mod dma;
pub mod fs;
pub mod io;
pub mod irq;
pub mod memory;
pub mod object_manager;
pub mod pnp;
pub mod request;
pub mod runtime;
pub mod status;

#[cfg(test)]
mod test;

use alloc::sync::Arc;
pub use kernel_macros::RequestPayload;
pub use request::{RequestPayload, RequestPayloadInto};
use x86_64::VirtAddr;

use crate::async_ffi::FfiFuture;
use crate::device::{DevNode, DeviceObject};
use crate::pnp::DriverStep;
use crate::request::{Request, RequestHandle};
use crate::status::DriverStatus;
pub const PHYSICAL_MEMORY_OFFSET: VirtAddr = VirtAddr::new(0xFFFF_8000_0000_0000);
pub type EvtDriverDeviceAdd = extern "win64" fn(
    driver: &Arc<device::DriverObject>,
    init: &mut device::DeviceInit,
) -> DriverStep;
pub type EvtDriverUnload =
    extern "win64" fn(driver: Arc<device::DriverObject>) -> FfiFuture<DriverStep>;

pub type EvtIoRead = for<'req, 'data, 'b> extern "win64" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, 'data>,
    usize,
) -> FfiFuture<DriverStep>;
pub type EvtIoWrite = for<'req, 'data, 'b> extern "win64" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, 'data>,
    usize,
) -> FfiFuture<DriverStep>;
pub type EvtIoDeviceControl = for<'req, 'data, 'b> extern "win64" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, 'data>,
) -> FfiFuture<DriverStep>;
pub type EvtIoFs = for<'req, 'data, 'b> extern "win64" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, 'data>,
) -> FfiFuture<DriverStep>;
pub type EvtIoFlush = for<'req, 'data, 'b> extern "win64" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, 'data>,
) -> FfiFuture<DriverStep>;

pub type ClassAddCallback = extern "win64" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type CompletionRoutine<'data> =
    extern "win64" fn(request: &mut Request<'data>, context: usize) -> DriverStatus;
pub type PnpMinorCallback = for<'req, 'data, 'b> extern "win64" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, 'data>,
) -> FfiFuture<DriverStep>;

pub type DpcFn = extern "win64" fn(usize);

#[unsafe(export_name = "_fltused")]
static _FLTUSED: i32 = 0;

#[unsafe(no_mangle)]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
