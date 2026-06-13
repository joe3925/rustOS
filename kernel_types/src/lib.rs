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
#![feature(try_trait_v2_residual)]
extern crate alloc;
extern crate self as kernel_types;

pub use prost::Message as ProstMessage;
pub mod arch;
pub mod async_ffi;
pub mod async_types;
pub mod bench_archive;
pub mod benchmark;
pub mod bounded_mpmc;
pub mod device;
pub mod dma;
pub mod fdt;
pub mod fixed_slab;
pub mod fs;
pub mod io;
pub mod irq;
pub mod memory;
pub mod object_manager;
pub mod pci;
pub mod pnp;
pub mod port;
pub mod request;
pub mod runtime;
pub mod status;

#[cfg(test)]
mod test;

use alloc::sync::Arc;
pub use kernel_macros::RequestPayload;
pub use request::{RequestPayload, RequestPayloadInto};

use crate::async_ffi::FfiFuture;
use crate::device::{DevNode, DeviceObject};
use crate::pnp::DriverStep;
use crate::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs, FsAppend, FsClose, FsCreate, FsFlush,
    FsGetInfo, FsOpen, FsRead, FsReadDir, FsRename, FsSeek, FsSetLen, FsWrite, FsZeroRange, Pnp,
    Read, Request, RequestHandle, RequestKind, Write,
};
use crate::status::DriverStatus;
pub type EvtDriverDeviceAdd =
    extern "C" fn(driver: &Arc<device::DriverObject>, init: &mut device::DeviceInit) -> DriverStep;
pub type EvtDriverUnload =
    extern "C" fn(driver: Arc<device::DriverObject>) -> FfiFuture<DriverStep>;

pub type EvtIoRead = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Read<'data>>,
    usize,
) -> FfiFuture<DriverStep>;
pub type EvtIoWrite = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Write<'data>>,
    usize,
) -> FfiFuture<DriverStep>;
pub type EvtIoDeviceControl = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, DeviceControl<'data>>,
) -> FfiFuture<DriverStep>;
pub type EvtIoFlush = for<'req, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Flush>,
) -> FfiFuture<DriverStep>;
pub type EvtIoFlushDirty = for<'req, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, FlushDirty>,
) -> FfiFuture<DriverStep>;
pub type EvtIoFlushOwner = for<'req, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, FlushOwner>,
) -> FfiFuture<DriverStep>;

pub type EvtFsOpen = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsOpen>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsClose = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsClose>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsRead = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsRead>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsWrite = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsWrite>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsFlush = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsFlush>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsSeek = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsSeek>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsCreate = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsCreate>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsRename = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsRename>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsReadDir = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsReadDir>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsGetInfo = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsGetInfo>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsSetLen = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsSetLen>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsAppend = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsAppend>>,
) -> FfiFuture<DriverStep>;
pub type EvtFsZeroRange = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Fs<'data, FsZeroRange>>,
) -> FfiFuture<DriverStep>;

pub type ClassAddCallback = extern "C" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type CompletionRoutine<K: RequestKind> =
    extern "C" fn(request: &mut Request<K>, context: usize) -> DriverStatus;
pub type PnpMinorCallback = for<'req, 'data, 'b> extern "C" fn(
    &Arc<DeviceObject>,
    &'b mut RequestHandle<'req, Pnp<'data>>,
) -> FfiFuture<DriverStep>;
pub type DpcFn = extern "C" fn(usize);

#[unsafe(export_name = "_fltused")]
static _FLTUSED: i32 = 0;

#[cfg(not(any(test, feature = "hosted-tests")))]
#[unsafe(no_mangle)]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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
