#![no_std]
#![feature(variant_count)]
#![feature(try_trait_v2)]
#![feature(const_type_name)]
#![allow(static_mut_refs)]
#![feature(generic_const_exprs)]
#![feature(specialization)]
#![feature(try_trait_v2_residual)]
#![feature(lazy_type_alias)]
extern crate alloc;
extern crate self as kernel_types;

pub use prost::Message;
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
use crate::pnp::{
    PnpOp, QueryDeviceRelations, QueryId, QueryResources, RegisterDmaBacking, RemoveDevice,
    InitComplete, StartDevice, StopDevice, SurpriseRemoval,
};
use crate::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs, FsAppend, FsClose, FsCreate, FsFlush,
    FsGetInfo, FsOpen, FsRead, FsReadDir, FsRename, FsSeek, FsSetLen, FsWrite, FsZeroRange, Read,
    Write,
};
pub type EvtDriverDeviceAdd =
    extern "C" fn(driver: &Arc<device::DriverObject>, init: &mut device::DeviceInit) -> DriverStep;
pub type EvtDriverUnload =
    extern "C" fn(driver: Arc<device::DriverObject>) -> FfiFuture<DriverStep>;

pub type EvtIoRead =
    for<'a, 'io> extern "C" fn(&'a Arc<DeviceObject>, &'a mut Read<'io>) -> FfiFuture<DriverStep>;

pub type EvtIoWrite =
    for<'a, 'io> extern "C" fn(&'a Arc<DeviceObject>, &'a mut Write<'io>) -> FfiFuture<DriverStep>;
pub type EvtIoDeviceControl = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut DeviceControl<'data>,
) -> FfiFuture<DriverStep>;
pub type EvtIoFlush =
    for<'a> extern "C" fn(&'a Arc<DeviceObject>, &'a mut Flush) -> FfiFuture<DriverStep>;
pub type EvtIoFlushDirty =
    for<'a> extern "C" fn(&'a Arc<DeviceObject>, &'a mut FlushDirty) -> FfiFuture<DriverStep>;
pub type EvtIoFlushOwner =
    for<'a> extern "C" fn(&'a Arc<DeviceObject>, &'a mut FlushOwner) -> FfiFuture<DriverStep>;

pub type EvtFsOpen = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsOpen>,
) -> FfiFuture<DriverStep>;
pub type EvtFsClose = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsClose>,
) -> FfiFuture<DriverStep>;
pub type EvtFsRead = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsRead>,
) -> FfiFuture<DriverStep>;
pub type EvtFsWrite = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsWrite>,
) -> FfiFuture<DriverStep>;
pub type EvtFsFlush = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsFlush>,
) -> FfiFuture<DriverStep>;
pub type EvtFsSeek = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsSeek>,
) -> FfiFuture<DriverStep>;
pub type EvtFsCreate = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsCreate>,
) -> FfiFuture<DriverStep>;
pub type EvtFsRename = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsRename>,
) -> FfiFuture<DriverStep>;
pub type EvtFsReadDir = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsReadDir>,
) -> FfiFuture<DriverStep>;
pub type EvtFsGetInfo = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsGetInfo>,
) -> FfiFuture<DriverStep>;
pub type EvtFsSetLen = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsSetLen>,
) -> FfiFuture<DriverStep>;
pub type EvtFsAppend = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsAppend>,
) -> FfiFuture<DriverStep>;
pub type EvtFsZeroRange = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Fs<'data, FsZeroRange>,
) -> FfiFuture<DriverStep>;

pub type EvtPnpInitComplete = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut InitComplete,
) -> FfiFuture<DriverStep>;
pub type EvtPnpStartDevice = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut StartDevice,
) -> FfiFuture<DriverStep>;
pub type EvtPnpQueryDeviceRelations = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut QueryDeviceRelations,
) -> FfiFuture<DriverStep>;
pub type EvtPnpQueryId =
    for<'a> extern "C" fn(&'a Arc<DeviceObject>, PnpOp, &'a mut QueryId) -> FfiFuture<DriverStep>;
pub type EvtPnpRegisterDmaBacking = for<'a, 'data> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut RegisterDmaBacking<'data>,
) -> FfiFuture<DriverStep>;
pub type EvtPnpQueryResources = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut QueryResources,
) -> FfiFuture<DriverStep>;
pub type EvtPnpSurpriseRemoval = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut SurpriseRemoval,
) -> FfiFuture<DriverStep>;
pub type EvtPnpRemoveDevice = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut RemoveDevice,
) -> FfiFuture<DriverStep>;
pub type EvtPnpStopDevice = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut StopDevice,
) -> FfiFuture<DriverStep>;

pub type ClassAddCallback = extern "C" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type DpcFn = extern "C" fn(usize);

#[unsafe(export_name = "_fltused")]
static _FLTUSED: i32 = 0;

#[cfg(not(any(test, feature = "hosted-tests")))]
#[unsafe(no_mangle)]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}
