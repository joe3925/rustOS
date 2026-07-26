#![no_std]
#![feature(variant_count)]
#![feature(try_trait_v2)]
#![feature(const_type_name)]
#![allow(static_mut_refs)]
#![feature(generic_const_exprs)]
#![feature(specialization)]
#![feature(try_trait_v2_residual)]
#![feature(lazy_type_alias)]
#![feature(allocator_api)]
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
pub mod error;
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
pub mod protocol;
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
    InitComplete, PnpOp, QueryDeviceRelations, QueryId, QueryResources, RegisterDmaBacking,
    RemoveDevice, StartDevice, StopDevice, SurpriseRemoval,
};
use crate::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs, FsAppend, FsClose, FsCreate, FsFlush,
    FsGetInfo, FsOpen, FsRead, FsReadDir, FsRename, FsSeek, FsSetLen, FsWrite, FsZeroRange, Read,
    Write,
};
pub type EvtDriverDeviceAdd = extern "C" fn(
    driver: &Arc<device::DriverObject>,
    init: &mut device::DeviceInit,
) -> Result<DriverStep, error::KernelError>;
pub type EvtDriverProbeDevice = extern "C" fn(
    driver: &Arc<device::DriverObject>,
    context: &pnp::ProbeContext,
) -> FfiFuture<pnp::ProbeOutcome>;
pub type EvtDriverUnload = extern "C" fn(
    driver: Arc<device::DriverObject>,
) -> FfiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtIoRead =
    for<'a, 'io> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Read<'io>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtIoWrite =
    for<'a, 'io> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Write<'io>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoDeviceControl =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut DeviceControl<'data>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoFlush = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Flush,
) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoFlushDirty =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut FlushDirty,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoFlushOwner =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut FlushOwner,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtFsOpen =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsOpen>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsClose =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsClose>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsRead =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsRead>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsWrite =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsWrite>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsFlush =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsFlush>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsSeek =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsSeek>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsCreate =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsCreate>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsRename =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsRename>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsReadDir =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsReadDir>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsGetInfo =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsGetInfo>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsSetLen =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsSetLen>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsAppend =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsAppend>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsZeroRange =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsZeroRange>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtPnpInitComplete =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut InitComplete,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpStartDevice =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut StartDevice,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpQueryDeviceRelations =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut QueryDeviceRelations,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpQueryId = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut QueryId,
)
    -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpRegisterDmaBacking =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut RegisterDmaBacking<'data>,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpQueryResources =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut QueryResources,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpSurpriseRemoval =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut SurpriseRemoval,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpRemoveDevice =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut RemoveDevice,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpStopDevice =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut StopDevice,
    ) -> FfiFuture<Result<DriverStep, error::KernelError>>;

pub type ClassEventCallback =
    extern "C" fn(node: Arc<DevNode>, event: pnp::DeviceEvent, listener_dev: &Arc<DeviceObject>);
pub type DpcFn = extern "C" fn(usize);

#[unsafe(export_name = "_fltused")]
static _FLTUSED: i32 = 0;

#[cfg(not(any(test, feature = "hosted-tests")))]
#[unsafe(no_mangle)]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}
