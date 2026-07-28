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

use crate::async_ffi::AbiFuture;
use crate::device::{DevNode, DeviceObject};
use crate::pnp::DriverStep;
use crate::pnp::{
    InitComplete, PnpOp, QueryDeviceRelations, QueryId, QueryResources, RegisterDmaBacking,
    RemoveDevice, StartDevice, StopDevice, SurpriseRemoval,
};
use crate::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs, FsAppend, FsClose, FsCreate, FsDelete,
    FsFlush, FsGetInfo, FsOpen, FsRead, FsReadDir, FsRemoveDir, FsRename, FsSeek, FsSetLen,
    FsWrite, FsZeroRange, Read, Write,
};
pub type EvtDriverDeviceAdd = extern "C" fn(
    driver: &Arc<device::DriverObject>,
    init: &mut device::DeviceInit,
) -> Result<DriverStep, error::KernelError>;
pub type EvtDriverProbeDevice = extern "C" fn(
    driver: &Arc<device::DriverObject>,
    context: &pnp::ProbeContext,
) -> AbiFuture<pnp::ProbeOutcome>;
pub type EvtDriverUnload = extern "C" fn(
    driver: Arc<device::DriverObject>,
) -> AbiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtIoRead =
    for<'a, 'io> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Read<'io>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtIoWrite =
    for<'a, 'io> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Write<'io>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoDeviceControl =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut DeviceControl<'data>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoFlush = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    &'a mut Flush,
) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoFlushDirty =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut FlushDirty,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtIoFlushOwner =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut FlushOwner,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtFsOpen =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsOpen>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsClose =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsClose>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsRead =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsRead>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsWrite =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsWrite>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsFlush =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsFlush>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsSeek =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsSeek>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsCreate =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsCreate>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsRemoveDir =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsRemoveDir>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsDelete =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsDelete>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsRename =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsRename>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsReadDir =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsReadDir>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsGetInfo =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsGetInfo>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsSetLen =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsSetLen>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsAppend =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsAppend>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtFsZeroRange =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        &'a mut Fs<'data, FsZeroRange>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;

pub type EvtPnpInitComplete =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut InitComplete,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpStartDevice =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut StartDevice,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpQueryDeviceRelations =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut QueryDeviceRelations,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpQueryId = for<'a> extern "C" fn(
    &'a Arc<DeviceObject>,
    PnpOp,
    &'a mut QueryId,
)
    -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpRegisterDmaBacking =
    for<'a, 'data> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut RegisterDmaBacking<'data>,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpQueryResources =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut QueryResources,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpSurpriseRemoval =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut SurpriseRemoval,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpRemoveDevice =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut RemoveDevice,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;
pub type EvtPnpStopDevice =
    for<'a> extern "C" fn(
        &'a Arc<DeviceObject>,
        PnpOp,
        &'a mut StopDevice,
    ) -> AbiFuture<Result<DriverStep, error::KernelError>>;

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
