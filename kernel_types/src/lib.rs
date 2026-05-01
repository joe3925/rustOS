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

pub mod async_ffi;
pub mod async_types;
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
