#![no_std]
#![feature(variant_count)]
#![feature(try_trait_v2)]
#![feature(negative_impls)]
#![feature(auto_traits)]
#![feature(specialization)]
#![feature(const_type_name)]
extern crate alloc;

pub mod async_ffi;
pub mod async_types;
pub mod benchmark;
pub mod device;
pub mod fs;
pub mod io;
pub mod irq;
pub mod memory;
pub mod pnp;
pub mod request;
pub mod status;
use alloc::sync::Arc;

use crate::async_ffi::{BorrowingFfiFuture, FfiFuture};
use crate::device::{DevNode, DeviceObject};
use crate::pnp::DriverStep;
use crate::request::{Request, RequestHandle};
use crate::status::DriverStatus;

pub type EvtDriverDeviceAdd = extern "win64" fn(
    driver: Arc<device::DriverObject>,
    init: &mut device::DeviceInit,
) -> DriverStep;
pub type EvtDriverUnload =
    extern "win64" fn(driver: Arc<device::DriverObject>) -> FfiFuture<DriverStep>;

pub type EvtIoRead = for<'a, 'b> extern "win64" fn(
    Arc<DeviceObject>,
    &'b mut RequestHandle<'a>,
    usize,
) -> BorrowingFfiFuture<'b, DriverStep>;
pub type EvtIoWrite = for<'a, 'b> extern "win64" fn(
    Arc<DeviceObject>,
    &'b mut RequestHandle<'a>,
    usize,
) -> BorrowingFfiFuture<'b, DriverStep>;
pub type EvtIoDeviceControl = for<'a, 'b> extern "win64" fn(
    Arc<DeviceObject>,
    &'b mut RequestHandle<'a>,
) -> BorrowingFfiFuture<'b, DriverStep>;
pub type EvtIoFs = for<'a, 'b> extern "win64" fn(
    Arc<DeviceObject>,
    &'b mut RequestHandle<'a>,
) -> BorrowingFfiFuture<'b, DriverStep>;

pub type ClassAddCallback = extern "win64" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type CompletionRoutine =
    extern "win64" fn(request: &mut Request, context: usize) -> DriverStatus;
pub type PnpMinorCallback = for<'a, 'b> extern "win64" fn(
    Arc<DeviceObject>,
    &'b mut RequestHandle<'a>,
) -> BorrowingFfiFuture<'b, DriverStep>;

pub type DpcFn = extern "win64" fn(usize);
