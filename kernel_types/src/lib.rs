#![no_std]
#![feature(variant_count)]
#![feature(try_trait_v2)]

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
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;

use crate::async_ffi::FfiFuture;
use crate::device::{DevNode, DeviceObject};
use crate::pnp::DriverStep;
use crate::request::Request;
use crate::status::DriverStatus;
use spin::RwLock;

pub type EvtDriverDeviceAdd = extern "win64" fn(
    driver: Arc<device::DriverObject>,
    init: &mut device::DeviceInit,
) -> DriverStep;
pub type EvtDriverUnload =
    extern "win64" fn(driver: Arc<device::DriverObject>) -> FfiFuture<DriverStep>;

pub type EvtIoRead =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> FfiFuture<DriverStep>;
pub type EvtIoWrite =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> FfiFuture<DriverStep>;
pub type EvtIoDeviceControl =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStep>;
pub type EvtIoFs =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStep>;

pub type EvtDevicePrepareHardware = extern "win64" fn(Arc<DeviceObject>) -> FfiFuture<DriverStep>;
pub type EvtDeviceEnumerateDevices =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStep>;

pub type ClassAddCallback = extern "win64" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type CompletionRoutine =
    extern "win64" fn(request: &mut Request, context: usize) -> DriverStatus;
pub type PnpMinorCallback =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStep>;

pub type DpcFn = extern "win64" fn(usize);
