#![no_std]
#![feature(variant_count)]
#![feature(try_trait_v2)]

extern crate alloc;

pub mod async_ffi;
pub mod benchmark;
pub mod device;
pub mod fs;
pub mod io;
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
use crate::request::Request;
use crate::status::DriverStatus;
use spin::RwLock;

pub type EvtDriverDeviceAdd = extern "win64" fn(
    driver: Arc<device::DriverObject>,
    init: &mut device::DeviceInit,
) -> DriverStatus;
pub type EvtDriverUnload =
    extern "win64" fn(driver: Arc<device::DriverObject>) -> FfiFuture<DriverStatus>;

pub type EvtIoRead =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> FfiFuture<DriverStatus>;
pub type EvtIoWrite =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> FfiFuture<DriverStatus>;
pub type EvtIoDeviceControl =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStatus>;
pub type EvtIoFs =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStatus>;

pub type EvtDevicePrepareHardware = extern "win64" fn(Arc<DeviceObject>) -> FfiFuture<DriverStatus>;
pub type EvtDeviceEnumerateDevices =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStatus>;

pub type ClassAddCallback = extern "win64" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type CompletionRoutine =
    extern "win64" fn(request: &mut Request, context: usize) -> DriverStatus;
pub type PnpMinorCallback =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> FfiFuture<DriverStatus>;

pub type DpcFn = extern "win64" fn(usize);
