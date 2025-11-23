#![no_std]
#![feature(variant_count)]
#![feature(try_trait_v2)]

extern crate alloc;

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

use crate::device::{DevNode, DeviceObject};
use crate::request::Request;
use crate::status::DriverStatus;
use spin::RwLock;
pub type BoxedIoFuture = Pin<Box<dyn Future<Output = DriverStatus> + Send + 'static>>;
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub type EvtDriverDeviceAdd = extern "win64" fn(
    driver: Arc<device::DriverObject>,
    init: &mut device::DeviceInit,
) -> DriverStatus;
pub type EvtDriverUnload = extern "win64" fn(driver: Arc<device::DriverObject>) -> DriverStatus;

pub type EvtIoRead = fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> BoxedIoFuture;
pub type EvtIoWrite = fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> BoxedIoFuture;
pub type EvtIoDeviceControl = fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> BoxedIoFuture;
pub type EvtIoFs = fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> BoxedIoFuture;

pub type EvtDevicePrepareHardware = extern "win64" fn(Arc<DeviceObject>) -> DriverStatus;
pub type EvtDeviceEnumerateDevices =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> DriverStatus;

pub type ClassAddCallback = extern "win64" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type CompletionRoutine =
    extern "win64" fn(request: &mut Request, context: usize) -> DriverStatus;
pub type PnpMinorCallback =
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> DriverStatus;

pub type DpcFn = extern "win64" fn(usize);
