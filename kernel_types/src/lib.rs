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
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::ptr;

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    ptr::copy_nonoverlapping(src, dst, n);
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    ptr::copy(src, dst, n);
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    ptr::write_bytes(dst, c as u8, n);
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    while i < n {
        let av = *a.add(i);
        let bv = *b.add(i);
        if av != bv {
            return av as i32 - bv as i32;
        }
        i += 1;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut i = 0usize;
    while *s.add(i) != 0 {
        i += 1;
    }
    i
}
