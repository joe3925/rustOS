#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
#[cfg(not(test))]
use core::panic::PanicInfo;
use kernel_api::println;
use kernel_api::KernelAllocator;
use kernel_api::{
    alloc_api::{
        ffi::{driver_set_evt_device_add, pnp_complete_request, pnp_forward_request_to_next_lower},
        DeviceInit,
    },
    DeviceObject, DriverObject, DriverStatus, Request,
};
mod msvc_shims;
#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, disk_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn disk_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = 0;

    dev_init.io_read = Some(disk_read);
    dev_init.io_write = Some(disk_write);

    DriverStatus::Success
}

pub extern "win64" fn disk_read(
    device: &Arc<DeviceObject>,
    request: &mut Request,
    _buf_len: usize,
) {
    let st = unsafe { pnp_forward_request_to_next_lower(device, request) };
    if st == DriverStatus::NoSuchDevice {
        request.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(request) };
    }
}

pub extern "win64" fn disk_write(
    device: &Arc<DeviceObject>,
    request: &mut Request,
    _buf_len: usize,
) {
    let st = unsafe { pnp_forward_request_to_next_lower(device, request) };
    if st == DriverStatus::NoSuchDevice {
        request.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(request) };
    }
}
