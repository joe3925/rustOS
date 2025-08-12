#![no_std]
#![no_main]
extern crate alloc;
mod msvc_shims;
use core::panic::PanicInfo;

use alloc::sync::Arc;
use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator,
    alloc_api::{DeviceInit, ffi::driver_set_evt_device_add},
    println,
};

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    println!("BaseBusDriver: DriverEntry called.\n");
    unsafe { driver_set_evt_device_add(driver, bus_driver_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_device_add(
    driver: &Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> DriverStatus {
    dev_init_ptr.dev_ext_size = 0;
    dev_init_ptr.evt_device_prepare_hardware = Some(bus_driver_prepare_hardware);
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_prepare_hardware(device: &Arc<DeviceObject>) -> DriverStatus {
    println!("BaseBusDriver: EvtDevicePrepareHardware called.\n");
    DriverStatus::Success
}
