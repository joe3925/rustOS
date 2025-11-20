#![no_std]
#![no_main]
extern crate alloc;
mod msvc_shims;
use core::panic::PanicInfo;

use alloc::sync::Arc;
use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, PnpMinorFunction, Request,
    alloc_api::{DeviceInit, PnpVtable, ffi::driver_set_evt_device_add},
    println,
};
use spin::RwLock;

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
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, bus_driver_prepare_hardware);
    dev_init_ptr.pnp_vtable = Some(pnp_vtable);
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_prepare_hardware(
    device: &Arc<DeviceObject>,
    _request: Arc<RwLock<Request>>,
) -> DriverStatus {
    println!("BaseBusDriver: EvtDevicePrepareHardware called.\n");
    DriverStatus::Continue
}
