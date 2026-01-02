#![no_std]
#![no_main]
extern crate alloc;
use core::panic::PanicInfo;

use alloc::sync::Arc;
use kernel_api::{
    device::{DeviceInit, DeviceObject, DriverObject},
    pnp::{DriverStep, PnpMinorFunction, PnpVtable, driver_set_evt_device_add},
    println,
    request::Request,
    request_handler,
    status::DriverStatus,
};
use spin::RwLock;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    println!("BaseBusDriver: DriverEntry called.\n");
    driver_set_evt_device_add(driver, bus_driver_device_add);
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_device_add(
    driver: Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> DriverStep {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, bus_driver_prepare_hardware);
    dev_init_ptr.pnp_vtable = Some(pnp_vtable);
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn bus_driver_prepare_hardware(
    device: Arc<DeviceObject>,
    _request: Arc<RwLock<Request>>,
) -> DriverStep {
    println!("BaseBusDriver: EvtDevicePrepareHardware called.\n");
    DriverStep::complete(DriverStatus::Success)
}
