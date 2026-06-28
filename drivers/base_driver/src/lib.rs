#![no_std]
#![no_main]
extern crate alloc;
use core::panic::PanicInfo;

use alloc::sync::Arc;
use kernel_api::{
    device::{DeviceInit, DeviceObject, DriverObject},
    pnp::{DriverStep, PnpOp, PnpOps, driver_set_evt_device_add},
    println, request_handler,
    status::DriverStatus,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    println!("BaseBusDriver: DriverEntry called.\n");
    driver_set_evt_device_add(driver, bus_driver_device_add);
    DriverStatus::Success
}

pub extern "C" fn bus_driver_device_add(
    _driver: &Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> DriverStep {
    let mut pnp_ops = PnpOps::new();
    println!("BaseBusDriver: EvtDeviceAdd called.\n");
    pnp_ops.start_device.set(bus_driver_prepare_hardware);
    dev_init_ptr.pnp_ops = Some(pnp_ops);
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn bus_driver_prepare_hardware<'req, 'data, 'b>(
    _device: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut kernel_api::pnp::StartDevice,
) -> DriverStep {
    println!("BaseBusDriver: EvtDevicePrepareHardware called.\n");
    DriverStep::complete(DriverStatus::Success)
}
