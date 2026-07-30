#![no_std]
#![no_main]
extern crate alloc;
use kernel_api::pnp::StartDevice;
use core::panic::PanicInfo;

use alloc::sync::Arc;
use kernel_api::{
    device::{DeviceInit, DeviceObject, DriverObject},
    pnp::{DriverStep, PnpOp, PnpOps, driver_set_evt_device_add},
    println, request_handler,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> Result<(), kernel_api::error::KernelError> {
    println!("BaseBusDriver: DriverEntry called.\n");
    driver_set_evt_device_add(driver, bus_driver_device_add);
    Ok(())
}

pub extern "C" fn bus_driver_device_add(
    _driver: &Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let mut pnp_ops = PnpOps::new();
    println!("BaseBusDriver: EvtDeviceAdd called.\n");
    pnp_ops.start_device.set(bus_driver_prepare_hardware);
    dev_init_ptr.pnp_ops = Some(pnp_ops);
    Ok(DriverStep::Complete)
}

#[request_handler]
pub async fn bus_driver_prepare_hardware<'req, 'data, 'b>(
    _device: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut StartDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    println!("BaseBusDriver: EvtDevicePrepareHardware called.\n");
    Ok(DriverStep::Complete)
}
