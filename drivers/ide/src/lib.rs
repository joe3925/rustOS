#![no_std]
#![no_main]
extern crate alloc;
mod dev_ext;
mod msvc_shims;
use core::panic::PanicInfo;

use alloc::sync::Arc;
use kernel_api::{
    alloc_api::{
        ffi::{driver_set_evt_device_add, pnp_complete_request},
        DeviceInit,
    },
    println,
    x86_64::instructions::port::Port,
    DeviceObject, DriverObject, DriverStatus, KernelAllocator,
};

use crate::dev_ext::DevExt;
// User mode -> (IRP_MJ_READ) Class driver -> (IOCTL) IDE driver
// IDE driver completes request and writes data to the buffer

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
    unsafe { driver_set_evt_device_add(driver, ide_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn ide_device_add(
    driver: &Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> DriverStatus {
    dev_init_ptr.dev_ext_size = 0;
    dev_init_ptr.evt_device_prepare_hardware = Some(ide_prepare_hardware);
    dev_init_ptr.io_device_control = Some(ioctl_handler);
    DriverStatus::Success
}
pub extern "win64" fn ioctl_handler(
    device: &Arc<DeviceObject>,
    request: &mut kernel_api::Request,
    code: u32,
) {
    if let Some(ioctl_code) = request.ioctl_code {
        // TODO: figure out a control code
    } else {
        request.status = DriverStatus::InvalidParameter;
        unsafe { pnp_complete_request(request) };
    }
}

pub extern "win64" fn ide_prepare_hardware(device: &Arc<DeviceObject>) -> DriverStatus {
    let command_base = 0x1F0;
    let ctrl_base = 0x3F6;
    let dev_ext: &mut DevExt =
        unsafe { &mut *((&*device.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };
    dev_ext.command_port = Port::new(command_base + 7);
    dev_ext.data_port = Port::new(command_base);
    dev_ext.error_port = Port::new(command_base + 1);
    dev_ext.sector_count_port = Port::new(command_base + 2);
    dev_ext.lba_lo_port = Port::new(command_base + 3);
    dev_ext.lba_mid_port = Port::new(command_base + 4);
    dev_ext.lba_hi_port = Port::new(command_base + 5);
    dev_ext.drive_head_port = Port::new(command_base + 6);
    dev_ext.control_port = Port::new(ctrl_base + 2);
    dev_ext.alternative_command_port = Port::new(ctrl_base);
    DriverStatus::Success
}
