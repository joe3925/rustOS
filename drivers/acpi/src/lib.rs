#![no_std]
#![no_main]
#![feature(core_intrinsics)]

extern crate alloc;
mod aml;
mod dev_ext;
mod msvc_shims;
mod pdo;
use core::{intrinsics::size_of, mem, ptr};

use ::aml::{AmlContext, AmlName, DebugVerbosity, LevelType};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use aml::{KernelAmlHandler, PAGE_SIZE, create_pnp_bus_from_acpi};
use dev_ext::DevExt;
use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request,
    alloc_api::{
        DeviceInit,
        ffi::{driver_set_evt_device_add, get_acpi_tables, pnp_send_request},
    },
    ffi::{self},
    println,
    x86_64::PhysAddr,
};
use spin::RwLock;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}
#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, bus_driver_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_device_add(
    _driver: &Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> DriverStatus {
    dev_init_ptr.dev_ext_size = size_of::<DevExt>();
    dev_init_ptr.evt_device_prepare_hardware = Some(bus_driver_prepare_hardware);
    dev_init_ptr.evt_bus_enumerate_devices = Some(enumerate_bus);

    DriverStatus::Success
}

pub extern "win64" fn bus_driver_prepare_hardware(device: &Arc<DeviceObject>) -> DriverStatus {
    let acpi_tables = unsafe { get_acpi_tables() };
    let mut aml_ctx = AmlContext::new(Box::new(KernelAmlHandler), DebugVerbosity::All);

    if let Ok(dsdt) = acpi_tables.dsdt() {
        let bytes = unsafe { map_aml(dsdt.address, dsdt.length as usize) };
        if let Err(e) = aml_ctx.parse_table(bytes) {
            println!("[ACPI] ERROR: parse DSDT: {:?}", e);
        }
    }
    for ssdt in acpi_tables.ssdts() {
        let bytes = unsafe { map_aml(ssdt.address, ssdt.length as usize) };
        if let Err(e) = aml_ctx.parse_table(bytes) {
            println!("[ACPI] ERROR: parse SSDT: {:?}", e);
        }
    }
    if let Err(e) = aml_ctx.initialize_objects() {
        println!("[ACPI] ERROR: initialize AML objects: {:?}", e);
        return DriverStatus::Success;
    }
    assert!(
        device.dev_ext.len() >= mem::size_of::<DevExt>(),
        "Device extension buffer is too small for DevExt"
    );

    let dev_ext_ptr = device.dev_ext.as_ptr() as *const DevExt as *mut DevExt;

    let new_ext = DevExt {
        ctx: RwLock::new(aml_ctx),
    };

    unsafe {
        ptr::write(dev_ext_ptr, new_ext);
    }

    DriverStatus::Success
}
pub unsafe fn map_aml(paddr: usize, len: usize) -> &'static [u8] {
    let offset = paddr & (PAGE_SIZE - 1);
    let base_pa = paddr - offset;
    let need = len + offset;
    let size_rounded = (need + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let va =
        match unsafe { ffi::map_mmio_region(PhysAddr::new(base_pa as u64), size_rounded as u64) } {
            Ok(va) => va,
            Err(e) => {
                kernel_api::println!("[ACPI] map_aml: map_mmio_region failed: {:?}", e);
                core::intrinsics::abort();
            }
        };

    let ptr = (va.as_u64() as usize + offset) as *const u8;
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

pub extern "win64" fn enumerate_bus(
    device: &Arc<DeviceObject>,
    _req: &mut Request,
) -> DriverStatus {
    let dev_ext: &mut DevExt =
        unsafe { &mut *((&*device.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };

    let parent_dev_node = unsafe {
        (*(Arc::as_ptr(device) as *const DeviceObject))
            .dev_node
            .upgrade()
            .expect("ACPI PDO has no DevNode")
    };
    let devices_to_report: Vec<AmlName> = {
        let mut v = Vec::new();
        let _ = dev_ext.ctx.write().namespace.traverse(|name, level| {
            if matches!(level.typ, LevelType::Device) {
                let s = name.as_string();
                let is_sb_child = s.starts_with("\\_SB_.") || s.starts_with("_SB_.");
                if is_sb_child {
                    let path_after_prefix =
                        s.trim_start_matches("\\_SB_.").trim_start_matches("_SB_.");
                    if !path_after_prefix.contains('.') {
                        v.push(name.clone());
                    }
                }
            }
            Ok(true)
        });
        v
    };

    for dev_name in devices_to_report {
        create_pnp_bus_from_acpi(&dev_ext.ctx, &parent_dev_node, dev_name);
    }

    DriverStatus::Success
}
