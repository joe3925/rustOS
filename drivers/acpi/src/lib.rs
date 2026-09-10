#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;
mod aml;
mod dev_ext;
mod pdo;
use kernel_api::pnp::QueryDeviceRelations;
use kernel_api::pnp::StartDevice;
use ::aml::aml::{namespace::{AmlName, NamespaceLevelKind}, object::{Object, WrappedObject}, Interpreter};
use alloc::{string::ToString, sync::Arc, vec, vec::Vec};
use aml::{AmlContext, KernelAmlHandler, create_pnp_bus_from_acpi};
use dev_ext::DevExt;
use kernel_api::device::{DevNode, DeviceInit, DeviceObject, DriverObject};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::pnp::{
    DriverStep, PnpOp, PnpOps, driver_set_evt_device_add, get_rsdp,
    pnp_create_child_devnode_and_pdo_with_init,
};
use kernel_api::runtime::spawn_blocking;
use kernel_api::{println, request_handler};
use spin::RwLock;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

use core::str::FromStr;
#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;

    panic_common(MOD_NAME, info)
}
#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> Result<(), kernel_api::error::KernelError> {
    driver_set_evt_device_add(driver, bus_driver_device_add);
    Ok(())
}

pub extern "C" fn bus_driver_device_add(
    _driver: &Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let mut pnp_ops = PnpOps::new();
    pnp_ops.start_device.set(bus_driver_prepare_hardware);
    pnp_ops.query_device_relations.set(enumerate_bus);

    dev_init_ptr.set_dev_ext_default::<DevExt>();
    dev_init_ptr.pnp_ops = Some(pnp_ops);

    Ok(DriverStep::Complete)
}

#[request_handler]
pub async fn bus_driver_prepare_hardware<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut StartDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let Some(rsdp) = get_rsdp() else { return Ok(DriverStep::Continue); };

    let parsed = spawn_blocking(move || -> Result<AmlContext, ()> {
        let handler = KernelAmlHandler;
        let tables = unsafe { ::aml::AcpiTables::from_rsdp(handler.clone(), rsdp as usize) }.map_err(|e| { println!("[ACPI] ERROR: parse tables: {:?}", e); })?;
        let platform = ::aml::platform::AcpiPlatform::new(tables, handler).map_err(|e| { println!("[ACPI] ERROR: create platform: {:?}", e); })?;
        let aml_ctx = Interpreter::new_from_platform(&platform).map_err(|e| { println!("[ACPI] ERROR: parse AML: {:?}", e); })?;
        aml_ctx.initialize_namespace();
        if let Ok(pic_path) = AmlName::from_str("\\_PIC") {
            let _ = aml_ctx.evaluate(pic_path, vec![WrappedObject::new(Object::Integer(1))]);
        }

        Ok(aml_ctx)
    })
    .await;

    let Ok(aml_ctx) = parsed else {
        return Ok(DriverStep::Continue);
    };

    let dev_ext: &DevExt = &device.try_devext().expect("Failed to get dev ext ACPI");
    dev_ext.ctx.call_once(|| Arc::new(RwLock::new(aml_ctx)));

    Ok(DriverStep::Continue)
}

#[request_handler]
pub async fn enumerate_bus<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut QueryDeviceRelations,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let dev_ext: &DevExt = &device.try_devext().expect("Failed to get dev ext ACPI");

    let parent_dev_node = device
        .dev_node
        .get()
        .unwrap()
        .upgrade()
        .expect("ACPI PDO has no DevNode");
    let devices_to_report: Vec<AmlName> = {
        let mut v = Vec::new();
        let _ = dev_ext
            .ctx
            .get()
            .unwrap()
            .write()
            .namespace.lock()
            .traverse(|name, level| {
                if matches!(level.kind, NamespaceLevelKind::Device) {
                    let s = name.to_string();
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
        create_pnp_bus_from_acpi(dev_ext.ctx.get().unwrap(), &parent_dev_node, dev_name);
    }
    create_synthetic_i8042_pdo(&parent_dev_node);

    Ok(DriverStep::Complete)
}
fn create_synthetic_i8042_pdo(parent: &Arc<DevNode>) {
    let ids = DeviceIds {
        hardware: alloc::vec!["ACPI\\I8042".to_string()],
        compatible: alloc::vec![],
    };

    let child_init = DeviceInit::with_pnp(Some(PnpOps::new()));

    let name = "\\Device\\ACPI_I8042".to_string();
    let instance = "ACPI\\I8042\\0".to_string();

    let _ =
        pnp_create_child_devnode_and_pdo_with_init(parent, name, instance, ids, None, child_init);
}
