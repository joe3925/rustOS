#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;
mod aml;
mod dev_ext;
mod pdo;
use ::aml::{AmlContext, AmlName, DebugVerbosity, LevelType};
use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use aml::{KernelAmlHandler, PAGE_SIZE, create_pnp_bus_from_acpi};
use dev_ext::DevExt;
use kernel_api::device::{DevNode, DeviceInit, DeviceObject, DriverObject};
use kernel_api::kernel_types::io::IoVtable;
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::memory::map_mmio_region;
use kernel_api::pnp::{
    DriverStep, PnpMinorFunction, PnpVtable, driver_set_evt_device_add, get_acpi_tables,
    pnp_create_child_devnode_and_pdo_with_init,
};
use kernel_api::request::RequestHandle;
use kernel_api::runtime::spawn_blocking;
use kernel_api::status::DriverStatus;
use kernel_api::x86_64::PhysAddr;
use kernel_api::{println, request_handler};
use spin::RwLock;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;

    unsafe { panic_common(MOD_NAME, info) }
}
#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, bus_driver_device_add);
    DriverStatus::Success
}

pub extern "win64" fn bus_driver_device_add(
    _driver: Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> DriverStep {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, bus_driver_prepare_hardware);
    pnp_vtable.set(PnpMinorFunction::QueryDeviceRelations, enumerate_bus);

    dev_init_ptr.set_dev_ext_default::<DevExt>();
    dev_init_ptr.pnp_vtable = Some(pnp_vtable);

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn bus_driver_prepare_hardware<'a>(
    device: Arc<DeviceObject>,
    req: RequestHandle<'a>,
) -> RequestHandleResult<'a> {
    let (dsdt, ssdts) = {
        let acpi_tables = get_acpi_tables();

        let dsdt = acpi_tables
            .dsdt()
            .ok()
            .map(|t| (t.address, t.length as usize));

        let mut ssdts = Vec::new();
        for t in acpi_tables.ssdts() {
            ssdts.push((t.address, t.length as usize));
        }

        (dsdt, ssdts)
    };

    let parsed = spawn_blocking(move || -> Result<AmlContext, ()> {
        let mut aml_ctx = AmlContext::new(Box::new(KernelAmlHandler), DebugVerbosity::All);

        if let Some((addr, len)) = dsdt {
            let bytes = unsafe { map_aml(addr, len) };
            if let Err(e) = aml_ctx.parse_table(bytes) {
                println!("[ACPI] ERROR: parse DSDT: {:?}", e);
            }
        }

        for (addr, len) in ssdts {
            let bytes = unsafe { map_aml(addr, len) };
            if let Err(e) = aml_ctx.parse_table(bytes) {
                println!("[ACPI] ERROR: parse SSDT: {:?}", e);
            }
        }

        if let Err(e) = aml_ctx.initialize_objects() {
            println!("[ACPI] ERROR: initialize AML objects: {:?}", e);
            return Err(());
        }

        // Inform firmware we are using APIC mode so _PRT returns GSIs
        if let Ok(pic_path) = AmlName::from_str("\\_PIC") {
            let args = ::aml::value::Args([
                Some(::aml::value::AmlValue::Integer(1)),
                None,
                None,
                None,
                None,
                None,
                None,
            ]);
            let _ = aml_ctx.invoke_method(&pic_path, args);
        }

        Ok(aml_ctx)
    })
    .await;

    let Ok(aml_ctx) = parsed else {
        return req.cont();
    };

    let dev_ext: &DevExt = &device.try_devext().expect("Failed to get dev ext ACPI");
    dev_ext.ctx.call_once(|| Arc::new(RwLock::new(aml_ctx)));

    req.cont()
}
pub unsafe fn map_aml(paddr: usize, len: usize) -> &'static [u8] {
    let offset = paddr & (PAGE_SIZE - 1);
    let base_pa = paddr - offset;
    let need = len + offset;
    let size_rounded = (need + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let va = match map_mmio_region(PhysAddr::new(base_pa as u64), size_rounded as u64) {
        Ok(va) => va,
        Err(e) => {
            kernel_api::println!("[ACPI] map_aml: map_mmio_region failed: {:?}", e);
            core::intrinsics::abort();
        }
    };

    let ptr = (va.as_u64() as usize + offset) as *const u8;
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

#[request_handler]
pub async fn enumerate_bus<'a>(
    device: Arc<DeviceObject>,
    req: RequestHandle<'a>,
) -> RequestHandleResult<'a> {
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
            .namespace
            .traverse(|name, level| {
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
        create_pnp_bus_from_acpi(dev_ext.ctx.get().unwrap(), &parent_dev_node, dev_name);
    }
    create_synthetic_i8042_pdo(&parent_dev_node);

    req.complete(DriverStatus::Success)
}
fn create_synthetic_i8042_pdo(parent: &Arc<DevNode>) {
    let ids = DeviceIds {
        hardware: alloc::vec!["ACPI\\I8042".to_string()],
        compatible: alloc::vec![],
    };

    let child_init = DeviceInit::new(IoVtable::new(), Some(PnpVtable::new()));

    let name = "\\Device\\ACPI_I8042".to_string();
    let instance = "ACPI\\I8042\\0".to_string();

    let _ =
        pnp_create_child_devnode_and_pdo_with_init(parent, name, instance, ids, None, child_init);
}
