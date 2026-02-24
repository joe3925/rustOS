#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::{
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};
use i8042::probe_i8042;
use kernel_api::println;
use kernel_api::{
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{io::IoVtable, pnp::DeviceIds},
    pnp::{
        DriverStep, PnpMinorFunction, PnpVtable, QueryIdType, driver_set_evt_device_add,
        pnp_create_child_devnode_and_pdo_with_init,
    },
    request::RequestHandle,
    request_handler,
    status::DriverStatus,
};

pub mod i8042;
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());
#[panic_handler]
#[cfg(not(test))]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    panic_common(MOD_NAME, info)
}
#[repr(C)]
pub struct DevExt {
    probed: AtomicBool,
    have_kbd: AtomicBool,
    have_mouse: AtomicBool,
}

#[repr(C)]
pub struct Ps2ChildExt {
    is_kbd: bool,
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, ps2_device_add);
    DriverStatus::Success
}

pub extern "win64" fn ps2_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut pnp = PnpVtable::new();
    pnp.set(PnpMinorFunction::StartDevice, ps2_start);
    pnp.set(PnpMinorFunction::QueryDeviceRelations, ps2_query_devrels);

    dev_init.pnp_vtable = Some(pnp);
    dev_init.set_dev_ext_from(DevExt {
        probed: AtomicBool::new(false),
        have_kbd: AtomicBool::new(false),
        have_mouse: AtomicBool::new(false),
    });
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn ps2_start<'a, 'b>(
    dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    if let Ok(ext) = dev.try_devext::<DevExt>() {
        if !ext.probed.swap(true, Ordering::Release) {
            let (have_kbd, have_mouse) = unsafe { probe_i8042() };
            ext.have_kbd.store(have_kbd, Ordering::Release);
            ext.have_mouse.store(have_mouse, Ordering::Release);
        }
    } else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    }
    DriverStep::Continue
}

#[request_handler]
pub async fn ps2_query_devrels<'a, 'b>(
    device: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    use kernel_api::pnp::DeviceRelationType;
    let relation = req.read().pnp.as_ref().unwrap().relation;
    if relation != DeviceRelationType::BusRelations {
        return DriverStep::complete(DriverStatus::NotImplemented);
    }

    let devnode: Arc<DevNode> = match device.dev_node.get().unwrap().upgrade() {
        Some(dn) => dn,
        None => {
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    let ext = match device.try_devext::<DevExt>() {
        Ok(g) => g,
        Err(_) => {
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    if ext.have_kbd.load(Ordering::Acquire) {
        make_child_pdo(
            &devnode,
            true,
            "I8042\\PNP0303",
            &["PS2\\Keyboard"],
            &["INPUT\\Keyboard", "INPUT\\GenericKbd"],
            "\\I8042\\Kbd0",
            "\\Device\\Ps2Keyboard",
        );
    }
    if ext.have_mouse.load(Ordering::Acquire) {
        make_child_pdo(
            &devnode,
            false,
            "I8042\\PNP0F13",
            &["PS2\\Mouse"],
            &["INPUT\\Pointer", "INPUT\\GenericMouse"],
            "\\I8042\\Mouse0",
            "\\Device\\Ps2Mouse",
        );
    }

    DriverStep::complete(DriverStatus::Success)
}

fn make_child_pdo(
    parent: &Arc<DevNode>,
    is_kbd: bool,
    hw_primary: &str,
    hw_extra: &[&str],
    compat: &[&str],
    instance_id: &str,
    name: &str,
) {
    let ids = DeviceIds {
        hardware: {
            let mut v = Vec::with_capacity(1 + hw_extra.len());
            v.push(hw_primary.into());
            for s in hw_extra {
                v.push((*s).into());
            }
            v
        },
        compatible: compat.iter().map(|s| (*s).into()).collect(),
    };

    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::QueryId, ps2_child_query_id);
    vt.set(PnpMinorFunction::StartDevice, ps2_child_start);

    let mut child_init = DeviceInit::new(IoVtable::new(), Some(vt));
    child_init.set_dev_ext_from(Ps2ChildExt { is_kbd });

    let (_dn, _pdo) = pnp_create_child_devnode_and_pdo_with_init(
        parent,
        name.into(),
        instance_id.into(),
        ids,
        None,
        child_init,
    );
}

#[request_handler]
async fn ps2_child_query_id<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let is_kbd = match dev.try_devext::<Ps2ChildExt>() {
        Ok(ext) => ext.is_kbd,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    {
        let mut r = req.write();
        let p = r.pnp.as_mut().unwrap();

        match p.id_type {
            QueryIdType::HardwareIds => {
                if is_kbd {
                    p.ids_out.push("PS2\\Keyboard".into());
                    p.ids_out.push("ACPI\\PNP0303".into());
                } else {
                    p.ids_out.push("PS2\\Mouse".into());
                    p.ids_out.push("ACPI\\PNP0F13".into());
                }
            }
            QueryIdType::CompatibleIds => {
                if is_kbd {
                    p.ids_out.push("INPUT\\Keyboard".into());
                    p.ids_out.push("INPUT\\GenericKbd".into());
                } else {
                    p.ids_out.push("INPUT\\Pointer".into());
                    p.ids_out.push("INPUT\\GenericMouse".into());
                }
            }
            QueryIdType::DeviceId => {
                p.ids_out.push(
                    if is_kbd {
                        "PS2\\Keyboard"
                    } else {
                        "PS2\\Mouse"
                    }
                    .into(),
                );
            }
            QueryIdType::InstanceId => {
                p.ids_out.push(
                    if is_kbd {
                        "\\I8042\\Kbd0"
                    } else {
                        "\\I8042\\Mouse0"
                    }
                    .into(),
                );
            }
        }
    }
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn ps2_child_start<'a, 'b>(
    _dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}
