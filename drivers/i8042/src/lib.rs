#![no_std]
#![no_main]

extern crate alloc;
use crate::alloc::string::ToString;
use alloc::{string::String, sync::Arc, vec::Vec};
use core::{mem::size_of, panic::PanicInfo};
use kernel_api::{
    alloc_api::{
        ffi::{
            driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
            pnp_forward_request_to_next_lower, pnp_wait_for_request,
        },
        DeviceIds, DeviceInit, IoVtable, PnpVtable,
    },
    DevNode, DeviceObject, DriverObject, DriverStatus, KernelAllocator, PnpMinorFunction,
    QueryIdType, Request, RequestType,
};
use spin::RwLock;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

mod msvc_shims;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel_api::println!("[i8042] {}", info);
    loop {}
}

#[repr(C)]
pub struct DevExt {
    pub have_kbd: bool,
    pub have_mouse: bool,
}

#[repr(C)]
pub struct Ps2ChildExt {
    pub is_kbd: bool,
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, ps2_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn ps2_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, ps2_start);
    pnp_vtable.set(PnpMinorFunction::QueryDeviceRelations, ps2_query_devrels);

    dev_init.dev_ext_size = size_of::<DevExt>();
    dev_init.pnp_vtable = Some(pnp_vtable);
    DriverStatus::Success
}

extern "win64" fn ps2_start(dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStatus {
    let down = unsafe { pnp_forward_request_to_next_lower(dev, req.clone()) };
    if down != DriverStatus::NoSuchDevice {
        unsafe { pnp_wait_for_request(&req) };
        return DriverStatus::Success;
    }

    let mut r = req.write();
    if r.status == DriverStatus::Pending {
        r.status = DriverStatus::Success;
    }

    let ext_ptr = dev.dev_ext.as_ptr() as *mut DevExt;
    unsafe {
        core::ptr::write(
            ext_ptr,
            DevExt {
                have_kbd: true,
                have_mouse: true,
            },
        );
    }
    DriverStatus::Success
}

extern "win64" fn ps2_query_devrels(
    device: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    use kernel_api::DeviceRelationType;
    let relation = req.read().pnp.as_ref().unwrap().relation;
    if relation != DeviceRelationType::BusRelations {
        req.write().status = DriverStatus::Pending;
        return DriverStatus::Pending;
    }

    // Enumerate child PDOs (keyboard/mouse) if present.
    let devnode: Arc<DevNode> = unsafe {
        (*(Arc::as_ptr(device) as *const DeviceObject))
            .dev_node
            .upgrade()
            .expect("[i8042] PDO missing DevNode")
    };
    let ext: &DevExt = unsafe { &*(device.dev_ext.as_ptr() as *const DevExt) };

    if ext.have_kbd {
        make_child_pdo(
            &devnode,
            true,
            "PS2KBD",
            "ACPI\\PNP0303",
            &["PS2\\Keyboard"],
            &["INPUT\\Keyboard", "INPUT\\GenericKbd"],
        );
    }
    if ext.have_mouse {
        make_child_pdo(
            &devnode,
            false,
            "PS2MOU",
            "ACPI\\PNP0F13",
            &["PS2\\Mouse"],
            &["INPUT\\Pointer", "INPUT\\GenericMouse"],
        );
    }

    req.write().status = DriverStatus::Success;
    DriverStatus::Success
}

fn make_child_pdo(
    parent: &Arc<DevNode>,
    is_kbd: bool,
    short: &str,
    hw_acpi_primary: &str,
    hw_extra: &[&str],
    compat: &[&str],
) {
    let ids = DeviceIds {
        hardware: {
            let mut v = Vec::new();
            v.push(hw_acpi_primary.into());
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

    let child_init = DeviceInit {
        dev_ext_size: core::mem::size_of::<Ps2ChildExt>(),
        pnp_vtable: Some(vt),
        io_vtable: IoVtable::new(),
    };

    let name = if is_kbd {
        "\\Device\\Ps2Keyboard"
    } else {
        "\\Device\\Ps2Mouse"
    }
    .to_string();
    let instance = if is_kbd {
        "\\ACPI\\PS2\\Kbd0".to_string()
    } else {
        "\\ACPI\\PS2\\Mouse0".to_string()
    };

    let (_dn, pdo) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(parent, name, instance, ids, None, child_init)
    };

    let ptr_ext = pdo.dev_ext.as_ptr() as *mut Ps2ChildExt;
    unsafe {
        core::ptr::write(ptr_ext, Ps2ChildExt { is_kbd });
    }
}

extern "win64" fn ps2_child_query_id(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let is_kbd = unsafe { (*(dev.dev_ext.as_ptr() as *const Ps2ChildExt)).is_kbd };
    let mut r = req.write();
    let pnp = r.pnp.as_mut().unwrap();

    match pnp.id_type {
        QueryIdType::HardwareIds => {
            if is_kbd {
                pnp.ids_out.push("PS2\\Keyboard".into());
                pnp.ids_out.push("ACPI\\PNP0303".into());
            } else {
                pnp.ids_out.push("PS2\\Mouse".into());
                pnp.ids_out.push("ACPI\\PNP0F13".into());
            }
            r.status = DriverStatus::Success;
        }
        QueryIdType::CompatibleIds => {
            if is_kbd {
                pnp.ids_out.push("INPUT\\Keyboard".into());
                pnp.ids_out.push("INPUT\\GenericKbd".into());
            } else {
                pnp.ids_out.push("INPUT\\Pointer".into());
                pnp.ids_out.push("INPUT\\GenericMouse".into());
            }
            r.status = DriverStatus::Success;
        }
        QueryIdType::DeviceId => {
            if is_kbd {
                pnp.ids_out.push("PS2\\Keyboard".into());
            } else {
                pnp.ids_out.push("PS2\\Mouse".into());
            }
            r.status = DriverStatus::Success;
        }
        QueryIdType::InstanceId => {
            if is_kbd {
                pnp.ids_out.push("\\ACPI\\PS2\\Kbd0".into());
            } else {
                pnp.ids_out.push("\\ACPI\\PS2\\Mouse0".into());
            }
            r.status = DriverStatus::Success;
        }
    }
    DriverStatus::Success
}

extern "win64" fn ps2_child_start(
    _dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let mut r = req.write();
    if r.status == DriverStatus::Pending {
        r.status = DriverStatus::Success;
    }
    DriverStatus::Success
}
