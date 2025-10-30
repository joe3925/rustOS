#![no_std]
#![no_main]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{mem::size_of, panic::PanicInfo};
use kernel_api::{
    alloc_api::{
        ffi::pnp_create_child_devnode_and_pdo_with_init, DeviceIds, DeviceInit, IoVtable, PnpVtable,
    },
    DevNode, DeviceObject, DriverObject, DriverStatus, KernelAllocator, PnpMinorFunction,
    QueryIdType, Request,
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
    probed: bool,
    have_kbd: bool,
    have_mouse: bool,
}

#[repr(C)]
pub struct Ps2ChildExt {
    is_kbd: bool,
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    use kernel_api::alloc_api::ffi::driver_set_evt_device_add;
    unsafe { driver_set_evt_device_add(driver, ps2_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn ps2_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    let mut pnp = PnpVtable::new();
    pnp.set(PnpMinorFunction::StartDevice, ps2_start);
    pnp.set(PnpMinorFunction::QueryDeviceRelations, ps2_query_devrels);

    dev_init.dev_ext_size = size_of::<DevExt>();
    dev_init.pnp_vtable = Some(pnp);
    DriverStatus::Success
}

extern "win64" fn ps2_start(dev: &Arc<DeviceObject>, _req: Arc<RwLock<Request>>) -> DriverStatus {
    let ext: &mut DevExt = unsafe { &mut *(dev.dev_ext.as_ptr() as *mut DevExt) };
    if !ext.probed {
        let (have_kbd, have_mouse) = unsafe { probe_i8042() };
        *ext = DevExt {
            probed: true,
            have_kbd,
            have_mouse,
        };
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
            "ACPI\\PNP0303",
            &["PS2\\Keyboard"],
            &["INPUT\\Keyboard", "INPUT\\GenericKbd"],
            "\\I8042\\Kbd0",
            "\\Device\\Ps2Keyboard",
        );
    }
    if ext.have_mouse {
        make_child_pdo(
            &devnode,
            false,
            "ACPI\\PNP0F13",
            &["PS2\\Mouse"],
            &["INPUT\\Pointer", "INPUT\\GenericMouse"],
            "\\I8042\\Mouse0",
            "\\Device\\Ps2Mouse",
        );
    }

    req.write().status = DriverStatus::Success;
    DriverStatus::Success
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

    let child_init = DeviceInit {
        dev_ext_size: core::mem::size_of::<Ps2ChildExt>(),
        pnp_vtable: Some(vt),
        io_vtable: IoVtable::new(),
    };

    let (_dn, pdo) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(
            parent,
            name.into(),
            instance_id.into(),
            ids,
            None,
            child_init,
        )
    };

    let ptr_ext = pdo.dev_ext.as_ptr() as *mut Ps2ChildExt;
    unsafe { core::ptr::write(ptr_ext, Ps2ChildExt { is_kbd }) };
}

extern "win64" fn ps2_child_query_id(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let is_kbd = unsafe { (*(dev.dev_ext.as_ptr() as *const Ps2ChildExt)).is_kbd };
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
            r.status = DriverStatus::Success;
        }
        QueryIdType::CompatibleIds => {
            if is_kbd {
                p.ids_out.push("INPUT\\Keyboard".into());
                p.ids_out.push("INPUT\\GenericKbd".into());
            } else {
                p.ids_out.push("INPUT\\Pointer".into());
                p.ids_out.push("INPUT\\GenericMouse".into());
            }
            r.status = DriverStatus::Success;
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
            r.status = DriverStatus::Success;
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

/* --- minimal i8042 probing --- */

const I8042_DATA: u16 = 0x60;
const I8042_STS: u16 = 0x64;
const I8042_CMD: u16 = 0x64;

const STS_OBF: u8 = 1 << 0;
const STS_IBF: u8 = 1 << 1;

unsafe fn inb(p: u16) -> u8 {
    let v: u8;
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("in al, dx", in("dx") p, out("al") v, options(nomem, nostack, preserves_flags));
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = p;
        v = 0;
    }
    v
}
unsafe fn outb(p: u16, v: u8) {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("out dx, al", in("dx") p, in("al") v, options(nomem, nostack, preserves_flags));
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (p, v);
    }
}

unsafe fn wait_ibf_clear(timeout_iters: u32) -> bool {
    let mut i = 0;
    while i < timeout_iters {
        if (inb(I8042_STS) & STS_IBF) == 0 {
            return true;
        }
        i += 1;
    }
    false
}
unsafe fn wait_obf_set(timeout_iters: u32) -> Option<u8> {
    let mut i = 0;
    while i < timeout_iters {
        if (inb(I8042_STS) & STS_OBF) != 0 {
            return Some(inb(I8042_DATA));
        }
        i += 1;
    }
    None
}
unsafe fn flush_ob(timeout_iters: u32) {
    let mut i = 0;
    while i < timeout_iters {
        if (inb(I8042_STS) & STS_OBF) == 0 {
            break;
        }
        let _ = inb(I8042_DATA);
        i += 1;
    }
}

unsafe fn cmd(c: u8) -> bool {
    if !wait_ibf_clear(100000) {
        return false;
    }
    outb(I8042_CMD, c);
    true
}
unsafe fn write_data(v: u8) -> bool {
    if !wait_ibf_clear(100000) {
        return false;
    }
    outb(I8042_DATA, v);
    true
}
unsafe fn read_data() -> Option<u8> {
    wait_obf_set(100000)
}

unsafe fn probe_i8042() -> (bool, bool) {
    // Disable both ports (ignore failures)
    let _ = cmd(0xAD);
    let _ = cmd(0xA7);
    flush_ob(10000);

    // Self-test
    if !cmd(0xAA) {
        return (false, false);
    }
    let ok = matches!(read_data(), Some(0x55));
    if !ok {
        return (false, false);
    }

    if !cmd(0x20) {
        return (false, false);
    }
    let mut cbyte = match read_data() {
        Some(v) => v,
        None => return (false, false),
    };
    cbyte &= !(1 << 6);
    cbyte &= !(1 << 0);
    cbyte &= !(1 << 1);
    if !cmd(0x60) || !write_data(cbyte) {
        return (false, false);
    }

    let have_kbd = cmd(0xAB) && matches!(read_data(), Some(0x00));
    let mut have_mouse = cmd(0xA9) && matches!(read_data(), Some(0x00));

    if !have_mouse {
        let _ = cmd(0xA8);
        let _ = cmd(0xD4);
        let _ = write_data(0xFF);
        let a = read_data();
        if matches!(a, Some(0xFA)) {
            let b = read_data();
            have_mouse =
                matches!(b, Some(0xAA)) || matches!(b, Some(0x00)) || matches!(b, Some(0xAA));
        }
        let _ = cmd(0xA7);
        flush_ob(10000);
    }

    if have_kbd {
        let _ = cmd(0xAE);
    }
    if have_mouse {
        let _ = cmd(0xA8);
    }

    (have_kbd, have_mouse)
}
