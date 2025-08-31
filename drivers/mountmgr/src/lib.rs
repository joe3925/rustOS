#![no_std]
#![no_main]
#![allow(static_mut_refs)]

extern crate alloc;

use crate::alloc::vec;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    mem::size_of,
    panic::PanicInfo,
    ptr, slice,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use spin::RwLock;

use kernel_api::{
    Data, DeviceObject, DriverObject, DriverStatus, FsIdentify, IoTarget, KernelAllocator, Request,
    RequestType,
    alloc_api::{
        DeviceInit,
        ffi::{
            driver_set_evt_device_add, pnp_create_control_device_and_link,
            pnp_create_device_symlink_top, pnp_forward_request_to_next_lower,
            pnp_get_device_target, pnp_ioctl_via_symlink, pnp_load_service, pnp_remove_symlink,
            pnp_wait_for_request, reg,
        },
    },
    println,
};

mod msvc_shims;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

const IOCTL_MOUNTMGR_REGISTER_FS: u32 = 0x4D4D_0001;
const IOCTL_MOUNTMGR_UNMOUNT: u32 = 0x4D4D_0002;
const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;
const IOCTL_MOUNTMGR_RESYNC: u32 = 0x4D4D_0004;
const IOCTL_MOUNTMGR_LIST_FS: u32 = 0x4D4D_0005;
const IOCTL_FS_IDENTIFY: u32 = 0x4653_0002;

const VOLUME_LINK_BASE: &str = "\\Volumes";
const CTRL_LINK: &str = "\\MountMgr";
const CTRL_NAME: &str = "\\Device\\volclass.ctrl";

#[inline]
fn make_volume_link_name(id: u32) -> String {
    alloc::format!("{}\\{:04}", VOLUME_LINK_BASE, id)
}

#[derive(Clone, Debug)]
struct FsReg {
    svc: String,
    tag: String,
    ord: u32,
}
static mut FS_REGISTRY: RwLock<Vec<FsReg>> = RwLock::new(Vec::new());
static mut FS_REGISTERED: RwLock<Vec<String>> = RwLock::new(Vec::new());

fn refresh_fs_registry_from_registry() -> usize {
    const ROOT: &str = "SYSTEM/CurrentControlSet/MountMgr/Filesystems";
    let mut add: Vec<FsReg> = Vec::new();

    if let Ok(keys) = reg::list_keys(ROOT) {
        for sub in keys {
            let svc = match reg::get_value(&sub, "Service") {
                Some(Data::Str(s)) if !s.is_empty() => s,
                _ => continue,
            };
            let link = match reg::get_value(&sub, "ControlLink") {
                Some(Data::Str(s)) if !s.is_empty() => s,
                _ => continue,
            };
            let order = match reg::get_value(&sub, "Order") {
                Some(Data::U32(v)) => v,
                _ => 100,
            };
            let _ = unsafe { pnp_load_service(svc.clone()) };
            add.push(FsReg {
                svc,
                tag: link,
                ord: order,
            });
        }
    }

    add.sort_by(|a, b| a.ord.cmp(&b.ord).then_with(|| a.tag.cmp(&b.tag)));

    let mut added = 0usize;
    unsafe {
        let mut wr = FS_REGISTRY.write();
        for r in add {
            if !wr.iter().any(|e| e.tag == r.tag) {
                wr.push(r);
                added += 1;
            }
        }
    }
    added
}

fn list_fs_blob() -> Box<[u8]> {
    let s = unsafe {
        let rd = FS_REGISTRY.read();
        let mut out = String::new();
        for (i, r) in rd.iter().enumerate() {
            if i != 0 {
                out.push('\n');
            }
            out.push_str(&r.tag);
        }
        out
    };
    s.into_bytes().into_boxed_slice()
}

#[repr(C)]
struct VolFdoExt {
    inst_path: String,
    public_link: String,
    fs_attached: AtomicBool,
    fs_ctrl: Option<Arc<DeviceObject>>,
}
impl VolFdoExt {
    fn blank() -> Self {
        Self {
            inst_path: String::new(),
            public_link: String::new(),
            fs_attached: AtomicBool::new(false),
            fs_ctrl: None,
        }
    }
}

#[repr(C)]
struct CtrlDevExt;

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

static NEXT_VOL_ID: AtomicU32 = AtomicU32::new(1);

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, volclass_device_add) };

    let mut init = DeviceInit {
        dev_ext_size: size_of::<CtrlDevExt>(),
        io_read: None,
        io_write: None,
        io_device_control: Some(volclass_ctrl_ioctl),
        evt_device_prepare_hardware: None,
        evt_bus_enumerate_devices: None,
        evt_pnp: None,
    };
    let _ctrl = unsafe {
        pnp_create_control_device_and_link(CTRL_NAME.to_string(), init, CTRL_LINK.to_string())
    };

    let _ = refresh_fs_registry_from_registry();
    DriverStatus::Success
}

pub extern "win64" fn volclass_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = size_of::<VolFdoExt>();
    dev_init.evt_device_prepare_hardware = Some(volclass_start);
    dev_init.io_device_control = Some(volclass_ioctl);
    dev_init.io_read = Some(vol_pdo_read);
    dev_init.io_write = Some(vol_pdo_write);
    DriverStatus::Success
}

extern "win64" fn volclass_start(dev: &Arc<DeviceObject>) -> DriverStatus {
    let vid = NEXT_VOL_ID.fetch_add(1, Ordering::AcqRel);
    let io_target = IoTarget {
        target_device: dev.clone(),
    };
    let inst = dev.dev_node.upgrade().unwrap().instance_path.clone();
    {
        let dx = ext_mut::<VolFdoExt>(dev);
        *dx = VolFdoExt::blank();
        dx.inst_path = inst.clone();
        dx.public_link = make_volume_link_name(vid);
    }

    let _ = refresh_fs_registry_from_registry();
    let vol = Arc::new(io_target);

    for tag in unsafe { FS_REGISTERED.read().clone() } {
        // Build FsIdentify payload in-place inside Request::data
        let payload = Box::new(FsIdentify {
            volume_fdo: vol.clone(),
            mount_device: None,
            can_mount: false,
        });
        let len = core::mem::size_of::<FsIdentify>();
        let ptr = Box::into_raw(payload) as *mut u8;
        let data: Box<[u8]> = unsafe { Box::from_raw(core::slice::from_raw_parts_mut(ptr, len)) };

        let req_arc = Arc::new(RwLock::new(Request::new(
            RequestType::DeviceControl(IOCTL_FS_IDENTIFY),
            data,
        )));

        unsafe {
            let _ = pnp_ioctl_via_symlink(tag.clone(), IOCTL_FS_IDENTIFY, req_arc.clone());
            pnp_wait_for_request(&req_arc.clone());
        }

        // Examine and act on the result
        let mut guard = req_arc.write();

        if guard.status != DriverStatus::Success {
            let raw = core::mem::replace(&mut guard.data, Box::<[u8]>::from([]));
            drop(guard);
            let _owned: Box<FsIdentify> =
                unsafe { Box::from_raw(Box::into_raw(raw) as *mut u8 as *mut FsIdentify) };
            continue;
        }

        let id_ref: &FsIdentify = unsafe { &*(guard.data.as_ptr() as *const FsIdentify) };

        if !id_ref.can_mount {
            let raw = core::mem::replace(&mut guard.data, Box::<[u8]>::from([]));
            drop(guard);
            let _owned: Box<FsIdentify> =
                unsafe { Box::from_raw(Box::into_raw(raw) as *mut u8 as *mut FsIdentify) };
            continue;
        }

        if let Some(ctrl) = &id_ref.mount_device {
            {
                let dx = ext_mut::<VolFdoExt>(dev);
                dx.fs_ctrl = Some(ctrl.clone());
                dx.fs_attached.store(true, Ordering::Release);
            }
            let _ = unsafe {
                pnp_create_device_symlink_top(
                    inst.clone(),
                    ext_mut::<VolFdoExt>(dev).public_link.clone(),
                )
            };

            let raw = core::mem::replace(&mut guard.data, Box::<[u8]>::from([]));
            drop(guard);
            let _owned: Box<FsIdentify> =
                unsafe { Box::from_raw(Box::into_raw(raw) as *mut u8 as *mut FsIdentify) };
            break;
        }

        let raw = core::mem::replace(&mut guard.data, Box::<[u8]>::from([]));
        drop(guard);
        let _owned: Box<FsIdentify> =
            unsafe { Box::from_raw(Box::into_raw(raw) as *mut u8 as *mut FsIdentify) };
    }

    DriverStatus::Success
}

fn build_status_blob(dev: &Arc<DeviceObject>) -> Box<[u8]> {
    let dx = ext_mut::<VolFdoExt>(dev);
    let claimed = if dx.fs_attached.load(Ordering::Acquire) {
        1
    } else {
        0
    };
    let s = alloc::format!("claimed={};public={}", claimed, dx.public_link);
    s.into_bytes().into_boxed_slice()
}

fn string_from_req(req: &Request) -> Option<String> {
    core::str::from_utf8(&req.data)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).to_string())
}

// FDO IOCTL
pub extern "win64" fn volclass_ioctl(dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => {
                drop(r);
                let _ = unsafe { pnp_forward_request_to_next_lower(dev, req) };
                return;
            }
        }
    };

    match code {
        IOCTL_MOUNTMGR_UNMOUNT => {
            let target = {
                let r = req.read();
                string_from_req(&r).unwrap_or_default()
            };
            if !target.is_empty() {
                let _ = unsafe { pnp_remove_symlink(target) };
            }
            {
                ext_mut::<VolFdoExt>(dev)
                    .fs_attached
                    .store(false, Ordering::Release);
                ext_mut::<VolFdoExt>(dev).fs_ctrl = None;
            }
            req.write().status = DriverStatus::Success;
        }
        IOCTL_MOUNTMGR_QUERY => {
            let mut w = req.write();
            w.data = build_status_blob(dev);
            w.status = DriverStatus::Success;
        }
        IOCTL_MOUNTMGR_RESYNC => {
            let _ = refresh_fs_registry_from_registry();
            req.write().status = DriverStatus::Success;
        }
        IOCTL_MOUNTMGR_LIST_FS => {
            let mut w = req.write();
            w.data = list_fs_blob();
            w.status = DriverStatus::Success;
        }
        _ => {
            let _ = unsafe { pnp_forward_request_to_next_lower(dev, req) };
        }
    }
}

// Control device IOCTL (MountMgr root)
pub extern "win64" fn volclass_ctrl_ioctl(_dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => {
                drop(r);
                req.write().status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };

    match code {
        IOCTL_MOUNTMGR_REGISTER_FS => {
            let tag = {
                let r = req.read();
                string_from_req(&r)
            };
            match tag {
                Some(t) if !t.is_empty() => unsafe {
                    let mut wr = FS_REGISTERED.write();
                    if !wr.iter().any(|s| s == &t) {
                        wr.push(t);
                    }
                    req.write().status = DriverStatus::Success;
                },
                _ => {
                    req.write().status = DriverStatus::InvalidParameter;
                }
            }
        }
        _ => {
            req.write().status = DriverStatus::NotImplemented;
        }
    }
}
pub extern "win64" fn vol_pdo_read(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    parent.write().status = DriverStatus::Pending;
}

pub extern "win64" fn vol_pdo_write(
    dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    parent.write().status = DriverStatus::Pending;
}
