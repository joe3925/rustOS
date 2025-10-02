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
    slice,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use spin::RwLock;

use kernel_api::{
    CTRL_LINK, CTRL_NAME, Data, DeviceObject, DriverObject, DriverStatus, FsIdentify, IoTarget,
    KernelAllocator, Request, RequestType, VOLUME_LINK_BASE,
    alloc_api::{
        DeviceIds, DeviceInit, IoType, IoVtable, PnpVtable, Synchronization,
        ffi::{
            driver_set_evt_device_add, pnp_create_control_device_and_link,
            pnp_create_device_symlink_top, pnp_create_devnode_over_fdo_with_function,
            pnp_forward_request_to_next_lower, pnp_ioctl_via_symlink, pnp_load_service,
            pnp_remove_symlink, pnp_send_request, pnp_send_request_via_symlink,
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

const IOCTL_FS_CREATE_FUNCTION_FDO: u32 = 0x4653_3001;

#[repr(C)]
struct FsCreateFdoResp {
    function_fdo: Option<Arc<DeviceObject>>,
}

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
}
impl VolFdoExt {
    fn blank() -> Self {
        Self {
            inst_path: String::new(),
            public_link: String::new(),
            fs_attached: AtomicBool::new(false),
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
    let mut io_vtable = IoVtable::new();
    io_vtable.set(
        IoType::DeviceControl(volclass_ctrl_ioctl),
        Synchronization::Sync,
        0,
    );
    let mut init = DeviceInit {
        dev_ext_size: size_of::<CtrlDevExt>(),
        pnp_vtable: None,
        io_vtable,
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
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(kernel_api::PnpMinorFunction::StartDevice, volclass_start);

    dev_init
        .io_vtable
        .set(IoType::Read(vol_fdo_read), Synchronization::Sync, 0);
    dev_init
        .io_vtable
        .set(IoType::Write(vol_fdo_write), Synchronization::Sync, 0);
    dev_init.io_vtable.set(
        IoType::DeviceControl(volclass_ioctl),
        Synchronization::Sync,
        0,
    );

    dev_init.dev_ext_size = size_of::<VolFdoExt>();
    dev_init.pnp_vtable = Some(pnp_vtable);

    DriverStatus::Success
}

fn svc_for_tag(tag: &str) -> Option<String> {
    unsafe {
        FS_REGISTRY
            .read()
            .iter()
            .find(|r| r.tag == tag)
            .map(|r| r.svc.clone())
    }
}

fn try_bind_filesystems_for_parent_fdo(parent_fdo: &Arc<DeviceObject>, public_link: &str) -> bool {
    let _ = refresh_fs_registry_from_registry();

    let vid = NEXT_VOL_ID.load(Ordering::Acquire);
    let inst_suffix = alloc::format!("FSINST.{:04X}", vid);
    let parent_inst = parent_fdo.dev_node.upgrade().unwrap().instance_path.clone();
    let instance_path = alloc::format!("{}\\{}", parent_inst, inst_suffix);
    let ids = DeviceIds {
        hardware: vec![alloc::format!("VIRT\\FSINST#{}", inst_suffix)],
        compatible: Vec::new(),
    };
    let class = Some("FileSystem".to_string());

    let vol_target = Arc::new(IoTarget {
        target_device: parent_fdo.clone(),
    });
    let tags = unsafe { FS_REGISTERED.read().clone() };

    for tag in tags {
        // build FsIdentify on the heap
        let mut id = Box::new(FsIdentify {
            volume_fdo: vol_target.clone(),
            mount_device: None,
            can_mount: false,
        });
        let len = core::mem::size_of::<FsIdentify>();
        let ptr = Box::into_raw(id) as *mut u8;
        let data: Box<[u8]> = unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr, len)) };

        let req = Arc::new(RwLock::new(Request::new(
            RequestType::DeviceControl(kernel_api::IOCTL_FS_IDENTIFY),
            data,
        )));

        unsafe {
            let _ = pnp_ioctl_via_symlink(tag.clone(), kernel_api::IOCTL_FS_IDENTIFY, req.clone());
            pnp_wait_for_request(&req);
        }

        let mut w = req.write();
        if w.status != DriverStatus::Success || w.data.len() < len {
            continue;
        }

        let id_ref: &FsIdentify = unsafe { &*(w.data.as_ptr() as *const FsIdentify) };
        if !id_ref.can_mount {
            continue;
        }
        let Some(function_fdo) = id_ref.mount_device.as_ref() else {
            continue;
        };

        let svc = match svc_for_tag(&tag) {
            Some(s) => s,
            None => continue,
        };

        match unsafe {
            pnp_create_devnode_over_fdo_with_function(
                &parent_fdo.clone(),
                instance_path.clone(),
                ids.clone(),
                class.clone(),
                &svc,
                &function_fdo.clone(),
            )
        } {
            Ok((_dn, _top)) => {
                let _ = unsafe {
                    pnp_create_device_symlink_top(instance_path.clone(), public_link.to_string())
                };
                return true;
            }
            Err(_) => continue,
        }
    }
    false
}
extern "win64" fn volclass_start(
    dev: &Arc<DeviceObject>,
    _request: Arc<RwLock<kernel_api::Request>>,
) -> DriverStatus {
    let vid = NEXT_VOL_ID.fetch_add(1, Ordering::AcqRel);
    let inst = dev.dev_node.upgrade().unwrap().instance_path.clone();

    {
        let dx = ext_mut::<VolFdoExt>(dev);
        *dx = VolFdoExt::blank();
        dx.inst_path = inst.clone();
        dx.public_link = make_volume_link_name(vid);
    }

    let linked = try_bind_filesystems_for_parent_fdo(dev, &ext_mut::<VolFdoExt>(dev).public_link);

    if linked {
        ext_mut::<VolFdoExt>(dev)
            .fs_attached
            .store(true, Ordering::Release);
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
            ext_mut::<VolFdoExt>(dev)
                .fs_attached
                .store(false, Ordering::Release);
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

pub extern "win64" fn vol_fdo_read(
    _dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    unsafe { pnp_forward_request_to_next_lower(_dev, parent) };
}

pub extern "win64" fn vol_fdo_write(
    _dev: &Arc<DeviceObject>,
    parent: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    unsafe { pnp_forward_request_to_next_lower(_dev, parent) };
}
