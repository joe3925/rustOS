#![no_std]
#![no_main]
#![allow(static_mut_refs)]

extern crate alloc;
mod msvc_shims;

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
    Data, DeviceObject, DriverObject, DriverStatus, FsIdentify, GLOBAL_CTRL_LINK,
    GLOBAL_VOLUMES_BASE, IoTarget, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceIds, DeviceInit, IoType, IoVtable, PnpVtable, Synchronization,
        ffi::{
            driver_set_evt_device_add, pnp_create_control_device_and_link,
            pnp_create_device_symlink_top, pnp_create_devnode_over_fdo_with_function,
            pnp_forward_request_to_next_lower, pnp_ioctl_via_symlink, pnp_load_service,
            pnp_remove_symlink, pnp_send_request, pnp_send_request_via_symlink, reg,
        },
    },
    ffi::switch_to_vfs,
    println,
};

#[inline]
fn make_volume_link_name(id: u32) -> String {
    alloc::format!("{}\\{:04}", GLOBAL_VOLUMES_BASE, id)
}

#[derive(Clone, Debug)]
struct FsReg {
    svc: String,
    tag: String,
    ord: u32,
}
static mut FS_REGISTRY: RwLock<Vec<FsReg>> = RwLock::new(Vec::new());
static mut FS_REGISTERED: RwLock<Vec<String>> = RwLock::new(Vec::new());
static VFS_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static mut VOLUMES: RwLock<Vec<alloc::sync::Weak<DeviceObject>>> = RwLock::new(Vec::new());
const MP_ROOT: &str = "SYSTEM/CurrentControlSet/MountMgr/MountPoints";

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

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

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
        pnp_create_control_device_and_link(
            "\\Device\\volclass.ctrl".to_string(),
            init,
            GLOBAL_CTRL_LINK.to_string(),
        )
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
            // identify completion may target another stack; using wait here is acceptable
            kernel_api::alloc_api::ffi::pnp_wait_for_request(&req);
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
    init_volume_dx(dev);
    mount_if_unmounted(dev);
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
            } else {
                let dx = ext_mut::<VolFdoExt>(dev);
                if !dx.public_link.is_empty() {
                    let _ = unsafe { pnp_remove_symlink(dx.public_link.clone()) };
                }
                dx.fs_attached.store(false, Ordering::Release);
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
            rescan_all_volumes();
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
                    drop(wr);
                    rescan_all_volumes();
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

fn dos_name_for(label: u8) -> String {
    let c = (label as char).to_ascii_uppercase();
    alloc::format!("DosDevices\\{}:", c)
}

fn set_label_for_link(public_link: &str, label: u8) -> Result<(), kernel_api::RegError> {
    let _ = reg::create_key(MP_ROOT);
    if let Ok(vals) = reg::list_values(MP_ROOT) {
        for name in vals {
            if let Some(kernel_api::Data::Str(s)) = reg::get_value(MP_ROOT, &name) {
                if s == public_link {
                    let _ = reg::delete_value(MP_ROOT, &name);
                }
            }
        }
    }
    let _ = reg::delete_value(MP_ROOT, &dos_name_for(label));
    reg::set_value(
        MP_ROOT,
        &dos_name_for(label),
        kernel_api::Data::Str(public_link.to_string()),
    )
}

fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]> {
    let len = core::mem::size_of::<T>();
    let p = Box::into_raw(b) as *mut u8;
    unsafe { Box::from_raw(core::slice::from_raw_parts_mut(p, len)) }
}
unsafe fn bytes_to_box<T>(b: Box<[u8]>) -> Box<T> {
    assert_eq!(b.len(), core::mem::size_of::<T>());
    let p = Box::into_raw(b) as *mut u8 as *mut T;
    Box::from_raw(p)
}

#[repr(C)]
struct BootProbe {
    link: String,
    need: AtomicU32,
    mod_ok: AtomicBool,
    inf_ok: AtomicBool,
    hive_ok: AtomicBool,
}

#[repr(C)]
struct BootReqCtx {
    probe: *mut BootProbe,
    which: u8,
}

extern "win64" fn fs_open_boot_check_complete(r: &mut Request, ctx: usize) {
    let reqctx: Box<BootReqCtx> = unsafe { Box::from_raw(ctx as *mut BootReqCtx) };
    let ok = if r.status == DriverStatus::Success
        && r.data.len() == core::mem::size_of::<kernel_api::FsOpenResult>()
    {
        let res: kernel_api::FsOpenResult =
            unsafe { *bytes_to_box(core::mem::replace(&mut r.data, Box::new([]))) };
        res.error.is_none()
    } else {
        false
    };

    let probe = unsafe { &*reqctx.probe };
    match reqctx.which {
        0 => {
            if ok {
                probe.mod_ok.store(true, Ordering::Release);
            }
        }
        1 => {
            if ok {
                probe.inf_ok.store(true, Ordering::Release);
            }
        }
        _ => {
            if ok {
                probe.hive_ok.store(true, Ordering::Release);
            }
        }
    }

    if probe.need.fetch_sub(1, Ordering::AcqRel) == 1 {
        let all = probe.mod_ok.load(Ordering::Acquire)
            && probe.inf_ok.load(Ordering::Acquire)
            && probe.hive_ok.load(Ordering::Acquire);
        if all {
            let _ = attempt_boot_bind(&probe.link);
        }
        unsafe {
            drop(Box::from_raw(reqctx.probe));
        }
    }
}

fn send_fs_open_async(public_link: &str, path: &str, which: u8, probe_ptr: *mut BootProbe) {
    let params = kernel_api::FsOpenParams {
        flags: kernel_api::OpenFlags::Open,
        path: path.to_string(),
    };
    let mut req = Request::new(
        RequestType::Fs(kernel_api::FsOp::Open),
        box_to_bytes(Box::new(params)),
    );
    let ctx = Box::into_raw(Box::new(BootReqCtx {
        probe: probe_ptr,
        which,
    })) as usize;
    req.set_completion(fs_open_boot_check_complete, ctx);
    let req = Arc::new(RwLock::new(req));
    println!("Sending request {:#x?}", req.read().id);
    unsafe {
        let e = kernel_api::alloc_api::ffi::pnp_send_request_via_symlink(
            public_link.to_string(),
            req.clone(),
        );
        println!("send via symlink: {:#?}", e);
    }
}

fn start_boot_probe_async(public_link: &str) {
    let probe = Box::new(BootProbe {
        link: public_link.to_string(),
        need: AtomicU32::new(3),
        mod_ok: AtomicBool::new(false),
        inf_ok: AtomicBool::new(false),
        hive_ok: AtomicBool::new(false),
    });
    let probe_ptr = Box::into_raw(probe);
    println!("start probe");
    send_fs_open_async(public_link, "\\SYSTEM\\MOD", 0, probe_ptr);
    send_fs_open_async(public_link, "\\SYSTEM\\TOML", 1, probe_ptr);
    send_fs_open_async(public_link, "\\SYSTEM\\REGISTRY.BIN", 2, probe_ptr);
}

fn assign_c_for(dev_link: &str) {
    let _ = set_label_for_link(dev_link, b'C');
    let _ = unsafe {
        kernel_api::alloc_api::ffi::pnp_replace_symlink(
            alloc::format!("\\GLOBAL\\DosDevices\\C:"),
            dev_link.to_string(),
        )
    };
}
fn attempt_boot_bind(public_link: &str) -> DriverStatus {
    if VFS_ACTIVE.load(Ordering::Acquire) {
        return DriverStatus::Success;
    }
    match unsafe { switch_to_vfs() } {
        Ok(()) => {
            VFS_ACTIVE.store(true, Ordering::Release);
            assign_c_for(public_link);
            DriverStatus::Success
        }
        Err(_) => DriverStatus::Unsuccessful,
    }
}

fn rescan_all_volumes() {
    let vols = unsafe { VOLUMES.read().clone() };
    for w in vols {
        if let Some(dev) = w.upgrade() {
            let dx = ext_mut::<VolFdoExt>(&dev);
            if dx.fs_attached.load(Ordering::Acquire) {
                continue;
            }
            if dx.public_link.is_empty() {
                continue;
            }

            if try_bind_filesystems_for_parent_fdo(&dev, &dx.public_link) {
                dx.fs_attached.store(true, Ordering::Release);
                start_boot_probe_async(&dx.public_link);
            }
        }
    }
}

fn init_volume_dx(dev: &Arc<DeviceObject>) {
    let vid = NEXT_VOL_ID.fetch_add(1, Ordering::AcqRel);
    let inst = dev.dev_node.upgrade().unwrap().instance_path.clone();

    let dx = ext_mut::<VolFdoExt>(dev);
    *dx = VolFdoExt::blank();
    dx.inst_path = inst;
    dx.public_link = make_volume_link_name(vid);

    unsafe { VOLUMES.write().push(Arc::downgrade(dev)) };
}

fn mount_if_unmounted(dev: &Arc<DeviceObject>) {
    let dx = ext_mut::<VolFdoExt>(dev);
    if dx.fs_attached.load(Ordering::Acquire) || dx.public_link.is_empty() {
        return;
    }
    if try_bind_filesystems_for_parent_fdo(dev, &dx.public_link) {
        dx.fs_attached.store(true, Ordering::Release);
        start_boot_probe_async(&dx.public_link);
        println!("mounted");
    }
}
