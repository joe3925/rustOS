#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod msvc_shims;

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
use spin::{Once, RwLock};

use kernel_api::{
    Data, DevExtRef, DeviceObject, DriverObject, DriverStatus, FsIdentify, GLOBAL_CTRL_LINK,
    GLOBAL_VOLUMES_BASE, IoTarget, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceIds, DeviceInit, IoType, IoVtable, PnpVtable, Synchronization,
        ffi::{
            driver_set_evt_device_add, pnp_create_control_device_and_link,
            pnp_create_device_symlink_top, pnp_create_devnode_over_pdo_with_function,
            pnp_create_symlink, pnp_forward_request_to_next_lower, pnp_ioctl_via_symlink,
            pnp_load_service, pnp_remove_symlink, pnp_send_request_via_symlink, reg,
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

static FS_REGISTRY: RwLock<Vec<FsReg>> = RwLock::new(Vec::new());
static FS_REGISTERED: RwLock<Vec<String>> = RwLock::new(Vec::new());
static VFS_ACTIVE: AtomicBool = AtomicBool::new(false);
static VOLUMES: RwLock<Vec<Arc<DeviceObject>>> = RwLock::new(Vec::new());
const MP_ROOT: &str = "SYSTEM/CurrentControlSet/MountMgr/MountPoints";

#[repr(C)]
#[derive(Default)]
struct VolFdoExt {
    inst_path: Once<String>,
    public_link: Once<String>,
    fs_link: Once<String>,
    fs_attached: AtomicBool,
    vid: Once<u32>,
}

#[inline]
fn ext<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("Failed to get mountmgr dev ext")
}

static NEXT_VOL_ID: AtomicU32 = AtomicU32::new(1);

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::alloc_api::ffi::panic_common;
    unsafe { panic_common(MOD_NAME, info) }
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

    let init = DeviceInit::new(io_vtable, None);
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

    dev_init.set_dev_ext_default::<VolFdoExt>();
    dev_init.pnp_vtable = Some(pnp_vtable);

    let _ = refresh_fs_registry_from_registry();
    DriverStatus::Success
}

extern "win64" fn volclass_start(
    dev: &Arc<DeviceObject>,
    _request: Arc<RwLock<kernel_api::Request>>,
) -> DriverStatus {
    let _ = refresh_fs_registry_from_registry();
    init_volume_dx(dev);
    mount_if_unmounted(dev);
    DriverStatus::Success
}

pub extern "win64" fn vol_fdo_read(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    unsafe { pnp_forward_request_to_next_lower(dev, req) };
}

pub extern "win64" fn vol_fdo_write(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) {
    unsafe { pnp_forward_request_to_next_lower(dev, req) };
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
                let dx = ext::<VolFdoExt>(dev);
                if let Some(pl) = dx.public_link.get() {
                    let _ = unsafe { pnp_remove_symlink(pl.clone()) };
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
            mount_if_unmounted(dev);
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
                    let _ = refresh_fs_registry_from_registry();
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

fn init_volume_dx(dev: &Arc<DeviceObject>) {
    let vid = NEXT_VOL_ID.fetch_add(1, Ordering::AcqRel);
    let inst = dev
        .dev_node
        .get()
        .unwrap()
        .upgrade()
        .unwrap()
        .instance_path
        .clone();

    let dx = ext::<VolFdoExt>(dev);
    dx.inst_path.call_once(|| inst);
    dx.public_link.call_once(|| make_volume_link_name(vid));
    dx.vid.call_once(|| vid);

    let mut v = unsafe { VOLUMES.write() };
    if !v.iter().any(|d| Arc::ptr_eq(d, dev)) {
        v.push(dev.clone());
    }
}

fn mount_if_unmounted(dev: &Arc<DeviceObject>) {
    {
        let dx = ext::<VolFdoExt>(dev);
        if dx
            .fs_attached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
    }

    let dx = ext::<VolFdoExt>(dev);
    let public = dx.public_link.get().cloned().unwrap_or_default();
    if public.is_empty() {
        dx.fs_attached.store(false, Ordering::Release);
        return;
    }

    if try_bind_filesystems_for_parent_fdo(dev, &public) {
        let link = dx.fs_link.get().cloned().unwrap_or_else(|| public.clone());
        let inst = dx.inst_path.get().cloned().unwrap_or_default();
        start_boot_probe_async(&link, &inst);
    } else {
        dx.fs_attached.store(false, Ordering::Release);
    }
}

fn try_bind_filesystems_for_parent_fdo(parent_fdo: &Arc<DeviceObject>, public_link: &str) -> bool {
    let _ = refresh_fs_registry_from_registry();
    let dx_vol = ext::<VolFdoExt>(parent_fdo);
    let vid = dx_vol.vid.get().copied().unwrap_or(0);
    let inst_suffix = alloc::format!("FSINST.{:04X}", vid);
    let parent_dn = match parent_fdo.dev_node.get().unwrap().upgrade() {
        Some(x) => x,
        None => {
            return false;
        }
    };
    let parent_inst = parent_dn.instance_path.clone();
    let fs_inst = alloc::format!("{}\\{}", parent_inst, inst_suffix);

    let ids = DeviceIds {
        hardware: alloc::vec![alloc::format!("VIRT\\FSINST#{}", inst_suffix)],
        compatible: Vec::new(),
    };
    let class = Some("FileSystem".to_string());

    let vol_target = Arc::new(IoTarget {
        target_device: parent_fdo.clone(),
    });
    let tags = unsafe { FS_REGISTERED.read().clone() };

    for tag in tags {
        let id_box = Box::new(FsIdentify {
            volume_fdo: vol_target.clone(),
            mount_device: None,
            can_mount: false,
        });
        let len = core::mem::size_of::<FsIdentify>();
        let ptr = Box::into_raw(id_box) as *mut u8;
        let data: Box<[u8]> = unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr, len)) };

        let req = Arc::new(RwLock::new(Request::new(
            RequestType::DeviceControl(kernel_api::IOCTL_FS_IDENTIFY),
            data,
        )));
        unsafe {
            let _ = pnp_ioctl_via_symlink(tag.clone(), kernel_api::IOCTL_FS_IDENTIFY, req.clone());
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

        let created = unsafe {
            pnp_create_devnode_over_pdo_with_function(
                &parent_dn,
                fs_inst.clone(),
                ids.clone(),
                class.clone(),
                &svc,
                &function_fdo.clone(),
                DeviceInit::new(IoVtable::new(), None),
            )
        };

        if let Ok((dn, _top)) = created {
            let primary_link = public_link.to_string();
            let compat_link = alloc::format!("\\GLOBAL\\Mounts\\{:04}", vid);

            let _ = unsafe {
                pnp_create_device_symlink_top(dn.instance_path.clone(), primary_link.clone())
            };
            let _ = unsafe {
                pnp_create_device_symlink_top(dn.instance_path.clone(), compat_link.clone())
            };

            let dx = ext::<VolFdoExt>(parent_fdo);
            dx.fs_link.call_once(|| primary_link);
            return true;
        }
    }

    false
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

fn build_status_blob(dev: &Arc<DeviceObject>) -> Box<[u8]> {
    let dx = ext::<VolFdoExt>(dev);
    let claimed = if dx.fs_attached.load(Ordering::Acquire) {
        1
    } else {
        0
    };
    let link = dx
        .fs_link
        .get()
        .cloned()
        .or_else(|| dx.public_link.get().cloned())
        .unwrap_or_default();
    let s = alloc::format!("claimed={};public={}", claimed, link);
    s.into_bytes().into_boxed_slice()
}

fn string_from_req(req: &Request) -> Option<String> {
    core::str::from_utf8(&req.data)
        .ok()
        .map(|s| s.trim_matches(core::char::from_u32(0).unwrap()).to_string())
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

fn refresh_fs_registry_from_registry() -> usize {
    use alloc::collections::{BTreeMap, BTreeSet};

    const ROOT: &str = "SYSTEM/CurrentControlSet/MountMgr/Filesystems";

    let (old_regs, old_svcs): (Vec<FsReg>, BTreeSet<String>) = unsafe {
        let rd = FS_REGISTRY.read();
        let svcs = rd.iter().map(|r| r.svc.clone()).collect();
        (rd.clone(), svcs)
    };

    let mut by_tag: BTreeMap<String, FsReg> = BTreeMap::new();
    if let Ok(keys) = reg::list_keys(ROOT) {
        for sub in keys {
            let svc = match reg::get_value(&sub, "Service") {
                Some(Data::Str(s)) if !s.is_empty() => s,
                _ => continue,
            };
            let tag = match reg::get_value(&sub, "ControlLink") {
                Some(Data::Str(s)) if !s.is_empty() => s,
                _ => continue,
            };
            let ord = match reg::get_value(&sub, "Order") {
                Some(Data::U32(v)) => v,
                _ => 100,
            };
            by_tag.entry(tag.clone()).or_insert(FsReg { svc, tag, ord });
        }
    }
    let mut fresh: Vec<FsReg> = by_tag.into_values().collect();
    fresh.sort_by(|a, b| a.ord.cmp(&b.ord).then_with(|| a.tag.cmp(&b.tag)));

    let new_svcs: Vec<String> = {
        let mut v = Vec::new();
        for r in &fresh {
            if !old_svcs.contains(&r.svc) {
                v.push(r.svc.clone());
            }
        }
        v
    };

    unsafe {
        *FS_REGISTRY.write() = fresh;
    }

    for s in new_svcs {
        let _ = unsafe { pnp_load_service(s) };
    }

    let old_tags: BTreeSet<&str> = old_regs.iter().map(|r| r.tag.as_str()).collect();
    unsafe {
        FS_REGISTRY
            .read()
            .iter()
            .filter(|r| !old_tags.contains(r.tag.as_str()))
            .count()
    }
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
    inst_path: String,
}

#[repr(C)]
struct BootReqCtx {
    probe: *mut BootProbe,
    which: u8,
}

extern "win64" fn fs_open_boot_check_complete(r: &mut Request, ctx: usize) -> DriverStatus {
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
            let _ = attempt_boot_bind(&probe.inst_path, &probe.link);
        }
        unsafe {
            drop(Box::from_raw(reqctx.probe));
        }
    }
    return DriverStatus::Success;
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
    unsafe {
        let _ = pnp_send_request_via_symlink(public_link.to_string(), req.clone());
    }
}

fn start_boot_probe_async(public_link: &str, inst_path: &str) {
    let probe = Box::new(BootProbe {
        link: public_link.to_string(),
        need: AtomicU32::new(3),
        mod_ok: AtomicBool::new(false),
        inf_ok: AtomicBool::new(false),
        hive_ok: AtomicBool::new(false),
        inst_path: inst_path.to_string(),
    });
    let probe_ptr = Box::into_raw(probe);
    send_fs_open_async(public_link, "SYSTEM/MOD", 0, probe_ptr);
    send_fs_open_async(public_link, "SYSTEM/TOML", 1, probe_ptr);
    send_fs_open_async(public_link, "SYSTEM/REGISTRY.BIN", 2, probe_ptr);
}

fn attempt_boot_bind(_dev_inst_path: &str, fs_mount_link: &str) -> DriverStatus {
    println!("Attempt boot bind");
    if VFS_ACTIVE.load(Ordering::Acquire) {
        return DriverStatus::Success;
    }
    assign_drive_letter(b'C', fs_mount_link);
    match unsafe { switch_to_vfs() } {
        Ok(()) => {
            VFS_ACTIVE.store(true, Ordering::Release);
            println!("System volume mounted at '{}'", fs_mount_link);
            DriverStatus::Success
        }
        Err(e) => {
            println!("Error: {:#?}", e);
            panic!("VFS transition failed {:#?}", e);
        }
    }
}

fn assign_drive_letter(letter: u8, fs_mount_link: &str) {
    let ch = (letter as char).to_ascii_uppercase();
    if ch < 'A' || ch > 'Z' {
        return;
    }

    let _ = set_label_for_link(fs_mount_link, ch as u8);

    let link_nocolon = alloc::format!("\\GLOBAL\\StorageDevices\\{}", ch);
    let link_colon = alloc::format!("\\GLOBAL\\StorageDevices\\{}:", ch);

    let _ = unsafe { pnp_remove_symlink(link_nocolon.clone()) };
    let _ = unsafe { pnp_remove_symlink(link_colon.clone()) };

    let _ = unsafe { pnp_create_symlink(link_nocolon, fs_mount_link.to_string()) };
    let _ = unsafe { pnp_create_symlink(link_colon, fs_mount_link.to_string()) };
}

fn rescan_all_volumes() {
    let vols = unsafe { VOLUMES.read() };
    for dev in vols.clone() {
        mount_if_unmounted(&dev);
    }
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
    let _ = reg::delete_value(MP_ROOT, &dev_name_for(label));
    reg::set_value(
        MP_ROOT,
        &dev_name_for(label),
        kernel_api::Data::Str(public_link.to_string()),
    )
}

fn dev_name_for(label: u8) -> String {
    let c = (label as char).to_ascii_uppercase();
    alloc::format!("StorageDevices\\{}:", c)
}
