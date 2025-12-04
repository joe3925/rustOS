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
    ptr::addr_of,
    slice,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use spin::{Once, RwLock};

use kernel_api::{
    GLOBAL_CTRL_LINK, GLOBAL_VOLUMES_BASE, RequestExt, RequestResultExt,
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    fs::{FsOp, FsOpenParams, FsOpenResult},
    kernel_types::{
        fs::OpenFlags,
        io::{FsIdentify, IoTarget, IoType, IoVtable, Synchronization},
        pnp::DeviceIds,
    },
    pnp::{
        PnpMinorFunction, PnpVtable, driver_set_evt_device_add, pnp_create_control_device_and_link,
        pnp_create_device_symlink_top, pnp_create_devnode_over_pdo_with_function,
        pnp_create_symlink, pnp_ioctl_via_symlink, pnp_load_service, pnp_remove_symlink,
        pnp_send_request_via_symlink,
    },
    println,
    reg::{self, switch_to_vfs_async},
    request::{Request, RequestType, TraversalPolicy},
    request_handler, spawn,
    status::{Data, DriverStatus, RegError},
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

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        use kernel_api::util::panic_common;
        panic_common(MOD_NAME, info)
    }
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

    DriverStatus::Success
}

pub extern "win64" fn volclass_device_add(
    _driver: Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, volclass_start);

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

    DriverStatus::Success
}

#[request_handler]
pub async fn volclass_start(
    dev: Arc<DeviceObject>,
    _request: Arc<RwLock<Request>>,
) -> DriverStatus {
    let _ = refresh_fs_registry_from_registry().await;
    init_volume_dx(&dev);
    spawn(mount_if_unmounted(dev));
    DriverStatus::Continue
}

#[request_handler]
pub async fn vol_fdo_read(
    _dev: Arc<DeviceObject>,
    _req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStatus {
    DriverStatus::Continue
}

#[request_handler]
pub async fn vol_fdo_write(
    _dev: Arc<DeviceObject>,
    _req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStatus {
    DriverStatus::Continue
}

#[request_handler]
pub async fn volclass_ioctl(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStatus {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => {
                drop(r);
                return DriverStatus::NotImplemented;
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
                let dx = ext::<VolFdoExt>(&dev);
                if let Some(pl) = dx.public_link.get() {
                    let _ = unsafe { pnp_remove_symlink(pl.clone()) };
                }
                dx.fs_attached.store(false, Ordering::Release);
            }
            DriverStatus::Success
        }
        IOCTL_MOUNTMGR_QUERY => {
            let mut w = req.write();
            w.data = build_status_blob(&dev);
            DriverStatus::Success
        }
        IOCTL_MOUNTMGR_RESYNC => {
            let _ = refresh_fs_registry_from_registry().await;
            mount_if_unmounted(dev).await;
            DriverStatus::Success
        }
        IOCTL_MOUNTMGR_LIST_FS => {
            let mut w = req.write();
            w.data = list_fs_blob();
            DriverStatus::Success
        }
        _ => DriverStatus::NotImplemented,
    }
}

#[request_handler]
pub async fn volclass_ctrl_ioctl(
    _dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => {
                drop(r);
                return DriverStatus::NotImplemented;
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
                Some(t) if !t.is_empty() => {
                    unsafe {
                        let mut wr = FS_REGISTERED.write();
                        if !wr.iter().any(|s| s == &t) {
                            wr.push(t);
                        }
                        drop(wr);
                        let _ = refresh_fs_registry_from_registry().await;
                        spawn(rescan_all_volumes());
                    }
                    DriverStatus::Success
                }
                _ => DriverStatus::InvalidParameter,
            }
        }
        _ => DriverStatus::NotImplemented,
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

async fn mount_if_unmounted(dev: Arc<DeviceObject>) {
    {
        let dx = ext::<VolFdoExt>(&dev);
        if dx
            .fs_attached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
    }

    let dx = ext::<VolFdoExt>(&dev);
    let public = dx.public_link.get().cloned().unwrap_or_default();
    if public.is_empty() {
        dx.fs_attached.store(false, Ordering::Release);
        return;
    }

    if try_bind_filesystems_for_parent_fdo(&dev, &public).await {
        let link = dx.fs_link.get().cloned().unwrap_or_else(|| public.clone());
        let inst = dx.inst_path.get().cloned().unwrap_or_default();
        start_boot_probe_async(&link, &inst);
    } else {
        dx.fs_attached.store(false, Ordering::Release);
    }
}

async fn try_bind_filesystems_for_parent_fdo(
    parent_fdo: &Arc<DeviceObject>,
    public_link: &str,
) -> bool {
    let _ = refresh_fs_registry_from_registry().await;
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

        let req = Arc::new(RwLock::new(
            Request::new(
                RequestType::DeviceControl(kernel_api::IOCTL_FS_IDENTIFY),
                data,
            )
            .set_traversal_policy(TraversalPolicy::ForwardLower),
        ));
        unsafe {
            let err =
                pnp_ioctl_via_symlink(tag.clone(), kernel_api::IOCTL_FS_IDENTIFY, req.clone())
                    .resolve()
                    .await;
            if err != DriverStatus::Success {
                return false;
            }
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

        let created = pnp_create_devnode_over_pdo_with_function(
            &parent_dn,
            fs_inst.clone(),
            ids.clone(),
            class.clone(),
            &svc,
            &function_fdo.clone(),
            DeviceInit::new(IoVtable::new(), None),
        )
        .await;

        if let Ok((dn, _top)) = created {
            let primary_link = public_link.to_string();
            let compat_link = alloc::format!("\\GLOBAL\\Mounts\\{:04}", vid);

            let _ = pnp_create_device_symlink_top(dn.instance_path.clone(), primary_link.clone());
            let _ = pnp_create_device_symlink_top(dn.instance_path.clone(), compat_link.clone());

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

async fn refresh_fs_registry_from_registry() -> usize {
    use alloc::collections::{BTreeMap, BTreeSet};

    const ROOT: &str = "SYSTEM/CurrentControlSet/MountMgr/Filesystems";

    let mut by_tag: BTreeMap<String, FsReg> = BTreeMap::new();
    if let Ok(keys) = reg::list_keys(ROOT).await {
        for sub in keys {
            let svc = match reg::get_value(&sub, "Service").await {
                Some(Data::Str(s)) if !s.is_empty() => s,
                _ => continue,
            };
            let tag = match reg::get_value(&sub, "ControlLink").await {
                Some(Data::Str(s)) if !s.is_empty() => s,
                _ => continue,
            };
            let ord = match reg::get_value(&sub, "Order").await {
                Some(Data::U32(v)) => v,
                _ => 100,
            };
            by_tag.entry(tag.clone()).or_insert(FsReg { svc, tag, ord });
        }
    }

    let mut fresh: Vec<FsReg> = by_tag.into_values().collect();
    fresh.sort_by(|a, b| a.ord.cmp(&b.ord).then_with(|| a.tag.cmp(&b.tag)));

    let mut guard = FS_REGISTRY.write();

    let old_svcs: BTreeSet<String> = guard.iter().map(|r| r.svc.clone()).collect();
    let mut new_svcs = Vec::new();

    for r in &fresh {
        if !old_svcs.contains(&r.svc) {
            new_svcs.push(r.svc.clone());
        }
    }

    *guard = fresh;

    drop(guard);

    for s in new_svcs {
        let _ = pnp_load_service(s).await;
    }

    let guard = FS_REGISTRY.read();
    guard.len()
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

// Async boot device checks: just await each FsOpen instead of using completion routines.

async fn fs_check_open(public_link: &str, path: &str) -> bool {
    let params = FsOpenParams {
        flags: OpenFlags::Open,
        path: path.to_string(),
    };
    let req = Arc::new(RwLock::new(
        Request::new(RequestType::Fs(FsOp::Open), box_to_bytes(Box::new(params)))
            .set_traversal_policy(TraversalPolicy::ForwardLower),
    ));

    let err = unsafe {
        pnp_send_request_via_symlink(public_link.to_string(), req.clone())
            .resolve()
            .await
    };
    if err != DriverStatus::Success {
        println!("Boot check {}: send error {:#?}", path, err);
        return false;
    }

    let mut r = req.write();
    if r.status != DriverStatus::Success || r.data.len() != size_of::<FsOpenResult>() {
        println!(
            "Boot check {}: status {:#?}, len {}",
            path,
            r.status,
            r.data.len()
        );
        return false;
    }

    let res: FsOpenResult = unsafe { *bytes_to_box(core::mem::replace(&mut r.data, Box::new([]))) };

    if res.error.is_none() {
        println!("Boot check {}: OK", path);
        true
    } else {
        println!("Boot check {}: FsOpenResult error {:#?}", path, res.error);
        false
    }
}

fn start_boot_probe_async(public_link: &str, inst_path: &str) {
    let link = public_link.to_string();
    let inst = inst_path.to_string();

    spawn(async move {
        let mod_ok = fs_check_open(&link, "SYSTEM/MOD").await;
        let inf_ok = fs_check_open(&link, "SYSTEM/TOML").await;
        let reg_ok = fs_check_open(&link, "SYSTEM/REGISTRY.BIN").await;

        if mod_ok && inf_ok && reg_ok {
            let _ = attempt_boot_bind(&inst, &link).await;
        } else {
            println!(
                "Boot probe '{}' failed: mod_ok={}, inf_ok={}, reg_ok={}",
                link, mod_ok, inf_ok, reg_ok
            );
        }
    });
}

async fn attempt_boot_bind(_dev_inst_path: &str, fs_mount_link: &str) -> DriverStatus {
    if VFS_ACTIVE.load(Ordering::Acquire) {
        return DriverStatus::Success;
    }
    assign_drive_letter(b'C', fs_mount_link).await;
    match unsafe { switch_to_vfs_async().await } {
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

async fn assign_drive_letter(letter: u8, fs_mount_link: &str) -> Result<(), RegError> {
    let ch = (letter as char).to_ascii_uppercase();
    if ch < 'A' || ch > 'Z' {
        return Ok(());
    }

    set_label_for_link(fs_mount_link, ch as u8).await?;

    let link_nocolon = alloc::format!("\\GLOBAL\\StorageDevices\\{}", ch);
    let link_colon = alloc::format!("\\GLOBAL\\StorageDevices\\{}:", ch);

    pnp_remove_symlink(link_nocolon.clone());
    pnp_remove_symlink(link_colon.clone());

    pnp_create_symlink(link_nocolon, fs_mount_link.to_string());
    pnp_create_symlink(link_colon, fs_mount_link.to_string());
    Ok(())
}

async fn rescan_all_volumes() {
    let vols = VOLUMES.read();
    for dev in vols.clone() {
        mount_if_unmounted(dev.clone()).await;
    }
}

async fn set_label_for_link(public_link: &str, label: u8) -> Result<(), RegError> {
    reg::create_key(MP_ROOT).await;
    if let Ok(vals) = reg::list_values(MP_ROOT).await {
        for name in vals {
            if let Some(Data::Str(s)) = reg::get_value(MP_ROOT, &name).await {
                if s == public_link {
                    let _ = reg::delete_value(MP_ROOT, &name).await;
                }
            }
        }
    }
    let _ = reg::delete_value(MP_ROOT, &dev_name_for(label)).await;
    reg::set_value(
        MP_ROOT,
        &dev_name_for(label),
        Data::Str(public_link.to_string()),
    )
    .await
}

fn dev_name_for(label: u8) -> String {
    let c = (label as char).to_ascii_uppercase();
    alloc::format!("StorageDevices\\{}:", c)
}
