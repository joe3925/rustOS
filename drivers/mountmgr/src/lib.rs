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
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use spin::RwLock;

use kernel_api::{
    Data, DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceIds, DeviceInit,
        ffi::{
            InvalidateDeviceRelations, driver_set_evt_device_add, pnp_complete_request,
            pnp_create_child_devnode_and_pdo_with_init, pnp_create_device_symlink_top,
            pnp_forward_request_to_next_lower, pnp_ioctl_via_symlink, pnp_load_service,
            pnp_remove_symlink, reg,
        },
    },
    println,
};

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

mod msvc_shims;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

/* ---------------- IOCTLs ------------------ */
// FS → MountMgr: register control link (string)
const IOCTL_MOUNTMGR_REGISTER_FS: u32 = 0x4D4D_0001;
// MountMgr → FS: try mount the provided volume link (string)
const IOCTL_FS_TRY_MOUNT: u32 = 0x4653_0001;

// FS → MountMgr: unmount / relinquish claim for a volume (string: probe or public link)
const IOCTL_MOUNTMGR_UNMOUNT: u32 = 0x4D4D_0002;
// Any → MountMgr: query status (returns UTF8 summary)
const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;
// Any → MountMgr: rescan FS registry and reprobe
const IOCTL_MOUNTMGR_RESYNC: u32 = 0x4D4D_0004;
// Any → MountMgr: list registered FS control links (newline-separated)
const IOCTL_MOUNTMGR_LIST_FS: u32 = 0x4D4D_0005;

const VOLUME_LINK_BASE: &str = "\\Volumes"; // public, only when claimed
const PROBE_LINK_BASE: &str = "\\MountMgr\\Probe"; // internal, exists pre-claim

#[derive(Clone)]
struct FsReg {
    tag: String,
}
static mut FS_REGISTRY: RwLock<Vec<FsReg>> = RwLock::new(Vec::new());

fn refresh_fs_registry_from_registry() -> usize {
    // HKLM\SYSTEM\CurrentControlSet\MountMgr\Filesystems\<name>
    const ROOT: &str = "SYSTEM/CurrentControlSet/MountMgr/Filesystems";

    let mut add: Vec<(u32, String, String)> = Vec::new();

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
            add.push((order, svc, link));
        }
    }

    add.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));

    let mut added = 0usize;
    unsafe {
        let mut wr = FS_REGISTRY.write();
        for (_ord, _svc, link) in add {
            if !wr.iter().any(|r| r.tag == link) {
                wr.push(FsReg { tag: link });
                added += 1;
            }
        }
    }
    added
}

#[repr(C)]
struct FsPdoExt {
    backing_top: *const Arc<DeviceObject>,
}

#[repr(C)]
struct MountMgrExt {
    enumerated: AtomicBool, // raw PDO/probe link created
    claimed: AtomicBool,    // set once a FS claims the volume
    vol_id: AtomicU32,      // stable public id for this volume (non-zero when assigned)
    fs_pdo: *const Arc<DeviceObject>,

    inst_path_len: u32,
    inst_path_buf: [u8; 64],
    probe_link_len: u32,
    probe_link_buf: [u8; 96],
}

impl MountMgrExt {
    fn get_inst_path(&self) -> Option<String> {
        let n = self.inst_path_len as usize;
        if n == 0 || n > self.inst_path_buf.len() {
            return None;
        }
        Some(unsafe { core::str::from_utf8_unchecked(&self.inst_path_buf[..n]) }.to_string())
    }
    fn set_inst_path(&mut self, s: &str) {
        let b = s.as_bytes();
        let n = core::cmp::min(b.len(), self.inst_path_buf.len());
        self.inst_path_buf[..n].copy_from_slice(&b[..n]);
        self.inst_path_len = n as u32;
    }
    fn get_probe_link(&self) -> Option<String> {
        let n = self.probe_link_len as usize;
        if n == 0 || n > self.probe_link_buf.len() {
            return None;
        }
        Some(unsafe { core::str::from_utf8_unchecked(&self.probe_link_buf[..n]) }.to_string())
    }
    fn set_probe_link(&mut self, s: &str) {
        let b = s.as_bytes();
        let n = core::cmp::min(b.len(), self.probe_link_buf.len());
        self.probe_link_buf[..n].copy_from_slice(&b[..n]);
        self.probe_link_len = n as u32;
    }
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

#[inline]
fn make_volume_link_name(id: u32) -> String {
    alloc::format!("{}\\{:04}", VOLUME_LINK_BASE, id)
}
#[inline]
fn make_probe_link_name(id: u32) -> String {
    alloc::format!("{}\\{:04}", PROBE_LINK_BASE, id)
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, mountmgr_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn mountmgr_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = size_of::<MountMgrExt>();
    dev_init.evt_bus_enumerate_devices = Some(mountmgr_enumerate_devices);
    dev_init.io_device_control = Some(mountmgr_ioctl);

    let _ = refresh_fs_registry_from_registry();

    DriverStatus::Success
}

pub extern "win64" fn fs_pdo_read(child: &Arc<DeviceObject>, req: &mut Request, _len: usize) {
    let dx = ext_mut::<FsPdoExt>(child);
    if dx.backing_top.is_null() {
        req.status = DriverStatus::NoSuchDevice;
        return;
    }
    let top = unsafe { &*dx.backing_top };
    let _ = unsafe { pnp_forward_request_to_next_lower(top, req) };
}
pub extern "win64" fn fs_pdo_write(child: &Arc<DeviceObject>, req: &mut Request, _len: usize) {
    let dx = ext_mut::<FsPdoExt>(child);
    if dx.backing_top.is_null() {
        req.status = DriverStatus::NoSuchDevice;
        return;
    }
    let top = unsafe { &*dx.backing_top };
    let _ = unsafe { pnp_forward_request_to_next_lower(top, req) };
}

static NEXT_FS_CHILD_ID: AtomicU32 = AtomicU32::new(1);

#[repr(C)]
struct MountProbeCtx {
    parent_req: *mut Request,
    inst_path: String,
    public_link: String,
    probe_link: String,
    fs_tags: Vec<String>,
    idx: usize,
    mmx_ptr: *mut MountMgrExt,
}

extern "win64" fn mount_probe_complete(child: &mut Request, ctx_usize: usize) {
    let ctx: &mut MountProbeCtx = unsafe { &mut *(ctx_usize as *mut MountProbeCtx) };

    if child.status == DriverStatus::Success {
        let _ = unsafe {
            pnp_create_device_symlink_top(ctx.inst_path.clone(), ctx.public_link.clone())
        };

        if !ctx.mmx_ptr.is_null() {
            let mmx = unsafe { &mut *ctx.mmx_ptr };
            mmx.claimed.store(true, Ordering::Release);
        }

        let parent = unsafe { &mut *ctx.parent_req };
        parent.status = DriverStatus::Success;
        unsafe { pnp_complete_request(parent) };
        unsafe { drop(Box::from_raw(ctx_usize as *mut MountProbeCtx)) };
        return;
    }

    ctx.idx += 1;
    if ctx.idx < ctx.fs_tags.len() {
        let (tag_owned, payload) = {
            let t = ctx.fs_tags[ctx.idx].clone();
            let p = ctx.probe_link.clone().into_bytes().into_boxed_slice();
            (t, p)
        };

        let ctx_ptr = ctx as *mut _ as usize;
        let mut req = Request::new(RequestType::DeviceControl(IOCTL_FS_TRY_MOUNT), payload);
        req.set_completion(mount_probe_complete, ctx_ptr);
        let _ = unsafe { pnp_ioctl_via_symlink(tag_owned, IOCTL_FS_TRY_MOUNT, &mut req) };
        return;
    }

    let parent = unsafe { &mut *ctx.parent_req };
    parent.status = DriverStatus::Success;
    unsafe { pnp_complete_request(parent) };
    unsafe { drop(Box::from_raw(ctx_usize as *mut MountProbeCtx)) };
}

pub extern "win64" fn mountmgr_enumerate_devices(
    device: &Arc<DeviceObject>,
    request: &mut Request,
) -> DriverStatus {
    let mmx = ext_mut::<MountMgrExt>(device);

    if mmx.claimed.load(Ordering::Acquire) {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let _ = refresh_fs_registry_from_registry();

    let fs_tags: Vec<String> =
        unsafe { FS_REGISTRY.read().iter().map(|r| r.tag.clone()).collect() };
    if fs_tags.is_empty() {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let mut id = mmx.vol_id.load(Ordering::Acquire);
    if !mmx.enumerated.load(Ordering::Acquire) {
        if !mmx.enumerated.swap(true, Ordering::AcqRel) {
            let parent_dn = match device.dev_node.upgrade() {
                Some(dn) => dn,
                None => {
                    request.status = DriverStatus::Unsuccessful;
                    return DriverStatus::Unsuccessful;
                }
            };

            id = NEXT_FS_CHILD_ID.fetch_add(1, Ordering::AcqRel);
            mmx.vol_id.store(id, Ordering::Release);

            let name = alloc::format!("RawFsVol{}", id);
            let inst = alloc::format!("FS\\RAWVOLUME\\{:04}", id);

            let ids = DeviceIds {
                hardware: vec!["FS\\RawVolume".into()],
                compatible: vec!["FS\\Volume".into()],
            };

            let mut init = DeviceInit {
                dev_ext_size: core::mem::size_of::<FsPdoExt>(),
                io_read: Some(fs_pdo_read),
                io_write: Some(fs_pdo_write),
                io_device_control: None,
                evt_device_prepare_hardware: None,
                evt_bus_enumerate_devices: None,
                evt_pnp: None,
            };

            let (_dn_child, pdo) = unsafe {
                pnp_create_child_devnode_and_pdo_with_init(
                    &parent_dn,
                    name,
                    inst.clone(),
                    ids,
                    Some("FsVolume".into()),
                    init,
                )
            };

            let pext = ext_mut::<FsPdoExt>(&pdo);
            let boxed_top_arc = Box::new(device.clone());
            pext.backing_top = Box::into_raw(boxed_top_arc) as *const Arc<DeviceObject>;

            mmx.fs_pdo = Box::into_raw(Box::new(pdo)) as *const Arc<DeviceObject>;
            mmx.set_inst_path(&inst);

            let probe_link = make_probe_link_name(id);
            let _ = unsafe { pnp_create_device_symlink_top(inst, probe_link.clone()) };
            mmx.set_probe_link(&probe_link);
        }
    }

    id = mmx.vol_id.load(Ordering::Acquire);
    if id == 0 {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let inst_path = mmx.get_inst_path().unwrap_or_default();
    let probe_link = mmx.get_probe_link().unwrap_or_default();
    if probe_link.is_empty() || inst_path.is_empty() {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let public_link = make_volume_link_name(id);
    let mut ctx = Box::new(MountProbeCtx {
        parent_req: request as *mut _,
        inst_path,
        public_link,
        probe_link: probe_link.clone(),
        fs_tags,
        idx: 0,
        mmx_ptr: mmx as *mut _,
    });

    let tag0 = ctx.fs_tags[0].clone();
    let ctx_ptr = Box::into_raw(ctx) as usize;

    let mut probe = Request::new(
        RequestType::DeviceControl(IOCTL_FS_TRY_MOUNT),
        probe_link.into_bytes().into_boxed_slice(),
    );
    probe.set_completion(mount_probe_complete, ctx_ptr);

    request.status = DriverStatus::Waiting;
    let _ = unsafe { pnp_ioctl_via_symlink(tag0, IOCTL_FS_TRY_MOUNT, &mut probe) };

    DriverStatus::Waiting
}

fn build_status_blob(mmx: &MountMgrExt) -> Box<[u8]> {
    let id = mmx.vol_id.load(Ordering::Acquire);
    let claimed = if mmx.claimed.load(Ordering::Acquire) {
        1
    } else {
        0
    };
    let probe = mmx.get_probe_link().unwrap_or_default();
    let public = if id != 0 {
        make_volume_link_name(id)
    } else {
        String::new()
    };
    let s = alloc::format!(
        "id={};claimed={};probe={};public={}",
        id,
        claimed,
        probe,
        public
    );
    s.into_bytes().into_boxed_slice()
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

fn string_from_req(req: &Request) -> Option<String> {
    core::str::from_utf8(&req.data)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).to_string())
}

pub extern "win64" fn mountmgr_ioctl(dev: &Arc<DeviceObject>, req: &mut Request) {
    let RequestType::DeviceControl(code) = req.kind else {
        req.status = DriverStatus::InvalidParameter;
        return;
    };

    match code {
        IOCTL_MOUNTMGR_REGISTER_FS => {
            let tag = match string_from_req(req) {
                Some(t) if !t.is_empty() => t,
                _ => {
                    req.status = DriverStatus::InvalidParameter;
                    return;
                }
            };

            unsafe {
                let mut wr = FS_REGISTRY.write();
                if !wr.iter().any(|r| r.tag == tag) {
                    wr.push(FsReg { tag });
                }
            }
            let _ = refresh_fs_registry_from_registry();
            unsafe { InvalidateDeviceRelations(dev, kernel_api::DeviceRelationType::BusRelations) };
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_UNMOUNT => {
            let mmx = ext_mut::<MountMgrExt>(dev);
            let id = mmx.vol_id.load(Ordering::Acquire);
            if id == 0 {
                req.status = DriverStatus::Success;
                return;
            }

            let target = string_from_req(req).unwrap_or_default();
            let probe = mmx.get_probe_link().unwrap_or_default();
            let public = make_volume_link_name(id);

            if !target.is_empty() && target != probe && target != public {
                req.status = DriverStatus::InvalidParameter;
                return;
            }

            let _ = unsafe { pnp_remove_symlink(public.clone()) };
            mmx.claimed.store(false, Ordering::Release);

            unsafe { InvalidateDeviceRelations(dev, kernel_api::DeviceRelationType::BusRelations) };
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_QUERY => {
            let mmx = ext_mut::<MountMgrExt>(dev);
            req.data = build_status_blob(mmx);
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_RESYNC => {
            let _ = refresh_fs_registry_from_registry();
            unsafe { InvalidateDeviceRelations(dev, kernel_api::DeviceRelationType::BusRelations) };
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_LIST_FS => {
            req.data = list_fs_blob();
            req.status = DriverStatus::Success;
        }

        _ => {
            req.status = DriverStatus::NotImplemented;
        }
    }
}
