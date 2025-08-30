#![no_std]
#![no_main]
#![allow(static_mut_refs)]

extern crate alloc;

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
    Data, DevNode, DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceInit,
        ffi::{
            pnp_add_class_listener, pnp_create_device_symlink_top, pnp_ioctl_via_symlink,
            pnp_load_service, pnp_remove_symlink, reg,
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

// FS → MountMgr: register control link (string)
const IOCTL_MOUNTMGR_REGISTER_FS: u32 = 0x4D4D_0001;
// MountMgr → FS: try mount the provided volume link (string)
const IOCTL_FS_TRY_MOUNT: u32 = 0x4653_0001;

// FS → MountMgr: unmount / relinquish claim for a volume (string: probe or public link)
const IOCTL_MOUNTMGR_UNMOUNT: u32 = 0x4D4D_0002;
// Any → MountMgr: query status (returns UTF8 summary)
const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;
// Any → MountMgr: rescan FS registry
const IOCTL_MOUNTMGR_RESYNC: u32 = 0x4D4D_0004;
// Any → MountMgr: list registered FS control links (newline-separated)
const IOCTL_MOUNTMGR_LIST_FS: u32 = 0x4D4D_0005;

const VOLUME_LINK_BASE: &str = "\\Volumes"; // public, only when claimed
const PROBE_LINK_BASE: &str = "\\MountMgr\\Probe"; // internal, per-volume probe link

#[inline]
fn make_volume_link_name(id: u32) -> String {
    alloc::format!("{}\\{:04}", VOLUME_LINK_BASE, id)
}
#[inline]
fn make_probe_link_name(id: u32) -> String {
    alloc::format!("{}\\{:04}", PROBE_LINK_BASE, id)
}

#[derive(Clone)]
struct FsReg {
    // service name to Start (ensures control device exists)
    svc: String,
    // control device link (e.g. "\\FileSystems\\ntfs")
    tag: String,
    // order (smaller first)
    ord: u32,
}
static mut FS_REGISTRY: RwLock<Vec<FsReg>> = RwLock::new(Vec::new());

fn refresh_fs_registry_from_registry() -> usize {
    // HKLM\SYSTEM\CurrentControlSet\MountMgr\Filesystems\<name>
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
            // Start service so its control device is guaranteed to exist
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
struct MountMgrExt {
    last_vol_id: AtomicU32,
    last_claimed: AtomicBool,
}
impl MountMgrExt {
    fn new() -> Self {
        Self {
            last_vol_id: AtomicU32::new(0),
            last_claimed: AtomicBool::new(false),
        }
    }
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

static NEXT_VOL_ID: AtomicU32 = AtomicU32::new(1);

struct VolumeCtx {
    inst_path: String,   // DevNode instance path (e.g. "FS\\RAWVOLUME\\0001")
    probe_link: String,  // symlink to \\Device\\<inst>\\Top
    public_link: String, // final public link \\Volumes\\NNNN
    claimed: AtomicBool,
}
impl VolumeCtx {
    fn new(inst_path: String, vid: u32) -> Self {
        let probe = make_probe_link_name(vid);
        let public = make_volume_link_name(vid);
        Self {
            inst_path,
            probe_link: probe,
            public_link: public,
            claimed: AtomicBool::new(false),
        }
    }
}

extern "win64" fn fs_probe_complete(req: &mut Request, ctx: usize) {
    let vctx: &mut VolumeCtx = unsafe { &mut *(ctx as *mut VolumeCtx) };

    if req.status == DriverStatus::Success {
        if !vctx.claimed.swap(true, Ordering::AcqRel) {
            let _ = unsafe {
                pnp_create_device_symlink_top(vctx.inst_path.clone(), vctx.public_link.clone())
            };
            let _ = unsafe { pnp_remove_symlink(vctx.probe_link.clone()) };
            println!(
                "[mountmgr] volume '{}' claimed -> {}",
                vctx.inst_path, vctx.public_link
            );
        }
    }
}

extern "win64" fn on_new_volume(dn: &Arc<DevNode>, listener_dev: &Arc<DeviceObject>) {
    let inst = dn.instance_path.clone();
    let vid = NEXT_VOL_ID.fetch_add(1, Ordering::AcqRel);
    let mut ctx = Box::new(VolumeCtx::new(inst.clone(), vid));

    let _ = unsafe { pnp_create_device_symlink_top(inst.clone(), ctx.probe_link.clone()) };
    let regs: Vec<FsReg> = unsafe { FS_REGISTRY.read().clone() };
    if regs.is_empty() {
        let _ = refresh_fs_registry_from_registry();
    }

    let mmx = ext_mut::<MountMgrExt>(listener_dev);
    mmx.last_vol_id.store(vid, Ordering::Release);
    mmx.last_claimed.store(false, Ordering::Release);

    let payload = ctx.probe_link.clone().into_bytes().into_boxed_slice();
    let raw_ctx = Box::into_raw(ctx) as usize;

    for fs in unsafe { FS_REGISTRY.read().iter().cloned().collect::<Vec<_>>() } {
        let _ = unsafe { pnp_load_service(fs.svc.clone()) };

        let mut req = Request::new(
            RequestType::DeviceControl(IOCTL_FS_TRY_MOUNT),
            payload.clone(),
        );
        req.set_completion(fs_probe_complete, raw_ctx);
        let _ = unsafe { pnp_ioctl_via_symlink(fs.tag.clone(), IOCTL_FS_TRY_MOUNT, &mut req) };
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { kernel_api::alloc_api::ffi::driver_set_evt_device_add(driver, mountmgr_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn mountmgr_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = size_of::<MountMgrExt>();
    dev_init.evt_device_prepare_hardware = Some(mountmgr_prepare);
    dev_init.io_device_control = Some(mountmgr_ioctl);
    let _ = refresh_fs_registry_from_registry();
    DriverStatus::Success
}

extern "win64" fn mountmgr_prepare(dev: &Arc<DeviceObject>) -> DriverStatus {
    {
        let dx = ext_mut::<MountMgrExt>(dev);
        *dx = MountMgrExt::new();
    }
    unsafe { pnp_add_class_listener("FsVolume".to_string(), on_new_volume, dev.clone()) };

    DriverStatus::Success
}

fn build_status_blob(mmx: &MountMgrExt) -> Box<[u8]> {
    let id = mmx.last_vol_id.load(Ordering::Acquire);
    let claimed = if mmx.last_claimed.load(Ordering::Acquire) {
        1
    } else {
        0
    };
    let public = if id != 0 {
        make_volume_link_name(id)
    } else {
        String::new()
    };
    let probe = if id != 0 {
        make_probe_link_name(id)
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
                    // If only a tag arrives, assume svc name is the leaf of the tag path
                    let svc_guess = tag
                        .rsplit(&['\\', '/'][..])
                        .next()
                        .unwrap_or("fs")
                        .to_string();
                    wr.push(FsReg {
                        svc: svc_guess,
                        tag,
                        ord: 100,
                    });
                }
            }
            let _ = refresh_fs_registry_from_registry();
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_UNMOUNT => {
            // If a FS asks to unmount a link, remove both public/probe variants if they exist.
            let target = string_from_req(req).unwrap_or_default();
            if !target.is_empty() {
                let _ = unsafe { pnp_remove_symlink(target) };
            }
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_QUERY => {
            let mmx = ext_mut::<MountMgrExt>(dev);
            req.data = build_status_blob(mmx);
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_RESYNC => {
            let _ = refresh_fs_registry_from_registry();
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
