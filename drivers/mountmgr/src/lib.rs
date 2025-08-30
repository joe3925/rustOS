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
    Data, DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceInit,
        ffi::{
            driver_set_evt_device_add, pnp_create_device_symlink_top,
            pnp_forward_request_to_next_lower, pnp_ioctl_via_symlink, pnp_load_service,
            pnp_remove_symlink, reg,
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

// FS → VolClass: register control link
const IOCTL_MOUNTMGR_REGISTER_FS: u32 = 0x4D4D_0001;
// VolClass → FS: probe mount for provided link
const IOCTL_FS_TRY_MOUNT: u32 = 0x4653_0001;
// FS → VolClass: unmount/relinquish link
const IOCTL_MOUNTMGR_UNMOUNT: u32 = 0x4D4D_0002;
// Any → VolClass: query last status
const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;
// Any → VolClass: rescan FS registry
const IOCTL_MOUNTMGR_RESYNC: u32 = 0x4D4D_0004;
// Any → VolClass: list registered FS control links
const IOCTL_MOUNTMGR_LIST_FS: u32 = 0x4D4D_0005;

// FSCTL routing: any code in 0x9000_0000..=0x9FFF_FFFF is sent upward to the FS device.
const IOCTL_FSCTL_BASE: u32 = 0x9000_0000;
const IOCTL_FSCTL_MASK: u32 = 0xF000_0000;

const VOLUME_LINK_BASE: &str = "\\Volumes";
const PROBE_LINK_BASE: &str = "\\MountMgr\\Probe";

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
    svc: String,
    tag: String,
    ord: u32,
}
static mut FS_REGISTRY: RwLock<Vec<FsReg>> = RwLock::new(Vec::new());

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
    probe_link: String,
    public_link: String,
    fs_attached: AtomicBool,
}
impl VolFdoExt {
    fn blank() -> Self {
        Self {
            inst_path: String::new(),
            probe_link: String::new(),
            public_link: String::new(),
            fs_attached: AtomicBool::new(false),
        }
    }
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

static NEXT_VOL_ID: AtomicU32 = AtomicU32::new(1);

struct VolumeCtx {
    fdo: Arc<DeviceObject>,
    inst_path: String,
    probe_link: String,
    public_link: String,
}
impl VolumeCtx {
    fn new(fdo: Arc<DeviceObject>, inst_path: String, vid: u32) -> Self {
        Self {
            fdo,
            inst_path,
            probe_link: make_probe_link_name(vid),
            public_link: make_volume_link_name(vid),
        }
    }
}

extern "win64" fn fs_probe_complete(req: &mut Request, ctx: usize) {
    let mut bx = unsafe { Box::from_raw(ctx as *mut VolumeCtx) };
    if req.status == DriverStatus::Success {
        let _ =
            unsafe { pnp_create_device_symlink_top(bx.inst_path.clone(), bx.public_link.clone()) };
        let _ = unsafe { pnp_remove_symlink(bx.probe_link.clone()) };
        let dx = ext_mut::<VolFdoExt>(&bx.fdo);
        dx.public_link = bx.public_link.clone();
        dx.fs_attached.store(true, Ordering::Release);
        println!("[volclass] claimed -> {}", dx.public_link);
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, volclass_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn volclass_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = size_of::<VolFdoExt>();
    dev_init.evt_device_prepare_hardware = Some(volclass_start);
    dev_init.io_device_control = Some(volclass_ioctl);
    let _ = refresh_fs_registry_from_registry();
    DriverStatus::Success
}

extern "win64" fn volclass_start(dev: &Arc<DeviceObject>) -> DriverStatus {
    let vid = NEXT_VOL_ID.fetch_add(1, Ordering::AcqRel);
    let inst = dev.dev_node.upgrade().unwrap().instance_path.clone();

    {
        let dx = ext_mut::<VolFdoExt>(dev);
        *dx = VolFdoExt::blank();
        dx.inst_path = inst.clone();
        dx.probe_link = make_probe_link_name(vid);
        dx.public_link = make_volume_link_name(vid);
    }

    let _ = unsafe {
        pnp_create_device_symlink_top(inst.clone(), ext_mut::<VolFdoExt>(dev).probe_link.clone())
    };

    let regs: Vec<FsReg> = unsafe { FS_REGISTRY.read().clone() };
    if regs.is_empty() {
        let _ = refresh_fs_registry_from_registry();
    }

    let payload = ext_mut::<VolFdoExt>(dev)
        .probe_link
        .clone()
        .into_bytes()
        .into_boxed_slice();
    let raw_ctx = Box::into_raw(Box::new(VolumeCtx::new(dev.clone(), inst, vid))) as usize;

    for fs in unsafe { FS_REGISTRY.read().iter().cloned().collect::<Vec<_>>() } {
        let _ = unsafe { pnp_load_service(fs.svc.clone()) };
        let mut req = Request::new(
            RequestType::DeviceControl(IOCTL_FS_TRY_MOUNT),
            payload.clone(),
        );
        req.set_completion(fs_probe_complete, raw_ctx);
        let _ = unsafe { pnp_ioctl_via_symlink(fs.tag.clone(), IOCTL_FS_TRY_MOUNT, &mut req) };
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
    let s = alloc::format!(
        "claimed={};probe={};public={}",
        claimed,
        dx.probe_link,
        dx.public_link
    );
    s.into_bytes().into_boxed_slice()
}

fn string_from_req(req: &Request) -> Option<String> {
    core::str::from_utf8(&req.data)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).to_string())
}

#[inline]
fn is_fsctl(code: u32) -> bool {
    (code & IOCTL_FSCTL_MASK) == IOCTL_FSCTL_BASE
}

pub extern "win64" fn volclass_ioctl(dev: &Arc<DeviceObject>, req: &mut Request) {
    let RequestType::DeviceControl(code) = req.kind else {
        // pass non-IOCTL down
        unsafe { pnp_forward_request_to_next_lower(dev, req) };
        return;
    };

    // Up-route FSCTLs
    if is_fsctl(code) {
        let dx = ext_mut::<VolFdoExt>(dev);
        if !dx.fs_attached.load(Ordering::Acquire) {
            req.status = DriverStatus::DeviceNotReady;
            return;
        }
        let mut shadow = Request::new(RequestType::DeviceControl(code), req.data.clone());
        let r = unsafe { pnp_ioctl_via_symlink(dx.public_link.clone(), code, &mut shadow) };
        if r == DriverStatus::Success {
            req.data = shadow.data;
            req.status = DriverStatus::Success;
        } else {
            req.status = DriverStatus::Unsuccessful;
        }
        return;
    }

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
            let target = string_from_req(req).unwrap_or_default();
            if !target.is_empty() {
                let _ = unsafe { pnp_remove_symlink(target) };
            }
            ext_mut::<VolFdoExt>(dev)
                .fs_attached
                .store(false, Ordering::Release);
            req.status = DriverStatus::Success;
        }

        IOCTL_MOUNTMGR_QUERY => {
            req.data = build_status_blob(dev);
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
            // pass unknown IOCTLs down the storage stack
            unsafe { pnp_forward_request_to_next_lower(dev, req) };
        }
    }
}
