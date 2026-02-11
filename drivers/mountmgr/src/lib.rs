#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    panic::PanicInfo,
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use spin::{Once, RwLock};

use kernel_api::{
    GLOBAL_CTRL_LINK, GLOBAL_VOLUMES_BASE,
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    fs::{FsOp, FsOpenParams, FsOpenResult, notify_label_published, notify_label_unpublished},
    kernel_types::{
        fs::{OpenFlags, Path},
        io::{FsIdentify, IoTarget, IoType, IoVtable, Synchronization},
        pnp::DeviceIds,
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
        driver_set_evt_device_add, pnp_create_control_device_and_link,
        pnp_create_device_symlink_top, pnp_create_devnode_over_pdo_with_function,
        pnp_create_symlink, pnp_ioctl_via_symlink, pnp_load_service, pnp_remove_symlink,
        pnp_send_request_via_symlink,
    },
    println,
    reg::{self, switch_to_vfs_async},
    request::{Request, RequestHandle, RequestType, TraversalPolicy},
    request_handler,
    runtime::{spawn, spawn_detached},
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
const DL_ROOT: &str = "SYSTEM/CurrentControlSet/MountMgr/DriveLetters";

#[repr(C)]
#[derive(Default)]
struct VolFdoExt {
    inst_path: Once<String>,
    public_link: Once<String>,
    fs_link: Once<String>,
    fs_attached: AtomicBool,
    vid: Once<u32>,
    /// Stable identifier derived from GPT partition GUID (e.g., "GPT.XXXX...")
    /// None if the volume lacks a valid GPT GUID.
    stable_id: Once<Option<String>>,
    /// Assigned drive label (e.g., "C:") - only set after successful assignment
    assigned_label: RwLock<Option<String>>,
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
    driver_set_evt_device_add(driver, volclass_device_add);

    let mut io_vtable = IoVtable::new();
    io_vtable.set(
        IoType::DeviceControl(volclass_ctrl_ioctl),
        Synchronization::Sync,
        0,
    );

    let init = DeviceInit::new(io_vtable, None);
    let _ctrl = pnp_create_control_device_and_link(
        "\\Device\\volclass.ctrl".to_string(),
        init,
        GLOBAL_CTRL_LINK.to_string(),
    );

    DriverStatus::Success
}

pub extern "win64" fn volclass_device_add(
    _driver: Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, volclass_start);

    dev_init.io_vtable.set(
        IoType::DeviceControl(volclass_ioctl),
        Synchronization::Sync,
        0,
    );

    dev_init.set_dev_ext_default::<VolFdoExt>();
    dev_init.pnp_vtable = Some(pnp_vtable);

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn volclass_start<'a, 'b>(
    dev: Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let _ = refresh_fs_registry_from_registry().await;
    init_volume_dx(&dev);
    spawn_detached(mount_if_unmounted(dev));
    DriverStep::Continue
}

#[request_handler]
pub async fn volclass_ioctl<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let code = match { req.read().kind } {
        RequestType::DeviceControl(c) => c,
        _ => return DriverStep::complete(DriverStatus::NotImplemented),
    };

    match code {
        IOCTL_MOUNTMGR_UNMOUNT => {
            let target = {
                let r = req.read();
                string_from_req(&r).unwrap_or_default()
            };

            if !target.is_empty() {
                let _ = pnp_remove_symlink(target);
            } else {
                let dx = ext::<VolFdoExt>(&dev);
                if let Some(pl) = dx.public_link.get() {
                    let _ = pnp_remove_symlink(pl.clone());
                }
                dx.fs_attached.store(false, Ordering::Release);
            }
            let mut w = req.write();
            w.status = DriverStatus::Success;
            DriverStep::complete(DriverStatus::Success)
        }
        IOCTL_MOUNTMGR_QUERY => {
            let mut w = req.write();
            w.set_data_bytes(build_status_blob(&dev));
            drop(w);
            DriverStep::complete(DriverStatus::Success)
        }
        IOCTL_MOUNTMGR_RESYNC => {
            let _ = refresh_fs_registry_from_registry().await;
            mount_if_unmounted(dev).await;
            // Enumerate all volumes and assign labels on-demand
            enumerate_and_assign_all_labels().await;
            let mut w = req.write();
            w.status = DriverStatus::Success;
            DriverStep::complete(DriverStatus::Success)
        }
        IOCTL_MOUNTMGR_LIST_FS => {
            let mut w = req.write();
            w.set_data_bytes(list_fs_blob());
            drop(w);
            DriverStep::complete(DriverStatus::Success)
        }
        _ => DriverStep::complete(DriverStatus::NotImplemented),
    }
}

#[request_handler]
pub async fn volclass_ctrl_ioctl<'a, 'b>(
    _dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let code = match { req.read().kind } {
        RequestType::DeviceControl(c) => c,
        _ => return DriverStep::complete(DriverStatus::NotImplemented),
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
                        spawn_detached(rescan_all_volumes());
                    }
                    DriverStep::complete(DriverStatus::Success)
                }
                _ => DriverStep::complete(DriverStatus::InvalidParameter),
            }
        }
        _ => DriverStep::complete(DriverStatus::NotImplemented),
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
        // Get stable_id - must exist after successful bind
        let stable_id = dx.stable_id.get().cloned().flatten().unwrap_or_default();
        start_boot_probe_async(&link, &inst, &stable_id);

        // If the system is already running on VFS, assign a drive label immediately.
        if VFS_ACTIVE.load(Ordering::Acquire) && dx.assigned_label.read().is_none() {
            let published_label = if !stable_id.is_empty() {
                PUBLISHED_LABELS
                    .read()
                    .iter()
                    .find_map(|(lbl, sid)| (sid == &stable_id).then(|| lbl.clone()))
            } else {
                None
            };

            if let Some(lbl) = published_label {
                *dx.assigned_label.write() = Some(lbl);
            } else {
                let _ = assign_label_on_demand(&dev).await;
            }
        }
    } else {
        dx.fs_attached.store(false, Ordering::Release);
    }
}

/// Compute stable identifier from GPT partition GUID.
/// Returns None if the volume lacks a valid GPT GUID.
async fn compute_stable_id(parent_fdo: &Arc<DeviceObject>) -> Option<String> {
    let vol_target = parent_fdo.clone();
    let mut request = Request::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::with_capacity(0),
            data_out: RequestData::empty(),
        },
        RequestData::empty(),
    )
    .set_traversal_policy(TraversalPolicy::ForwardLower);
    let status = {
        let mut req_handle = RequestHandle::Stack(&mut request);
        kernel_api::pnp::pnp_send_request(vol_target, &mut req_handle).await
    };
    if status != DriverStatus::Success {
        return None;
    }

    // PartitionInfo is returned in the PnP payload data_out for QueryResources
    let pi = {
        let pnp = request.pnp.as_ref()?;
        if let Some(pi) = pnp
            .data_out
            .view::<kernel_api::kernel_types::io::PartitionInfo>()
        {
            pi.clone()
        } else {
            return None;
        }
    };
    let ge = pi.gpt_entry?;
    let guid = ge.unique_partition_guid;

    // Check for all-zero GUID
    if guid.iter().all(|&b| b == 0) {
        return None;
    }

    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut id = String::new();
    id.push_str("GPT.");
    for &b in &guid {
        id.push(HEX[(b >> 4) as usize] as char);
        id.push(HEX[(b & 0xF) as usize] as char);
    }

    Some(id)
}

async fn try_bind_filesystems_for_parent_fdo(
    parent_fdo: &Arc<DeviceObject>,
    public_link: &str,
) -> bool {
    let _ = refresh_fs_registry_from_registry().await;

    let dx_vol = ext::<VolFdoExt>(parent_fdo);
    let vid = dx_vol.vid.get().copied().unwrap_or(0);

    let parent_dn = match parent_fdo.dev_node.get().unwrap().upgrade() {
        Some(x) => x,
        None => return false,
    };

    // Compute and store stable_id if not already set
    let stable_id = match dx_vol.stable_id.get() {
        Some(id) => id.clone(),
        None => {
            let id = compute_stable_id(parent_fdo).await;
            dx_vol.stable_id.call_once(|| id.clone());
            id
        }
    };

    // Require valid stable_id for mounting
    let stable_id = match stable_id {
        Some(id) => id,
        None => {
            println!("Volume {} has no stable_id, skipping mount", public_link);
            return false;
        }
    };

    let stable_link = alloc::format!("\\GLOBAL\\Volumes\\{}", stable_id);

    let inst_suffix = alloc::format!("FSINST.{:04X}", vid);
    let parent_inst = parent_dn.instance_path.clone();
    let fs_inst = alloc::format!("{}\\{}", parent_inst, inst_suffix);

    let ids = DeviceIds {
        hardware: alloc::vec![alloc::format!("VIRT\\FSINST#{}", inst_suffix)],
        compatible: Vec::new(),
    };
    let class = Some("FileSystem".to_string());

    let tags = FS_REGISTERED.read().clone();

    for tag in tags {
        let mut identify_req = Request::new(
            RequestType::DeviceControl(kernel_api::IOCTL_FS_IDENTIFY),
            RequestData::from_t(FsIdentify {
                volume_fdo: parent_fdo.clone(),
                mount_device: None,
                can_mount: false,
            }),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower);

        let err = {
            let mut handle = RequestHandle::Stack(&mut identify_req);
            pnp_ioctl_via_symlink(tag.clone(), kernel_api::IOCTL_FS_IDENTIFY, &mut handle).await
        };
        if err != DriverStatus::Success {
            continue;
        }

        if identify_req.status != DriverStatus::Success {
            continue;
        }

        let Some(id) = identify_req.take_data::<FsIdentify>() else {
            continue;
        };
        if !id.can_mount {
            continue;
        }
        let Some(function_fdo) = id.mount_device else {
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
            let _ = pnp_create_device_symlink_top(dn.instance_path.clone(), stable_link.clone());

            let dx = ext::<VolFdoExt>(parent_fdo);
            dx.fs_link.call_once(|| stable_link);
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
    core::str::from_utf8(req.data_slice())
        .ok()
        .map(|s| s.trim_matches(core::char::from_u32(0).unwrap()).to_string())
}

fn list_fs_blob() -> Box<[u8]> {
    let s = {
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

async fn fs_check_open(public_link: &str, path: &str) -> bool {
    let params = FsOpenParams {
        flags: OpenFlags::Open.into(),
        write_through: false,
        path: Path::from_string(path),
    };
    let mut req_inner = Request::new(RequestType::Fs(FsOp::Open), RequestData::from_t(params))
        .set_traversal_policy(TraversalPolicy::ForwardLower);

    let err = {
        let mut handle = RequestHandle::Stack(&mut req_inner);
        pnp_send_request_via_symlink(public_link.to_string(), &mut handle).await
    };

    if err != DriverStatus::Success {
        return false;
    }

    if req_inner.status != DriverStatus::Success {
        return false;
    }

    if let Some(_) = req_inner
        .take_data::<FsOpenResult>()
        .map(|res| res.error.is_none())
    {
        return true;
    }
    return false;
}

fn start_boot_probe_async(public_link: &str, inst_path: &str, stable_id: &str) {
    let link = public_link.to_string();
    let inst = inst_path.to_string();
    let sid = stable_id.to_string();

    spawn_detached(async move {
        if !VFS_ACTIVE.load(Ordering::Acquire) {
            let mod_ok = fs_check_open(&link, "system/mod").await;
            let inf_ok = fs_check_open(&link, "system/toml").await;
            let reg_dir_ok = fs_check_open(&link, "system/registry").await;

            if mod_ok && inf_ok && reg_dir_ok {
                let _ = attempt_boot_bind(&inst, &link, &sid).await;
            }
        }
    });
}

async fn attempt_boot_bind(
    _dev_inst_path: &str,
    fs_mount_link: &str,
    stable_id: &str,
) -> Result<(), RegError> {
    if VFS_ACTIVE.load(Ordering::Acquire) {
        return Ok(());
    }

    // Boot path: assign C: only, write registry only on first-boot/change
    if stable_id.is_empty() {
        println!("System volume has no stable_id, cannot assign C:");
        return Err(RegError::KeyNotFound);
    }

    assign_boot_drive_letter(b'C', stable_id, fs_mount_link).await?;

    match unsafe { switch_to_vfs_async().await } {
        Ok(()) => {
            VFS_ACTIVE.store(true, Ordering::Release);
            println!("System volume mounted at '{}')", fs_mount_link);
            // Now that the VFS provider is active, trigger a resync so all volumes
            // get mounted and labeled without waiting for an external RESYNC request.
            rescan_all_volumes().await;
            Ok(())
        }
        Err(e) => {
            println!("Error: {:#?}", e);
            panic!("VFS transition failed {:#?}", e);
        }
    }
}

/// Tracking structure for currently published labels at runtime.
/// Maps label (e.g., "C:") to stable_id of the volume holding it.
static PUBLISHED_LABELS: RwLock<BTreeMap<String, String>> = RwLock::new(BTreeMap::new());

/// Read preferred label for a stable_id from registry.
/// Returns None if no preference exists.
async fn read_preferred_label(stable_id: &str) -> Option<String> {
    reg::get_value(DL_ROOT, stable_id)
        .await
        .and_then(|d| match d {
            Data::Str(s) if !s.is_empty() => Some(s),
            _ => None,
        })
}

/// Write preferred label for a stable_id to registry.
async fn write_preferred_label(stable_id: &str, label: &str) -> Result<(), RegError> {
    let _ = reg::create_key(DL_ROOT).await;
    reg::set_value(DL_ROOT, stable_id, Data::Str(label.to_string())).await
}

/// Publish a drive letter symlink pointing to the volume's stable mount symlink.
/// Updates the PUBLISHED_LABELS map.
fn publish_label(label: &str, stable_id: &str, fs_mount_link: &str) {
    let ch = label.chars().next().unwrap_or('?');
    let link_nocolon = alloc::format!("\\GLOBAL\\StorageDevices\\{}", ch);
    let link_colon = alloc::format!("\\GLOBAL\\StorageDevices\\{}:", ch);

    pnp_remove_symlink(link_nocolon.clone());
    pnp_remove_symlink(link_colon.clone());

    pnp_create_symlink(link_nocolon, fs_mount_link.to_string());
    pnp_create_symlink(link_colon, fs_mount_link.to_string());

    PUBLISHED_LABELS
        .write()
        .insert(label.to_string(), stable_id.to_string());

    notify_label_published(label, fs_mount_link);
}

/// Unpublish a drive letter symlink.
fn unpublish_label(label: &str) {
    let ch = label.chars().next().unwrap_or('?');
    let link_nocolon = alloc::format!("\\GLOBAL\\StorageDevices\\{}", ch);
    let link_colon = alloc::format!("\\GLOBAL\\StorageDevices\\{}:", ch);

    pnp_remove_symlink(link_nocolon);
    pnp_remove_symlink(link_colon);

    PUBLISHED_LABELS.write().remove(label);

    notify_label_unpublished(label);
}

/// Check if a label is currently published.
fn is_label_published(label: &str) -> bool {
    PUBLISHED_LABELS.read().contains_key(label)
}

/// Find the first free label starting from D: (or C: if allow_c is true).
fn find_free_label(allow_c: bool) -> Option<String> {
    let published = PUBLISHED_LABELS.read();
    let start = if allow_c { b'C' } else { b'D' };
    for ch in start..=b'Z' {
        let label = alloc::format!("{}:", ch as char);
        if !published.contains_key(&label) {
            return Some(label);
        }
    }
    None
}

/// Assign a specific drive letter to a volume (boot path for C:).
/// Only writes to registry if this is first assignment or the mapping changed.
async fn assign_boot_drive_letter(
    letter: u8,
    stable_id: &str,
    fs_mount_link: &str,
) -> Result<(), RegError> {
    let ch = (letter as char).to_ascii_uppercase();
    if ch < 'A' || ch > 'Z' {
        return Ok(());
    }

    let label = alloc::format!("{}:", ch);

    // Check if we need to write to registry
    let current_pref = read_preferred_label(stable_id).await;
    if current_pref.as_ref() != Some(&label) {
        // First boot or mapping changed - write registry
        write_preferred_label(stable_id, &label).await?;
    }

    // Publish the runtime symlink
    publish_label(&label, stable_id, fs_mount_link);

    Ok(())
}

/// On-demand label assignment for a volume.
/// Uses Policy A: existing mapping wins (newcomers get new labels).
async fn assign_label_on_demand(dev: &Arc<DeviceObject>) -> Option<String> {
    let dx = ext::<VolFdoExt>(dev);

    // Get stable_id - required for assignment
    let stable_id = match dx.stable_id.get() {
        Some(Some(id)) => id.clone(),
        _ => return None,
    };

    // Get fs_link for the volume
    let fs_link = match dx.fs_link.get() {
        Some(link) => link.clone(),
        None => match dx.public_link.get() {
            Some(link) => link.clone(),
            None => return None,
        },
    };

    // Check if already assigned
    if let Some(existing) = dx.assigned_label.read().clone() {
        return Some(existing);
    }

    // Check registry for preferred label (single read)
    let preferred = read_preferred_label(&stable_id).await;

    let label = if let Some(pref) = preferred {
        // Has preference - check if free
        if is_label_published(&pref) {
            // Conflict - Policy A: existing wins, we get a new label
            match find_free_label(false) {
                Some(new_label) => {
                    // Don't persist conflict resolution to avoid future fights
                    new_label
                }
                None => return None, // No free labels
            }
        } else {
            pref
        }
    } else {
        // No preference - find a free label and persist it
        match find_free_label(false) {
            Some(new_label) => {
                // Persist new assignment
                let _ = write_preferred_label(&stable_id, &new_label).await;
                new_label
            }
            None => return None,
        }
    };

    // Publish the symlink
    publish_label(&label, &stable_id, &fs_link);

    // Store assignment in device extension
    *dx.assigned_label.write() = Some(label.clone());

    Some(label)
}

async fn rescan_all_volumes() {
    let vols = VOLUMES.read().clone();
    for dev in vols {
        mount_if_unmounted(dev.clone()).await;
    }
}

/// Enumerate all volumes and assign labels on-demand.
/// Called during RESYNC or when VFS needs to refresh labels.
async fn enumerate_and_assign_all_labels() {
    let vols = VOLUMES.read().clone();
    for dev in vols {
        let dx = ext::<VolFdoExt>(&dev);
        // Only process mounted volumes
        if dx.fs_attached.load(Ordering::Acquire) {
            let _ = assign_label_on_demand(&dev).await;
        }
    }
}

fn dev_name_for(label: u8) -> String {
    let c = (label as char).to_ascii_uppercase();
    alloc::format!("StorageDevices\\{}:", c)
}
