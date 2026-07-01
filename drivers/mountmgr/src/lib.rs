#![no_std]
#![no_main]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    marker::PhantomData,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};
use kernel_api::{
    device::{open_public_protocol, DevNode, DeviceInit, DeviceObject, DriverObject},
    fs::{notify_label_published, notify_label_unpublished, FsOpenParams},
    kernel_types::{
        fs::{OpenFlags, Path},
        io::{DeviceControlHandler, DeviceControlOp},
        pnp::DeviceEvent,
        protocol::volmgr::VolmgrProtocol,
        request::IoctlData,
    },
    pnp::{
        io, pnp_add_class_listener, pnp_create_control_device_and_link,
        pnp_create_device_symlink_top, pnp_create_symlink, pnp_remove_symlink, DriverStep,
    },
    reg::{self, switch_to_vfs_async},
    request::{DeviceControl, Fs, FsOpen, FsPayload},
    request_handler,
    runtime::spawn_detached,
    status::{Data, DriverStatus, RegError},
    util::panic_common,
    GLOBAL_CTRL_LINK, IOCTL_MOUNTMGR_LIST_FS, IOCTL_MOUNTMGR_QUERY, IOCTL_MOUNTMGR_RESYNC,
    IOCTL_MOUNTMGR_UNMOUNT,
};
use spin::RwLock;

const MOD_NAME: &str = env!("CARGO_PKG_NAME");
const DRIVE_LETTERS_KEY: &str = "SYSTEM/CurrentControlSet/MountMgr/DriveLetters";
const HINTS_KEY: &str = "SYSTEM/CurrentControlSet/MountMgr/FilesystemHints";

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panic_common(MOD_NAME, info)
}

#[derive(Clone)]
struct MountedVolume {
    instance_path: String,
    stable_id: String,
    stable_link: String,
    filesystem_service: String,
    assigned_label: Option<String>,
}

static MOUNTED: RwLock<BTreeMap<String, MountedVolume>> = RwLock::new(BTreeMap::new());
static PUBLISHED_LABELS: RwLock<BTreeMap<String, String>> = RwLock::new(BTreeMap::new());
static VFS_ACTIVE: AtomicBool = AtomicBool::new(false);

struct MountMgrControl;

impl DeviceControlHandler for MountMgrControl {
    #[request_handler]
    async fn handler(
        _device: &Arc<DeviceObject>,
        request: &mut DeviceControl<'_>,
    ) -> DriverStep {
        match request.code {
            IOCTL_MOUNTMGR_QUERY => {
                request.set_data(IoctlData::from_t::<Vec<u8>>(status_blob()));
                DriverStep::complete(DriverStatus::Success)
            }
            IOCTL_MOUNTMGR_LIST_FS => {
                request.set_data(IoctlData::from_t::<Vec<u8>>(filesystem_blob()));
                DriverStep::complete(DriverStatus::Success)
            }
            IOCTL_MOUNTMGR_RESYNC => {
                assign_all_labels().await;
                DriverStep::complete(DriverStatus::Success)
            }
            IOCTL_MOUNTMGR_UNMOUNT => DriverStep::complete(DriverStatus::NotImplemented),
            _ => DriverStep::complete(DriverStatus::NotImplemented),
        }
    }
}

extern "C" fn volume_event(
    node: Arc<DevNode>,
    event: DeviceEvent,
    _listener: &Arc<DeviceObject>,
) {
    spawn_detached(async move {
        match event {
            DeviceEvent::Started => handle_started(node).await,
            DeviceEvent::Stopped | DeviceEvent::Removed => handle_removed(&node.instance_path),
            DeviceEvent::Created | DeviceEvent::Failed => {}
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(_driver: &Arc<DriverObject>) -> DriverStatus {
    let mut init = DeviceInit::new();
    init.ops.register::<DeviceControlOp, MountMgrControl>();
    let control = pnp_create_control_device_and_link(
        "mountmgr".to_string(),
        init,
        GLOBAL_CTRL_LINK.to_string(),
    );
    pnp_add_class_listener("Volume".to_string(), volume_event, &control);
    DriverStatus::Success
}

async fn handle_started(node: Arc<DevNode>) {
    if MOUNTED.read().contains_key(&node.instance_path) {
        return;
    }
    let protocol = match open_public_protocol::<VolmgrProtocol>(&node) {
        Ok(protocol) => protocol,
        Err(_) => return,
    };
    let info = match (protocol.partition_info)(protocol.provider()) {
        Ok(info) => info,
        Err(_) => return,
    };
    let Some(entry) = info.gpt_entry else {
        return;
    };
    if entry.unique_partition_guid.iter().all(|byte| *byte == 0) {
        return;
    }

    let stable_id = guid_id(&entry.unique_partition_guid);
    let stable_link = alloc::format!("\\GLOBAL\\Volumes\\{stable_id}");
    let service = node
        .stack
        .read()
        .as_ref()
        .and_then(|stack| stack.function.as_ref())
        .map(|layer| layer.driver.driver_name.clone())
        .unwrap_or_default();
    if service.is_empty() {
        return;
    }

    let _ = pnp_create_device_symlink_top(node.instance_path.clone(), stable_link.clone());
    let mounted = MountedVolume {
        instance_path: node.instance_path.clone(),
        stable_id: stable_id.clone(),
        stable_link: stable_link.clone(),
        filesystem_service: service.clone(),
        assigned_label: None,
    };
    MOUNTED.write().insert(node.instance_path.clone(), mounted);
    write_filesystem_hint(&stable_id, &service).await;

    if VFS_ACTIVE.load(Ordering::Acquire) {
        let _ = assign_label(&node.instance_path, false).await;
    } else {
        start_boot_probe(node.instance_path.clone(), stable_id, stable_link);
    }
}

fn handle_removed(instance_path: &str) {
    let Some(volume) = MOUNTED.write().remove(instance_path) else {
        return;
    };
    if let Some(label) = volume.assigned_label {
        unpublish_label(&label);
    }
    let _ = pnp_remove_symlink(volume.stable_link);
}

fn guid_id(guid: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut id = String::from("GPT.");
    for byte in guid {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    id
}

async fn write_filesystem_hint(stable_id: &str, service: &str) {
    let _ = reg::create_key(HINTS_KEY).await;
    let key = alloc::format!("{HINTS_KEY}/{stable_id}");
    let _ = reg::create_key(&key).await;
    let _ = reg::set_value(&key, "Service", Data::Str(service.to_string())).await;
}

fn start_boot_probe(instance_path: String, stable_id: String, stable_link: String) {
    spawn_detached(async move {
        let has_boot_tree = fs_check_open(&stable_link, "system/mod").await
            && fs_check_open(&stable_link, "system/toml").await
            && fs_check_open(&stable_link, "system/registry").await;
        if !has_boot_tree || VFS_ACTIVE.load(Ordering::Acquire) {
            return;
        }
        if assign_specific_label('C', &instance_path, &stable_id, &stable_link)
            .await
            .is_err()
        {
            return;
        }
        match unsafe { switch_to_vfs_async().await } {
            Ok(()) => {
                VFS_ACTIVE.store(true, Ordering::Release);
                assign_all_labels().await;
            }
            Err(error) => panic!("VFS transition failed: {error:?}"),
        }
    });
}

async fn fs_check_open(volume_link: &str, path: &str) -> bool {
    let mut request = Fs::<FsOpen> {
        payload: FsPayload {
            params: FsOpenParams {
                flags: OpenFlags::Open.into(),
                write_through: false,
                path: Path::from_string(path),
            },
            result: None,
            _marker: PhantomData,
        },
    };
    let Some(target) = io::resolve_target(volume_link) else {
        return false;
    };
    io::send_down_stack(target, &mut request).await == DriverStatus::Success
        && request
            .payload
            .result
            .as_ref()
            .is_some_and(|result| result.error.is_none())
}

async fn assign_all_labels() {
    let instances: Vec<_> = MOUNTED.read().keys().cloned().collect();
    for instance in instances {
        let _ = assign_label(&instance, false).await;
    }
}

async fn assign_label(instance_path: &str, allow_c: bool) -> Option<String> {
    let volume = MOUNTED.read().get(instance_path).cloned()?;
    if volume.assigned_label.is_some() {
        return volume.assigned_label;
    }
    let preferred = read_preferred_label(&volume.stable_id).await;
    let label = match preferred {
        Some(label) if !is_label_published(&label) => label,
        _ => {
            let label = find_free_label(allow_c)?;
            let _ = write_preferred_label(&volume.stable_id, &label).await;
            label
        }
    };
    publish_label(&label, &volume.stable_id, &volume.stable_link);
    if let Some(current) = MOUNTED.write().get_mut(instance_path) {
        current.assigned_label = Some(label.clone());
    }
    Some(label)
}

async fn assign_specific_label(
    letter: char,
    instance_path: &str,
    stable_id: &str,
    stable_link: &str,
) -> Result<(), RegError> {
    let label = alloc::format!("{}:", letter.to_ascii_uppercase());
    write_preferred_label(stable_id, &label).await?;
    publish_label(&label, stable_id, stable_link);
    if let Some(volume) = MOUNTED.write().get_mut(instance_path) {
        volume.assigned_label = Some(label);
    }
    Ok(())
}

async fn read_preferred_label(stable_id: &str) -> Option<String> {
    reg::get_value(DRIVE_LETTERS_KEY, stable_id)
        .await
        .and_then(|value| match value {
            Data::Str(label) if !label.is_empty() => Some(label),
            _ => None,
        })
}

async fn write_preferred_label(stable_id: &str, label: &str) -> Result<(), RegError> {
    let _ = reg::create_key(DRIVE_LETTERS_KEY).await;
    reg::set_value(
        DRIVE_LETTERS_KEY,
        stable_id,
        Data::Str(label.to_string()),
    )
    .await
}

fn find_free_label(allow_c: bool) -> Option<String> {
    let labels = PUBLISHED_LABELS.read();
    for letter in if allow_c { b'C' } else { b'D' }..=b'Z' {
        let label = alloc::format!("{}:", letter as char);
        if !labels.contains_key(&label) {
            return Some(label);
        }
    }
    None
}

fn is_label_published(label: &str) -> bool {
    PUBLISHED_LABELS.read().contains_key(label)
}

fn publish_label(label: &str, stable_id: &str, stable_link: &str) {
    let letter = label.chars().next().unwrap_or('?');
    let plain = alloc::format!("\\GLOBAL\\StorageDevices\\{letter}");
    let colon = alloc::format!("\\GLOBAL\\StorageDevices\\{letter}:");
    let _ = pnp_remove_symlink(plain.clone());
    let _ = pnp_remove_symlink(colon.clone());
    let _ = pnp_create_symlink(plain, stable_link.to_string());
    let _ = pnp_create_symlink(colon, stable_link.to_string());
    PUBLISHED_LABELS
        .write()
        .insert(label.to_string(), stable_id.to_string());
    notify_label_published(label, stable_link);
}

fn unpublish_label(label: &str) {
    let letter = label.chars().next().unwrap_or('?');
    let _ = pnp_remove_symlink(alloc::format!("\\GLOBAL\\StorageDevices\\{letter}"));
    let _ = pnp_remove_symlink(alloc::format!("\\GLOBAL\\StorageDevices\\{letter}:"));
    PUBLISHED_LABELS.write().remove(label);
    notify_label_unpublished(label);
}

fn status_blob() -> Vec<u8> {
    let mounted = MOUNTED.read();
    let mut output = String::new();
    for volume in mounted.values() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&alloc::format!(
            "{};{};{};{}",
            volume.instance_path,
            volume.stable_id,
            volume.filesystem_service,
            volume.assigned_label.as_deref().unwrap_or("")
        ));
    }
    output.into_bytes()
}

fn filesystem_blob() -> Vec<u8> {
    let services: BTreeSet<_> = MOUNTED
        .read()
        .values()
        .map(|volume| volume.filesystem_service.clone())
        .collect();
    services.into_iter().collect::<Vec<_>>().join("\n").into_bytes()
}
