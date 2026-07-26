#![no_std]
#![no_main]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
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
    GLOBAL_CTRL_LINK, IOCTL_MOUNTMGR_LIST_FS, IOCTL_MOUNTMGR_QUERY, IOCTL_MOUNTMGR_RESYNC,
    IOCTL_MOUNTMGR_UNMOUNT,
    device::{DevNode, DeviceInit, DeviceObject, DriverObject, open_public_protocol},
    error::{
        DriverErrorKind, ErrorKind, FileErrorKind, KernelError, RegistryErrorKind,
        ResultErrorContext,
    },
    fs::{FsOpenParams, notify_label_published, notify_label_unpublished},
    kernel_types::{
        fs::{OpenFlags, Path},
        io::{DeviceControlHandler, DeviceControlOp},
        pnp::DeviceEvent,
        protocol::volmgr::VolumeProtocol,
        request::IoctlData,
    },
    pnp::{
        DriverStep, io, pnp_add_class_listener, pnp_create_control_device_and_link,
        pnp_create_device_symlink_top, pnp_create_symlink, pnp_remove_symlink,
        pnp_set_preferred_function_driver,
    },
    reg::{self, switch_to_vfs_async},
    request::{DeviceControl, Fs, FsOpen, FsPayload},
    request_handler,
    runtime::spawn_detached,
    status::Data,
    util::panic_common,
};
use spin::RwLock;

const MOD_NAME: &str = env!("CARGO_PKG_NAME");
const DRIVE_LETTERS_KEY: &str = "SYSTEM/CurrentControlSet/MountMgr/DriveLetters";

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
    filesystem_driver_name: String,
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
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        match request.code {
            IOCTL_MOUNTMGR_QUERY => {
                request.set_data(IoctlData::from_t::<Vec<u8>>(status_blob()));
                Ok(DriverStep::Complete)
            }
            IOCTL_MOUNTMGR_LIST_FS => {
                request.set_data(IoctlData::from_t::<Vec<u8>>(filesystem_blob()));
                Ok(DriverStep::Complete)
            }
            IOCTL_MOUNTMGR_RESYNC => {
                assign_all_labels().await;
                Ok(DriverStep::Complete)
            }
            IOCTL_MOUNTMGR_UNMOUNT => Err(kernel_api::error::error(
                kernel_api::error::DriverErrorKind::NotImplemented,
            )),
            _ => Err(kernel_api::error::error(
                kernel_api::error::DriverErrorKind::NotImplemented,
            )),
        }
    }
}

extern "C" fn volume_event(node: Arc<DevNode>, event: DeviceEvent, _listener: &Arc<DeviceObject>) {
    spawn_detached(async move {
        let result: Result<(), KernelError> = match event {
            DeviceEvent::Started => handle_started(node).await,
            DeviceEvent::Stopped | DeviceEvent::Removed => handle_removed(&node.instance_path),
            DeviceEvent::Created | DeviceEvent::Failed => Ok(()),
        };
        if let Err(error) = result {
            kernel_api::println!("mountmgr volume event failed: {error}");
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(
    _driver: &Arc<DriverObject>,
) -> Result<(), kernel_api::error::KernelError> {
    let mut init = DeviceInit::new();
    init.ops.register::<DeviceControlOp, MountMgrControl>();
    let control = pnp_create_control_device_and_link(
        "mountmgr".to_string(),
        init,
        GLOBAL_CTRL_LINK.to_string(),
    );
    pnp_add_class_listener("Volume".to_string(), volume_event, &control);
    Ok(())
}

async fn handle_started(node: Arc<DevNode>) -> Result<(), KernelError> {
    if MOUNTED.read().contains_key(&node.instance_path) {
        return Ok(());
    }
    let protocol = open_public_protocol::<VolumeProtocol>(&node).map_err(|kind| {
        kernel_api::error::error_with_message(
            kind,
            format_args!("opening volume protocol for `{}`", node.instance_path),
        )
    })?;
    let info = (protocol.partition_info)(protocol.provider()).with_context(|| {
        format!(
            "querying partition information for `{}`",
            node.instance_path
        )
    })?;
    let Some(entry) = info.gpt_entry else {
        return Ok(());
    };
    if entry.unique_partition_guid.iter().all(|byte| *byte == 0) {
        return Ok(());
    }

    let stable_id = guid_id(&entry.unique_partition_guid);
    let stable_link = alloc::format!("\\GLOBAL\\Volumes\\{stable_id}");
    let driver_name = node
        .stack
        .read()
        .as_ref()
        .and_then(|stack| stack.function.as_ref())
        .map(|layer| layer.driver.driver_name.clone())
        .unwrap_or_default();
    if driver_name.is_empty() {
        return Err(kernel_api::error::error_with_message(
            DriverErrorKind::DeviceError,
            format_args!("volume `{}` has no function driver", node.instance_path),
        ));
    }

    pnp_create_device_symlink_top(node.instance_path.clone(), stable_link.clone()).map_err(
        |error| {
            kernel_api::error::error_with_message(
                DriverErrorKind::DeviceError,
                format_args!("publishing stable volume link `{stable_link}` failed: {error:?}"),
            )
        },
    )?;
    let mounted = MountedVolume {
        instance_path: node.instance_path.clone(),
        stable_id: stable_id.clone(),
        stable_link: stable_link.clone(),
        filesystem_driver_name: driver_name.clone(),
        assigned_label: None,
    };
    MOUNTED.write().insert(node.instance_path.clone(), mounted);
    pnp_set_preferred_function_driver(&node.instance_path, &driver_name)
        .await
        .with_context(|| {
            format!(
                "recording preferred function driver for `{}`",
                node.instance_path
            )
        })?;

    if VFS_ACTIVE.load(Ordering::Acquire) {
        assign_label(&node.instance_path, false).await?;
    } else {
        start_boot_probe(node.instance_path.clone(), stable_id, stable_link);
    }
    Ok(())
}

fn handle_removed(instance_path: &str) -> Result<(), KernelError> {
    let Some(volume) = MOUNTED.write().remove(instance_path) else {
        return Ok(());
    };
    if let Some(label) = volume.assigned_label {
        unpublish_label(&label)?;
    }
    remove_symlink_if_present(volume.stable_link)?;
    Ok(())
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

fn start_boot_probe(instance_path: String, stable_id: String, stable_link: String) {
    spawn_detached(async move {
        let has_boot_tree = match async {
            Ok::<bool, KernelError>(
                fs_check_open(&stable_link, "system/mod").await?
                    && fs_check_open(&stable_link, "system/toml").await?
                    && fs_check_open(&stable_link, "system/registry").await?,
            )
        }
        .await
        {
            Ok(found) => found,
            Err(error) => {
                kernel_api::println!("mountmgr boot-volume probe failed: {error}");
                return;
            }
        };
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
            Err(error) => panic!("VFS transition failed:\n\n{error}"),
        }
    });
}

async fn fs_check_open(volume_link: &str, path: &str) -> Result<bool, KernelError> {
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
        return Err(kernel_api::error::error_with_message(
            DriverErrorKind::NoSuchDevice,
            format_args!("volume target `{volume_link}` could not be resolved"),
        ));
    };
    io::send_down_stack(target, &mut request)
        .await
        .with_context(|| format!("probing `{path}` on `{volume_link}`"))?;
    let result = request.payload.result.ok_or_else(|| {
        kernel_api::error::error_with_message(
            DriverErrorKind::DeviceError,
            format_args!("filesystem probe for `{path}` completed without a result"),
        )
    })?;
    match result.error {
        None => Ok(true),
        Some(error) if matches!(error.kind(), ErrorKind::File(FileErrorKind::PathNotFound)) => {
            Ok(false)
        }
        Some(error) => Err(error.with_context(format!("probing `{path}` on `{volume_link}`"))),
    }
}

async fn assign_all_labels() {
    let instances: Vec<_> = MOUNTED.read().keys().cloned().collect();
    for instance in instances {
        if let Err(error) = assign_label(&instance, false).await {
            kernel_api::println!("mountmgr failed to assign label to `{instance}`: {error}");
        }
    }
}

async fn assign_label(instance_path: &str, allow_c: bool) -> Result<Option<String>, KernelError> {
    let Some(volume) = MOUNTED.read().get(instance_path).cloned() else {
        return Ok(None);
    };
    if volume.assigned_label.is_some() {
        return Ok(volume.assigned_label);
    }
    let preferred = read_preferred_label(&volume.stable_id).await;
    let label = match preferred {
        Some(label) if !is_label_published(&label) => label,
        _ => {
            let Some(label) = find_free_label(allow_c) else {
                return Ok(None);
            };
            write_preferred_label(&volume.stable_id, &label).await?;
            label
        }
    };
    publish_label(&label, &volume.stable_id, &volume.stable_link)?;
    if let Some(current) = MOUNTED.write().get_mut(instance_path) {
        current.assigned_label = Some(label.clone());
    }
    Ok(Some(label))
}

async fn assign_specific_label(
    letter: char,
    instance_path: &str,
    stable_id: &str,
    stable_link: &str,
) -> Result<(), KernelError> {
    let label = alloc::format!("{}:", letter.to_ascii_uppercase());
    write_preferred_label(stable_id, &label).await?;
    publish_label(&label, stable_id, stable_link)?;
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

async fn write_preferred_label(stable_id: &str, label: &str) -> Result<(), KernelError> {
    create_registry_key_if_missing(DRIVE_LETTERS_KEY).await?;
    reg::set_value(DRIVE_LETTERS_KEY, stable_id, Data::Str(label.to_string())).await
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

async fn create_registry_key_if_missing(path: &str) -> Result<(), KernelError> {
    match reg::create_key(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::Registry(RegistryErrorKind::KeyAlreadyExists) => {
            Ok(())
        }
        Err(error) => Err(error.with_context(format!("creating registry key `{path}`"))),
    }
}

fn remove_symlink_if_present(path: String) -> Result<(), KernelError> {
    match pnp_remove_symlink(path.clone()) {
        Ok(()) | Err(DriverErrorKind::NoSuchDevice) => Ok(()),
        Err(kind) => Err(kernel_api::error::error_with_message(
            kind,
            format_args!("removing symlink `{path}`"),
        )),
    }
}

fn publish_label(label: &str, stable_id: &str, stable_link: &str) -> Result<(), KernelError> {
    let letter = label.chars().next().unwrap_or('?');
    let plain = alloc::format!("\\GLOBAL\\StorageDevices\\{letter}");
    let colon = alloc::format!("\\GLOBAL\\StorageDevices\\{letter}:");
    remove_symlink_if_present(plain.clone())?;
    remove_symlink_if_present(colon.clone())?;
    pnp_create_symlink(plain.clone(), stable_link.to_string()).map_err(|error| {
        kernel_api::error::error_with_message(
            DriverErrorKind::DeviceError,
            format_args!("publishing symlink `{plain}` failed: {error:?}"),
        )
    })?;
    pnp_create_symlink(colon.clone(), stable_link.to_string()).map_err(|error| {
        kernel_api::error::error_with_message(
            DriverErrorKind::DeviceError,
            format_args!("publishing symlink `{colon}` failed: {error:?}"),
        )
    })?;
    PUBLISHED_LABELS
        .write()
        .insert(label.to_string(), stable_id.to_string());
    notify_label_published(label, stable_link);
    Ok(())
}

fn unpublish_label(label: &str) -> Result<(), KernelError> {
    let letter = label.chars().next().unwrap_or('?');
    remove_symlink_if_present(alloc::format!("\\GLOBAL\\StorageDevices\\{letter}"))?;
    remove_symlink_if_present(alloc::format!("\\GLOBAL\\StorageDevices\\{letter}:"))?;
    PUBLISHED_LABELS.write().remove(label);
    notify_label_unpublished(label);
    Ok(())
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
            volume.filesystem_driver_name,
            volume.assigned_label.as_deref().unwrap_or("")
        ));
    }
    output.into_bytes()
}

fn filesystem_blob() -> Vec<u8> {
    let services: BTreeSet<_> = MOUNTED
        .read()
        .values()
        .map(|volume| volume.filesystem_driver_name.clone())
        .collect();
    services
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}
