use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::ToString,
    sync::Arc,
    vec::Vec,
};
use core::mem::{align_of, size_of};
use core::sync::atomic::AtomicU64;
use fatfs::FsOptions;
use spin::RwLock;

use kernel_api::{
    GLOBAL_CTRL_LINK, IOCTL_MOUNTMGR_REGISTER_FS,
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        async_types::AsyncMutex,
        io::{FsIdentify, IoType, IoVtable, PartitionInfo, Synchronization},
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, QueryIdType,
        driver_set_evt_device_add, pnp_create_control_device_and_link,
        pnp_create_control_device_with_init, pnp_ioctl_via_symlink, pnp_send_request,
    },
    println,
    request::{RequestHandle, RequestType, TraversalPolicy},
    request_handler,
    runtime::{spawn_blocking, spawn_detached},
    status::DriverStatus,
};

use crate::block_dev::BlockDev;
use crate::volume::{VolCtrlDevExt, fs_op_dispatch};
use log::{Level, Metadata, Record};

struct KernelLogger;

impl log::Log for KernelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("FAT32 [{}]: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: KernelLogger = KernelLogger;

fn init_logger() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Debug);
}

#[inline]
pub fn ext_mut<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("Failed to get fat32 dev ext")
}

fn from_boxed_bytes<T>(bytes: Box<[u8]>) -> Result<T, DriverStatus> {
    if bytes.len() != size_of::<T>() {
        return Err(DriverStatus::InvalidParameter);
    }
    let ptr = bytes.as_ptr();
    if !(ptr as usize).is_multiple_of(align_of::<T>()) {
        drop(bytes);
        return Err(DriverStatus::InvalidParameter);
    }
    // SAFETY: same rationale as take_req.
    let val = unsafe { (ptr as *const T).read() };
    drop(bytes);
    Ok(val)
}

#[request_handler]
pub async fn fs_root_ioctl<'a, 'b>(
    _dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let code = match req.read().kind {
        RequestType::DeviceControl(c) => c,
        _ => return DriverStep::complete(DriverStatus::NotImplemented),
    };

    match code {
        _IOCTL_FS_IDENTIFY => {
            let mut r = req.write();
            let id_opt = r.take_data::<FsIdentify>();
            drop(r);
            let mut id = match id_opt {
                Some(v) => v,
                None => return DriverStep::complete(DriverStatus::InvalidParameter),
            };

            let mut query = RequestHandle::new_pnp(
                PnpRequest {
                    minor_function: PnpMinorFunction::QueryResources,
                    relation: DeviceRelationType::TargetDeviceRelation,
                    id_type: QueryIdType::DeviceId,
                    ids_out: Vec::new(),
                    data_out: RequestData::empty(),
                },
                RequestData::empty(),
            );
            let st = pnp_send_request(id.volume_fdo.clone(), &mut query).await;

            let mut sector_size: Option<u16> = None;
            let mut total_sectors: Option<u64> = None;

            if st == DriverStatus::Success
                && let Some(pnp) = query.write().pnp.as_mut() {
                    let mut pi_opt = pnp.data_out.try_take::<PartitionInfo>();
                    if pi_opt.is_none() {
                        let raw = pnp.data_out.take_bytes();
                        pi_opt = from_boxed_bytes::<PartitionInfo>(raw).ok();
                    }

                    if let Some(pi) = pi_opt {
                        sector_size = Some(if pi.disk.logical_block_size != 0 {
                            pi.disk.logical_block_size as u16
                        } else {
                            512
                        });

                        total_sectors = pi.gpt_entry.map(|ent| {
                            ent.last_lba.saturating_sub(ent.first_lba).saturating_add(1)
                        });
                    }
                }
            let (sector_size, total_sectors) = match (sector_size, total_sectors) {
                (Some(sz), Some(ts)) => (sz, ts),
                _ => {
                    id.mount_device = None;
                    id.can_mount = false;
                    let mut w = req.write();
                    w.set_data_t(id);
                    w.status = DriverStatus::Success;
                    return DriverStep::complete(DriverStatus::Success);
                }
            };

            let options = FsOptions::new();
            let target_clone = id.volume_fdo.clone();
            let result = spawn_blocking(move || {
                fatfs::FileSystem::new(
                    BlockDev::new(target_clone, sector_size, total_sectors),
                    options,
                )
            })
            .await;
            match result {
                Ok(fs) => {
                    let mut io_vtable = IoVtable::new();
                    io_vtable.set(IoType::Fs(fs_op_dispatch), Synchronization::Sync, 0);

                    let ext = VolCtrlDevExt {
                        fs: Arc::new(AsyncMutex::new(fs)),
                        next_id: AtomicU64::new(1),
                        table: RwLock::new(BTreeMap::new()),
                    };

                    let mut init = DeviceInit::new(io_vtable, None);
                    init.set_dev_ext_from(ext);

                    let vol_name = alloc::format!("\\Device\\fat32.vol.{:p}", &id.volume_fdo);
                    let vol_ctrl = pnp_create_control_device_with_init(vol_name.clone(), init);

                    id.mount_device = Some(vol_ctrl);
                    id.can_mount = true;
                    let mut w = req.write();
                    w.set_data_t(id);
                    w.status = DriverStatus::Success;
                    DriverStep::complete(DriverStatus::Success)
                }
                Err(_e) => {
                    id.mount_device = None;
                    id.can_mount = false;
                    let mut w = req.write();
                    w.set_data_t(id);
                    w.status = DriverStatus::Success;
                    DriverStep::complete(DriverStatus::Success)
                }
            }
        }
        _ => DriverStep::complete(DriverStatus::NotImplemented),
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, fs_device_add);
    init_logger();
    let mut io_vtable = IoVtable::new();
    io_vtable.set(
        IoType::DeviceControl(fs_root_ioctl),
        Synchronization::Sync,
        0,
    );
    let init = DeviceInit::new(io_vtable, None);
    let ctrl_link = "\\GLOBAL\\FileSystems\\fat32".to_string();
    let ctrl_name = "\\Device\\fat32.fs".to_string();
    let _ctrl = pnp_create_control_device_and_link(ctrl_name.clone(), init, ctrl_link.clone());

    spawn_detached(async move {
        let mut binding = RequestHandle::new(
            RequestType::DeviceControl(IOCTL_MOUNTMGR_REGISTER_FS),
            RequestData::from_boxed_bytes(ctrl_link.clone().into_bytes().into_boxed_slice()),
        );
        binding.set_traversal_policy(TraversalPolicy::ForwardLower);

        pnp_ioctl_via_symlink(
            GLOBAL_CTRL_LINK.to_string(),
            IOCTL_MOUNTMGR_REGISTER_FS,
            &mut binding,
        )
        .await;
    });

    DriverStatus::Success
}

pub extern "win64" fn fs_device_add(
    _driver: Arc<DriverObject>,
    _dev_init: &mut DeviceInit,
) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}
