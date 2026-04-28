use alloc::{boxed::Box, collections::btree_map::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU64};
use fatfs::FsOptions;
use kernel_api::request::RequestDataView;
use spin::{Mutex, RwLock};

use kernel_api::{
    GLOBAL_CTRL_LINK, IOCTL_FS_IDENTIFY, IOCTL_MOUNTMGR_REGISTER_FS,
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        async_types::AsyncMutex,
        io::{FsIdentify, IoType, IoVtable, PartitionInfo},
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
use crate::volume::{FIRST_FILE_OWNER_ID, METADATA_OWNER_ID, VolCtrlDevExt, fs_op_dispatch};
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

#[request_handler]
pub async fn fs_root_ioctl<'a, 'b>(
    _dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => return DriverStep::complete(DriverStatus::NotImplemented),
        }
    };

    match code {
        IOCTL_FS_IDENTIFY => {
            let volume_fdo = {
                let mut r = req.write();

                let volume_fdo = match r.data() {
                    RequestDataView::FromDevice(mut data) => data
                        .view_mut::<FsIdentify>()
                        .map(|id| id.volume_fdo.clone()),
                    RequestDataView::ToDevice(_) => None,
                };

                let Some(volume_fdo) = volume_fdo else {
                    r.status = DriverStatus::InvalidParameter;
                    return DriverStep::complete(DriverStatus::InvalidParameter);
                };

                volume_fdo
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

            let st = pnp_send_request(volume_fdo.clone(), &mut query).await;

            let (sector_size, total_sectors) = {
                let mut sector_size = None;
                let mut total_sectors = None;

                if st == DriverStatus::Success {
                    let mut q = query.write();

                    if let Some(pnp) = q.pnp.as_mut() {
                        if let Some(pi) = pnp.data_out.try_take::<PartitionInfo>() {
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
                }

                (sector_size, total_sectors)
            };

            let (can_mount, mount_device) = match (sector_size, total_sectors) {
                (Some(sector_size), Some(total_sectors)) => {
                    let options = FsOptions::new().update_accessed_date(false).strict(false);
                    let target_clone = volume_fdo.clone();
                    let should_flush = Arc::new(AtomicBool::new(false));
                    let should_flush_blk = should_flush.clone();
                    let current_owner = Arc::new(AtomicU64::new(METADATA_OWNER_ID));
                    let current_owner_blk = current_owner.clone();

                    let result = spawn_blocking(move || {
                        fatfs::FileSystem::new(
                            BlockDev::new(
                                target_clone,
                                sector_size,
                                total_sectors,
                                should_flush_blk,
                                current_owner_blk,
                            ),
                            options,
                        )
                    })
                    .await;

                    match result {
                        Ok(fs) => {
                            let mut io_vtable = IoVtable::new();
                            io_vtable.set(IoType::Fs(fs_op_dispatch), 1);

                            let ext = VolCtrlDevExt {
                                fs: Arc::new(Mutex::new(fs)),
                                next_id: AtomicU64::new(FIRST_FILE_OWNER_ID),
                                table: RwLock::new(BTreeMap::new()),
                                volume_target: volume_fdo.clone(),
                                should_flush,
                                pending_flush_owner: Arc::new(AtomicU64::new(0)),
                                pending_flush_block: Arc::new(AtomicBool::new(false)),
                                current_owner,
                            };

                            let mut init = DeviceInit::new(io_vtable, None);
                            init.set_dev_ext_from(ext);

                            let vol_name = alloc::format!(
                                "\\Device\\fat32.vol.{:p}",
                                Arc::as_ptr(&volume_fdo)
                            );
                            let vol_ctrl = pnp_create_control_device_with_init(vol_name, init);

                            (true, Some(vol_ctrl))
                        }
                        Err(_) => (false, None),
                    }
                }
                _ => (false, None),
            };

            {
                let r = req.write();
                match r.data() {
                    RequestDataView::FromDevice(mut data) => {
                        if let Some(id) = data.view_mut::<FsIdentify>() {
                            id.mount_device = mount_device;
                            id.can_mount = can_mount;
                        } else {
                            r.set_data_t(FsIdentify {
                                mount_device,
                                can_mount,
                                volume_fdo: volume_fdo.clone(),
                            });
                        }
                    }
                    RequestDataView::ToDevice(_) => {
                        r.set_data_t(FsIdentify {
                            mount_device,
                            can_mount,
                            volume_fdo: volume_fdo.clone(),
                        });
                    }
                }

                r.status = DriverStatus::Success;
            }

            DriverStep::complete(DriverStatus::Success)
        }
        _ => DriverStep::complete(DriverStatus::NotImplemented),
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, fs_device_add);
    init_logger();
    let mut io_vtable = IoVtable::new();
    io_vtable.set(IoType::DeviceControl(fs_root_ioctl), 0);
    let init = DeviceInit::new(io_vtable, None);
    let ctrl_link = "\\GLOBAL\\FileSystems\\fat32".to_string();
    let ctrl_name = "\\Device\\fat32.fs".to_string();
    let _ctrl = pnp_create_control_device_and_link(ctrl_name, init, ctrl_link.clone());

    spawn_detached(async move {
        let mut binding = RequestHandle::new(
            RequestType::DeviceControl(IOCTL_MOUNTMGR_REGISTER_FS),
            RequestData::from_t::<Vec<u8>>(ctrl_link.into_bytes()),
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
    _driver: &Arc<DriverObject>,
    _dev_init: &mut DeviceInit,
) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}
