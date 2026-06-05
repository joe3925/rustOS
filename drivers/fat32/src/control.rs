use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64};
use fatfs::FsOptions;
use kernel_api::request::RequestDataView;

use kernel_api::{
    GLOBAL_CTRL_LINK, IOCTL_FS_IDENTIFY, IOCTL_MOUNTMGR_REGISTER_FS,
    device::{DevExtRef, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{
        async_types::AsyncMutex,
        io::{DeviceControlHandler, FsIdentify, PartitionInfo},
        request::RequestData,
    },
    pnp::{
        DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, QueryIdType,
        driver_set_evt_device_add, pnp_create_control_device_and_link,
        pnp_create_control_device_with_init, pnp_ioctl_via_symlink, pnp_send_request,
    },
    request::{DeviceControl, Pnp, RequestHandle, TraversalPolicy},
    request_handler,
    runtime::spawn_detached,
    status::DriverStatus,
};

use crate::block_dev::BlockDev;
use crate::volume::{
    FILE_HANDLE_CAPACITY, Fat32Fs, FileHandleTable, METADATA_OWNER_ID, VolCtrlDevExt,
};
use log::{Metadata, Record};
use spin::Mutex;

struct KernelLogger;

impl log::Log for KernelLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        false
    }

    fn log(&self, _record: &Record) {}

    fn flush(&self) {}
}

static LOGGER: KernelLogger = KernelLogger;

fn init_logger() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Off);
}

#[inline]
pub fn ext_mut<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("Failed to get fat32 dev ext")
}

pub struct Fat32RootIo;

impl DeviceControlHandler for Fat32RootIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        _dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, DeviceControl<'data>>,
    ) -> DriverStep {
        let code = req.read().body.code;

        match code {
            IOCTL_FS_IDENTIFY => {
                let volume_fdo = {
                    let r = req.write();

                    let volume_fdo = match r.data() {
                        RequestDataView::Writable(mut data) => data
                            .view_mut::<FsIdentify>()
                            .map(|id| id.volume_fdo.clone()),
                        RequestDataView::ReadOnly(_) => None,
                    };

                    let Some(volume_fdo) = volume_fdo else {
                        r.status = DriverStatus::InvalidParameter;
                        return DriverStep::complete(DriverStatus::InvalidParameter);
                    };

                    volume_fdo
                };

                let mut query = RequestHandle::new(Pnp {
                    request: PnpRequest {
                        minor_function: PnpMinorFunction::QueryResources,
                        relation: DeviceRelationType::TargetDeviceRelation,
                        id_type: QueryIdType::DeviceId,
                        ids_out: Vec::new(),
                        data_out: RequestData::empty(),
                    },
                });

                let st = pnp_send_request(volume_fdo.clone(), &mut query).await;

                let (sector_size, total_sectors) = {
                    let mut sector_size = None;
                    let mut total_sectors = None;

                    if st == DriverStatus::Success {
                        let q = query.write();

                        if let Some(pi) = q.body.request.data_out.take_exact::<PartitionInfo>().ok()
                        {
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

                        let result = fatfs::FileSystem::new(
                            BlockDev::new(
                                target_clone,
                                sector_size,
                                total_sectors,
                                should_flush_blk,
                                current_owner_blk,
                            ),
                            options,
                        )
                        .await;

                        match result {
                            Ok(fs) => {
                                let ext = VolCtrlDevExt {
                                    fs: Arc::new(AsyncMutex::new(fs)),
                                    handles: Mutex::new(FileHandleTable::with_capacity(
                                        FILE_HANDLE_CAPACITY,
                                    )),
                                    volume_target: volume_fdo.clone(),
                                    should_flush,
                                    pending_flush_owner: Arc::new(AtomicU64::new(0)),
                                    pending_flush_block: Arc::new(AtomicBool::new(false)),
                                    current_owner,
                                };

                                let mut init = DeviceInit::new();
                                init.ops.fs.register::<Fat32Fs>();
                                init.set_dev_ext_from(ext);

                                let vol_name = alloc::format!(
                                    "\\Device\\fat32.vol.{:p}",
                                    Arc::as_ptr(&volume_fdo)
                                );
                                let vol_ctrl = pnp_create_control_device_with_init(vol_name, init);

                                (true, Some(vol_ctrl))
                            }
                            Err(_e) => (false, None),
                        }
                    }
                    _ => (false, None),
                };

                {
                    let r = req.write();
                    let mut replacement = Some(FsIdentify {
                        mount_device,
                        can_mount,
                        volume_fdo,
                    });
                    let replace_payload = match r.data() {
                        RequestDataView::Writable(mut data) => {
                            if let Some(id) = data.view_mut::<FsIdentify>() {
                                let value = replacement.take().unwrap();
                                id.mount_device = value.mount_device;
                                id.can_mount = can_mount;
                                false
                            } else {
                                true
                            }
                        }
                        RequestDataView::ReadOnly(_) => true,
                    };

                    if replace_payload {
                        r.set_data_t(replacement.unwrap());
                    }

                    r.status = DriverStatus::Success;
                }

                DriverStep::complete(DriverStatus::Success)
            }
            _ => DriverStep::complete(DriverStatus::NotImplemented),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, fs_device_add);
    init_logger();
    let mut init = DeviceInit::new();
    init.ops.device_control.register::<Fat32RootIo>();
    let ctrl_link = "\\GLOBAL\\FileSystems\\fat32".to_string();
    let ctrl_name = "\\Device\\fat32.fs".to_string();
    let _ctrl = pnp_create_control_device_and_link(ctrl_name, init, ctrl_link.clone());

    spawn_detached(async move {
        let mut binding = RequestHandle::new(DeviceControl::new_t(
            IOCTL_MOUNTMGR_REGISTER_FS,
            ctrl_link.into_bytes(),
        ));
        binding.set_traversal_policy(TraversalPolicy::ForwardLower);
        let _ioctl_status = pnp_ioctl_via_symlink(
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
