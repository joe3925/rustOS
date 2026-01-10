use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU64};
use fatfs::FsOptions;
use spin::{Mutex, RwLock};

use kernel_api::{
    GLOBAL_CTRL_LINK, IOCTL_MOUNTMGR_REGISTER_FS, RequestExt,
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
    request::{Request, RequestType, TraversalPolicy},
    request_handler,
    runtime::{spawn, spawn_blocking},
    status::DriverStatus,
};

use crate::block_dev::BlockDev;
use crate::volume::{VolCtrlDevExt, fs_op_dispatch};

#[inline]
pub fn ext_mut<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("Failed to get fat32 dev ext")
}

fn from_boxed_bytes<T>(bytes: Box<[u8]>) -> Result<T, DriverStatus> {
    if bytes.len() != size_of::<T>() {
        return Err(DriverStatus::InvalidParameter);
    }
    let ptr = bytes.as_ptr();
    if (ptr as usize) % align_of::<T>() != 0 {
        drop(bytes);
        return Err(DriverStatus::InvalidParameter);
    }
    // SAFETY: same rationale as take_req.
    let val = unsafe { (ptr as *const T).read() };
    drop(bytes);
    Ok(val)
}

#[request_handler]
pub async fn fs_root_ioctl(_dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => {
                drop(r);
                req.write().status = DriverStatus::InvalidParameter;
                return DriverStep::complete(DriverStatus::NotImplemented);
            }
        }
    };

    match code {
        IOCTL_FS_IDENTIFY => {
            let mut id = {
                let mut r = req.write();
                match r.take_data::<FsIdentify>() {
                    Some(v) => v,
                    None => return DriverStep::complete(DriverStatus::InvalidParameter),
                }
            };

            let q = Request::new_pnp(
                PnpRequest {
                    minor_function: PnpMinorFunction::QueryResources,
                    relation: DeviceRelationType::TargetDeviceRelation,
                    id_type: QueryIdType::DeviceId,
                    ids_out: Vec::new(),
                    blob_out: Vec::new(),
                },
                RequestData::empty(),
            );
            let q = Arc::new(RwLock::new(q));

            pnp_send_request(id.volume_fdo.clone(), q.clone()).await;

            let mut sector_size: Option<u16> = None;
            let mut total_sectors: Option<u64> = None;
            let mut w = q.write();
            if w.status == DriverStatus::Success {
                if let Some(pnp) = w.pnp.as_mut() {
                    let buf = core::mem::take(&mut pnp.blob_out);
                    if let Ok(pi) = from_boxed_bytes::<PartitionInfo>(buf.into_boxed_slice()) {
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
            drop(w);

            let (sector_size, total_sectors) = match (sector_size, total_sectors) {
                (Some(sz), Some(ts)) => (sz, ts),
                _ => {
                    id.mount_device = None;
                    id.can_mount = false;
                    req.write().set_data_t(id);
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
                    req.write().set_data_t(id);
                    DriverStep::complete(DriverStatus::Success)
                }
                Err(_e) => {
                    id.mount_device = None;
                    id.can_mount = false;
                    req.write().set_data_t(id);
                    DriverStep::complete(DriverStatus::Success)
                }
            }
        }
        _ => DriverStep::complete(DriverStatus::NotImplemented),
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn fat_start(
    _dev: &Arc<DeviceObject>,
    _req: Arc<spin::rwlock::RwLock<Request>>,
) -> DriverStep {
    DriverStep::Continue
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, fs_device_add);
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

    let reg = Arc::new(RwLock::new(
        Request::new(
            RequestType::DeviceControl(IOCTL_MOUNTMGR_REGISTER_FS),
            RequestData::from_boxed_bytes(ctrl_link.clone().into_bytes().into_boxed_slice()),
        )
        .set_traversal_policy(TraversalPolicy::ForwardLower),
    ));

    spawn(async move {
        pnp_ioctl_via_symlink(
            GLOBAL_CTRL_LINK.to_string(),
            IOCTL_MOUNTMGR_REGISTER_FS,
            reg.clone(),
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
