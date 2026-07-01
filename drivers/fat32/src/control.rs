use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64};

use fatfs::{Error, FileSystem, FsOptions, IoKind, Read};
use kernel_api::{
    device::{
        open_protocol_to_next_lower, open_public_protocol, DevExtRef, DeviceInit, DeviceObject,
        DriverObject, ProtocolHandle,
    },
    kernel_types::{
        async_ffi::{FfiFuture, FutureExt},
        async_types::AsyncMutex,
        pnp::{ProbeContext, ProbeOutcome},
        protocol::volmgr::VolmgrProtocol,
    },
    pnp::{
        driver_set_evt_device_add, driver_set_evt_probe_device, DriverStep, PnpOp, PnpOps,
        RemoveDevice, StartDevice,
    },
    request_handler,
    status::DriverStatus,
};
use spin::Mutex;

use crate::{
    block_dev::{flush, BlockDev},
    volume::{
        Fat32Fs, FileHandleTable, MountedFat32, VolCtrlDevExt, FILE_HANDLE_CAPACITY,
        METADATA_OWNER_ID,
    },
};

#[inline]
pub fn ext_mut<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("failed to get FAT32 device extension")
}

fn volume_geometry(
    protocol: &ProtocolHandle<VolmgrProtocol>,
) -> Result<(u16, u64), DriverStatus> {
    let info = (protocol.partition_info)(protocol.provider())?;
    let entry = info.gpt_entry.ok_or(DriverStatus::InvalidParameter)?;
    let sector_size = if info.disk.logical_block_size == 0 {
        512
    } else {
        u16::try_from(info.disk.logical_block_size).map_err(|_| DriverStatus::InvalidParameter)?
    };
    let sectors = entry
        .last_lba
        .checked_sub(entry.first_lba)
        .and_then(|count| count.checked_add(1))
        .ok_or(DriverStatus::InvalidParameter)?;
    Ok((sector_size, sectors))
}

extern "C" fn fat32_probe(
    _driver: &Arc<DriverObject>,
    context: &ProbeContext,
) -> FfiFuture<ProbeOutcome> {
    let context = context.clone();
    async move {
        let protocol = match open_public_protocol::<VolmgrProtocol>(&context.devnode) {
            Ok(protocol) => protocol,
            Err(status) => return ProbeOutcome::Error(status),
        };
        let (sector_size, sectors) = match volume_geometry(&protocol) {
            Ok(geometry) => geometry,
            Err(status) => return ProbeOutcome::Error(status),
        };
        let should_flush = Arc::new(AtomicBool::new(false));
        let current_owner = Arc::new(AtomicU64::new(METADATA_OWNER_ID));
        let mut probe_block = BlockDev::new(
            context.lower_target.clone(),
            sector_size,
            sectors,
            should_flush.clone(),
            current_owner.clone(),
        );
        let mut boot_sector = [0_u8; 512];
        if probe_block
            .read_exact(&mut boot_sector, IoKind::Metadata)
            .await
            .is_err()
        {
            return ProbeOutcome::Error(DriverStatus::Unsuccessful);
        }
        let fat32_signature = boot_sector[510..512] == [0x55, 0xaa]
            && boot_sector[17..19] == [0, 0]
            && boot_sector[22..24] == [0, 0]
            && u32::from_le_bytes([
                boot_sector[36],
                boot_sector[37],
                boot_sector[38],
                boot_sector[39],
            ]) != 0;
        if !fat32_signature {
            return ProbeOutcome::NoMatch;
        }
        let block = BlockDev::new(
            context.lower_target,
            sector_size,
            sectors,
            should_flush,
            current_owner,
        );
        match FileSystem::new(
            block,
            FsOptions::new().update_accessed_date(false).strict(false),
        )
        .await
        {
            Ok(_) => ProbeOutcome::Match,
            Err(Error::Io(_)) => ProbeOutcome::Error(DriverStatus::Unsuccessful),
            Err(_) => ProbeOutcome::Error(DriverStatus::Unsuccessful),
        }
    }
    .into_ffi()
}

pub extern "C" fn fat32_device_add(
    _driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStep {
    let mut pnp = PnpOps::new();
    pnp.start_device.set(fat32_start);
    pnp.remove_device.set(fat32_remove);
    init.pnp_ops = Some(pnp);
    init.ops.fs.register::<Fat32Fs>();
    init.set_dev_ext_default::<VolCtrlDevExt>();
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn fat32_start(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _request: &mut StartDevice,
) -> DriverStep {
    let protocol = match open_protocol_to_next_lower::<VolmgrProtocol>(device) {
        Ok(protocol) => protocol,
        Err(status) => return DriverStep::complete(status),
    };
    let (sector_size, sectors) = match volume_geometry(&protocol) {
        Ok(geometry) => geometry,
        Err(status) => return DriverStep::complete(status),
    };
    let Some(volume_target) = device.lower_device.read().clone() else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    let should_flush = Arc::new(AtomicBool::new(false));
    let current_owner = Arc::new(AtomicU64::new(METADATA_OWNER_ID));
    let block = BlockDev::new(
        volume_target.clone(),
        sector_size,
        sectors,
        should_flush.clone(),
        current_owner.clone(),
    );
    let filesystem = match FileSystem::new(
        block,
        FsOptions::new().update_accessed_date(false).strict(false),
    )
    .await
    {
        Ok(filesystem) => filesystem,
        Err(_) => return DriverStep::complete(DriverStatus::Unsuccessful),
    };

    let mounted = MountedFat32 {
        fs: Arc::new(AsyncMutex::new(filesystem)),
        handles: Mutex::new(FileHandleTable::with_capacity(FILE_HANDLE_CAPACITY)),
        volume_target,
        should_flush,
        pending_flush_owner: Arc::new(AtomicU64::new(0)),
        pending_flush_block: Arc::new(AtomicBool::new(false)),
        current_owner,
    };
    if ext_mut::<VolCtrlDevExt>(device).mount(mounted).is_err() {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn fat32_remove(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _request: &mut RemoveDevice,
) -> DriverStep {
    if device.is_started() {
        flush(&ext_mut::<VolCtrlDevExt>(device));
    }
    DriverStep::complete(DriverStatus::Success)
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_probe_device(driver, fat32_probe);
    driver_set_evt_device_add(driver, fat32_device_add);
    DriverStatus::Success
}
