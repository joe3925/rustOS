use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64};

use fatfs::{Error, FileSystem, FsOptions, IoKind, Read};
use kernel_api::{
    device::{
        DevExtRef, DeviceInit, DeviceObject, DriverObject, ProtocolHandle,
        open_protocol_to_next_lower, open_public_protocol,
    },
    kernel_types::{
        async_ffi::{AbiFuture, FutureExt},
        async_types::AsyncMutex,
        pnp::{ProbeContext, ProbeOutcome},
        protocol::volmgr::VolumeProtocol,
    },
    pnp::{
        DriverStep, PnpOp, PnpOps, RemoveDevice, StartDevice, driver_set_evt_device_add,
        driver_set_evt_probe_device,
    },
    request_handler,
};
use kernel_api::error::{error, DriverErrorKind, FileErrorKind, KernelError, ResultErrorContext};
use spin::Mutex;

use crate::{
    block_dev::{BlockDev, flush},
    volume::{
        FILE_HANDLE_CAPACITY, Fat32Fs, FileHandleTable, METADATA_OWNER_ID, MountedFat32,
        VolCtrlDevExt,
    },
};

#[inline]
pub fn ext_mut<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext()
        .expect("failed to get FAT32 device extension")
}

fn volume_geometry(
    protocol: &ProtocolHandle<VolumeProtocol>,
) -> Result<(u16, u64), KernelError> {
    let info = (protocol.partition_info)(protocol.provider())
        .with_context(|| "querying FAT32 volume partition information")?;
    let entry = info.gpt_entry.ok_or_else(|| {
        error(DriverErrorKind::InvalidParameter)
            .with_context("FAT32 volume partition information has no GPT entry")
    })?;
    let sector_size = if info.disk.logical_block_size == 0 {
        512
    } else {
        u16::try_from(info.disk.logical_block_size)
            .map_err(|_| error(DriverErrorKind::InvalidParameter))
            .with_context(|| {
                alloc::format!(
                    "FAT32 logical block size {} does not fit in u16",
                    info.disk.logical_block_size
                )
            })?
    };
    let sectors = entry
        .last_lba
        .checked_sub(entry.first_lba)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            error(DriverErrorKind::InvalidParameter).with_context(alloc::format!(
                "invalid FAT32 GPT LBA range {}..={}",
                entry.first_lba,
                entry.last_lba
            ))
        })?;
    Ok((sector_size, sectors))
}

extern "C" fn fat32_probe(
    _driver: &Arc<DriverObject>,
    context: &ProbeContext,
) -> AbiFuture<ProbeOutcome> {
    let context = context.clone();
    async move {
        let protocol = match open_public_protocol::<VolumeProtocol>(&context.devnode) {
            Ok(protocol) => protocol,
            Err(kind) => {
                return ProbeOutcome::Error(
                    error(kind).with_context("opening the FAT32 probe volume protocol"),
                )
            }
        };
        let (sector_size, sectors) = match volume_geometry(&protocol) {
            Ok(geometry) => geometry,
            Err(err) => return ProbeOutcome::Error(err),
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
        if let Err(probe_error) = probe_block
            .read_exact(&mut boot_sector, IoKind::Metadata)
            .await
        {
            return ProbeOutcome::Error(
                probe_error
                    .0
                    .with_context("reading the FAT32 probe boot sector"),
            );
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
            Err(Error::Io(err)) => {
                ProbeOutcome::Error(err.0.with_context("mounting FAT32 during probe"))
            }
            Err(other) => ProbeOutcome::Error(
                error(DriverErrorKind::DeviceError)
                    .with_context(alloc::format!("mounting FAT32 during probe: {other:?}")),
            ),
        }
    }
    .into_abi()
}

pub extern "C" fn fat32_device_add(
    _driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let mut pnp = PnpOps::new();
    pnp.start_device.set(fat32_start);
    pnp.remove_device.set(fat32_remove);
    init.pnp_ops = Some(pnp);
    init.ops.fs.register::<Fat32Fs>();
    init.set_dev_ext_default::<VolCtrlDevExt>();
    Ok(DriverStep::Complete)
}

#[request_handler]
async fn fat32_start(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _request: &mut StartDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let protocol = match open_protocol_to_next_lower::<VolumeProtocol>(device) {
        Ok(protocol) => protocol,
        Err(kind) => {
            return Err(error(kind))
                .with_context(|| "opening the lower volume protocol while starting FAT32")
        }
    };
    let (sector_size, sectors) = match volume_geometry(&protocol) {
        Ok(geometry) => geometry,
        Err(err) => return Err(err),
    };
    let Some(volume_target) = device.lower_device.read().clone() else {
        return Err(error(DriverErrorKind::NoSuchDevice))
            .with_context(|| "starting FAT32 without a lower volume target");
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
        Err(Error::Io(err)) => {
            return Err(err.0).with_context(|| "mounting the FAT32 filesystem")
        }
        Err(other) => {
            return Err(error(DriverErrorKind::DeviceError))
                .with_context(|| alloc::format!("mounting the FAT32 filesystem: {other:?}"))
        }
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
        return Err(error(DriverErrorKind::InvalidParameter))
            .with_context(|| "mounting FAT32 more than once on the same device");
    }
    Ok(DriverStep::Complete)
}

#[request_handler]
async fn fat32_remove(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _request: &mut RemoveDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    if device.is_started() {
        flush(&ext_mut::<VolCtrlDevExt>(device));
    }
    Ok(DriverStep::Complete)
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> Result<(), kernel_api::error::KernelError> {
    driver_set_evt_probe_device(driver, fat32_probe);
    driver_set_evt_device_add(driver, fat32_device_add);
    Ok(())
}
