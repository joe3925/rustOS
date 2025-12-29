use crate::async_ffi::FfiFuture;
use crate::device::DeviceObject;
use crate::pnp::DriverStep;
use crate::request::{Request, RequestType};
use crate::status::DriverStatus;
use crate::{EvtIoDeviceControl, EvtIoFs, EvtIoRead, EvtIoWrite};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use spin::RwLock;

#[repr(C)]
#[derive(Clone)]
pub struct IoTarget {
    pub target_device: Arc<DeviceObject>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GptHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub _reserved: u32,
    pub _current_lba: u64,
    pub _backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub _partition_crc32: u32,
    pub_reserved_block: [u8; 420],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DiskInfo {
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub total_logical_blocks: u64,
    pub total_bytes_low: u64,
    pub total_bytes_high: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub disk: DiskInfo,
    pub gpt_header: Option<GptHeader>,
    pub gpt_entry: Option<GptPartitionEntry>,
}

#[repr(C)]
pub struct FsIdentify {
    pub volume_fdo: IoTarget,
    pub mount_device: Option<Arc<DeviceObject>>,
    pub can_mount: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlkRead {
    pub lba: u64,
    pub sectors: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GptPartitionEntry {
    pub partition_type_guid: [u8; 16],
    pub unique_partition_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub _attr: u64,
    pub name_utf16: [u16; 36],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub enum IoType {
    Read(EvtIoRead),
    Write(EvtIoWrite),
    DeviceControl(EvtIoDeviceControl),
    Fs(EvtIoFs),
}

impl IoType {
    #[inline]
    pub fn slot(&self) -> usize {
        match self {
            IoType::Read(_) => 0,
            IoType::Write(_) => 1,
            IoType::DeviceControl(_) => 2,
            IoType::Fs(_) => 3,
        }
    }

    #[inline]
    pub async fn invoke(&self, dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
        match *self {
            IoType::Read(h) | IoType::Write(h) => {
                let len = req.read().data.len();
                h(dev, req, len).await
            }
            IoType::DeviceControl(h) => h(dev, req).await,
            IoType::Fs(h) => h(dev, req).await,
        }
    }

    #[inline]
    pub fn slot_for_request(r: &RequestType) -> Option<usize> {
        match r {
            RequestType::Read { .. } => Some(0),
            RequestType::Write { .. } => Some(1),
            RequestType::DeviceControl(_) => Some(2),
            RequestType::Fs(_) => Some(3),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum Synchronization {
    Sync,
    Async,
    FireAndForget,
}

#[derive(Clone)]
#[repr(C)]
pub struct IoHandler {
    pub handler: IoType,
    pub synchronization: Synchronization,
    pub depth: usize,
    pub running_request: Arc<AtomicU64>,
}

impl core::fmt::Debug for IoHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoHandler")
            .field("synchronization", &self.synchronization)
            .finish()
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct IoVtable {
    pub handlers: Vec<Option<IoHandler>>,
}

impl IoVtable {
    #[inline]
    pub fn new() -> Self {
        let n = 4;
        Self {
            handlers: alloc::vec![None; n],
        }
    }

    #[inline]
    pub fn set(&mut self, cb: IoType, synchronization: Synchronization, depth: usize) {
        let i = cb.slot();
        if i < self.handlers.len() {
            self.handlers[i] = Some(IoHandler {
                handler: cb,
                synchronization,
                depth,
                running_request: Arc::new(AtomicU64::new(0)),
            });
        }
    }

    #[inline]
    pub fn get_for(&self, r: &RequestType) -> Option<IoHandler> {
        IoType::slot_for_request(r).and_then(|i| self.handlers.get(i).cloned().flatten())
    }
}
