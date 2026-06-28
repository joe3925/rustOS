use crate::device::DevNode;
use crate::dma::IoBufferBacking;
use crate::io::IoHandler;
use crate::io::{DiskInfo, PartitionInfo};
use crate::status::DriverStatus;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct DeviceIds {
    pub hardware: Vec<String>,
    pub compatible: Vec<String>,
}
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriverStep {
    Continue,
    Complete { status: DriverStatus },
}

impl DriverStep {
    #[inline(always)]
    pub fn complete(status: DriverStatus) -> Self {
        DriverStep::Complete { status }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceRelationType {
    BusRelations,
    EjectionRelations,
    RemovalRelations,
    TargetDeviceRelation,
    PowerRelations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QueryIdType {
    DeviceId,
    HardwareIds,
    CompatibleIds,
    InstanceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PnpOp {
    StartDevice,
    QueryDeviceRelations,
    QueryId,

    RegisterDmaBacking,
    QueryResources,

    SurpriseRemoval,
    RemoveDevice,
    StopDevice,
}

impl PnpOp {
    pub fn default_status_for_unhandled(self) -> DriverStatus {
        match self {
            Self::StartDevice
            | Self::QueryDeviceRelations
            | Self::SurpriseRemoval
            | Self::RemoveDevice
            | Self::StopDevice => DriverStatus::Success,

            Self::QueryId | Self::QueryResources | Self::RegisterDmaBacking => {
                DriverStatus::NotImplemented
            }
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct StartDevice {
    pub resources: Vec<ResourceDescriptor>,
}

#[repr(C)]
#[derive(Debug)]
pub struct QueryDeviceRelations {
    pub relation: DeviceRelationType,
    pub devices: Vec<Arc<DevNode>>,
}

#[repr(C)]
#[derive(Debug)]
pub struct QueryId {
    pub id_type: QueryIdType,
    pub ids: Vec<String>,
}

#[repr(C)]
pub struct RegisterDmaBacking<'data> {
    pub backing: &'data IoBufferBacking<'data>,
}

#[repr(C)]
#[derive(Debug)]
pub struct QueryResources {
    pub resources: ResourceSet,
}

#[derive(Debug, Clone)]
pub enum ResourceSet {
    Descriptors(Vec<ResourceDescriptor>),
    Encoded(Vec<u8>),
    Disk(DiskInfo),
    Partition(PartitionInfo),
}

impl Default for ResourceSet {
    fn default() -> Self {
        Self::Descriptors(Vec::new())
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SurpriseRemoval;

#[repr(C)]
#[derive(Debug, Default)]
pub struct RemoveDevice;

#[repr(C)]
#[derive(Debug, Default)]
pub struct StopDevice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResourceKind {
    Memory = 1,
    Port = 2,
    Interrupt = 3,
    ConfigSpace = 4,
    Gsi = 5,
    MsixCapability = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceDescriptor {
    pub kind: ResourceKind,
    pub index: u32,
    pub start: u64,
    pub length: u64,
}

impl ResourceDescriptor {
    pub const fn memory(index: u32, start: u64, length: u64) -> Self {
        Self {
            kind: ResourceKind::Memory,
            index,
            start,
            length,
        }
    }

    pub const fn interrupt(index: u32, irq: u64) -> Self {
        Self {
            kind: ResourceKind::Interrupt,
            index,
            start: irq,
            length: 0,
        }
    }
}

pub type PnpHandler<T> = IoHandler<T>;

#[repr(C)]
#[derive(Debug)]
pub struct PnpSlot<T> {
    handler: Option<PnpHandler<T>>,
}

impl<T> PnpSlot<T> {
    pub const fn empty() -> Self {
        Self { handler: None }
    }

    #[inline]
    pub fn as_handler(&self) -> Option<&PnpHandler<T>> {
        self.handler.as_ref()
    }

    #[inline]
    pub fn set(&mut self, handler: T) {
        self.handler = Some(PnpHandler::new(handler, 0));
    }

    #[inline]
    pub fn clear(&mut self) {
        self.handler = None;
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PnpOps {
    pub start_device: PnpSlot<crate::EvtPnpStartDevice>,
    pub query_device_relations: PnpSlot<crate::EvtPnpQueryDeviceRelations>,
    pub query_id: PnpSlot<crate::EvtPnpQueryId>,
    pub register_dma_backing: PnpSlot<crate::EvtPnpRegisterDmaBacking>,
    pub query_resources: PnpSlot<crate::EvtPnpQueryResources>,
    pub surprise_removal: PnpSlot<crate::EvtPnpSurpriseRemoval>,
    pub remove_device: PnpSlot<crate::EvtPnpRemoveDevice>,
    pub stop_device: PnpSlot<crate::EvtPnpStopDevice>,
}

impl PnpOps {
    pub const fn new() -> Self {
        Self {
            start_device: PnpSlot::empty(),
            query_device_relations: PnpSlot::empty(),
            query_id: PnpSlot::empty(),
            register_dma_backing: PnpSlot::empty(),
            query_resources: PnpSlot::empty(),
            surprise_removal: PnpSlot::empty(),
            remove_device: PnpSlot::empty(),
            stop_device: PnpSlot::empty(),
        }
    }
}

impl Default for PnpOps {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encode_resource_descriptors(resources: &[ResourceDescriptor]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + resources.len() * 24);
    out.extend_from_slice(b"RSRC");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(resources.len() as u32).to_le_bytes());
    for resource in resources {
        out.extend_from_slice(&(resource.kind as u32).to_le_bytes());
        out.extend_from_slice(&resource.index.to_le_bytes());
        out.extend_from_slice(&resource.start.to_le_bytes());
        out.extend_from_slice(&resource.length.to_le_bytes());
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BootType {
    Boot = 0,
    System = 1,
    Demand = 2,
    Disabled = 3,
}

impl BootType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "boot" => Some(BootType::Boot),
            "system" => Some(BootType::System),
            "demand" => Some(BootType::Demand),
            "disabled" => Some(BootType::Disabled),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}
