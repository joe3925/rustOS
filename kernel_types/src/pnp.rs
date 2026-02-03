use crate::PnpMinorCallback;
use crate::status::DriverStatus;
use alloc::string::String;
use alloc::vec::Vec;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct DeviceIds {
    pub hardware: Vec<String>,
    pub compatible: Vec<String>,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverStep {
    Continue,
    Pending,
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
pub enum PnpMinorFunction {
    StartDevice,
    QueryDeviceRelations,
    QueryId,
    QueryResources,
    SurpriseRemoval,
    RemoveDevice,
    StopDevice,
}

impl PnpMinorFunction {
    pub fn default_status_for_unhandled(&self) -> DriverStatus {
        match self {
            Self::StartDevice
            | Self::QueryDeviceRelations
            | Self::SurpriseRemoval
            | Self::RemoveDevice
            | Self::StopDevice => DriverStatus::Success,
            Self::QueryId | Self::QueryResources => DriverStatus::NotImplemented,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PnpVtable {
    pub handlers: Vec<Option<PnpMinorCallback>>,
}

impl PnpVtable {
    #[inline]
    pub fn new() -> Self {
        let n = core::mem::variant_count::<PnpMinorFunction>();
        Self {
            handlers: alloc::vec![None; n],
        }
    }

    #[inline]
    pub fn set(&mut self, m: PnpMinorFunction, cb: PnpMinorCallback) {
        let i = m as usize;
        if i < self.handlers.len() {
            self.handlers[i] = Some(cb);
        }
    }

    #[inline]
    pub fn get(&self, m: PnpMinorFunction) -> Option<PnpMinorCallback> {
        let i = m as usize;
        if i < self.handlers.len() {
            self.handlers[i]
        } else {
            None
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct PnpRequest {
    pub minor_function: PnpMinorFunction,
    pub relation: DeviceRelationType,
    pub id_type: QueryIdType,
    pub ids_out: Vec<String>,
    pub blob_out: Vec<u8>,
}

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
