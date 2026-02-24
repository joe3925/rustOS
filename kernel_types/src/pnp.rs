use crate::PnpMinorCallback;
use crate::request::RequestData;
use crate::status::DriverStatus;
use alloc::string::String;
use alloc::vec::Vec;
use array_init::array_init;
use spin::Once;

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
    pub handlers: [Once<PnpMinorCallback>; PNP_MINOR_COUNT],
}

const PNP_MINOR_COUNT: usize = core::mem::variant_count::<PnpMinorFunction>();

impl PnpVtable {
    #[inline]
    pub fn new() -> Self {
        Self {
            handlers: array_init(|_| Once::new()),
        }
    }

    #[inline]
    pub fn set(&self, m: PnpMinorFunction, cb: PnpMinorCallback) {
        let i = m as usize;
        if i < self.handlers.len() {
            let _ = self.handlers[i].call_once(|| cb);
        }
    }

    #[inline]
    pub fn get(&self, m: PnpMinorFunction) -> Option<PnpMinorCallback> {
        let i = m as usize;
        self.handlers.get(i).and_then(|h| h.get().copied())
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PnpRequest {
    pub minor_function: PnpMinorFunction,
    pub relation: DeviceRelationType,
    pub id_type: QueryIdType,
    pub ids_out: Vec<String>,
    pub data_out: RequestData,
}

impl PnpRequest {
    /// Print metadata without the actual data payload
    pub fn print_meta(&self) -> alloc::string::String {
        alloc::format!(
            "PnpRequest {{ minor_function: {:?}, relation: {:?}, id_type: {:?}, ids_out: {:?}, data_out: {} }}",
            self.minor_function,
            self.relation,
            self.id_type,
            self.ids_out,
            self.data_out.print_meta()
        )
    }
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
