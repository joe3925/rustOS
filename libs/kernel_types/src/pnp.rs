use crate::device::DevNode;
use crate::dma::IoBufferBacking;
use crate::io::{HandlerSlot, IoHandler};
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

macro_rules! define_pnp_ops {
    (
        $(
            $field:ident {
                op: $op:ident,
                slot: $slot:ident,
                handler: $handler:ty,
                variant: $variant:ident,
                default: $default:expr
            }
        ),+ $(,)?
    ) => {
        $(
            pub enum $op {}
            pub type $slot = PnpSlot<$handler>;
        )+

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u32)]
        pub enum PnpOp {
            $($variant,)+
        }

        impl PnpOp {
            #[inline]
            pub fn default_status_for_unhandled(self) -> DriverStatus {
                match self {
                    $(Self::$variant => $default,)+
                }
            }
        }

        #[repr(C)]
        #[derive(Debug)]
        pub struct PnpOps {
            $(pub $field: $slot,)+
        }

        pub trait PnpOpHandlerRegistration<Op, H> {
            fn set_pnp_op_handler(&mut self, handler: H, depth: u32);
        }

        impl PnpOps {
            pub const fn new() -> Self {
                Self {
                    $($field: PnpSlot::empty(),)+
                }
            }

            #[inline]
            pub fn register<Op, H>(&mut self, handler: H)
            where
                Self: PnpOpHandlerRegistration<Op, H>,
            {
                <Self as PnpOpHandlerRegistration<Op, H>>::set_pnp_op_handler(self, handler, 0);
            }

            #[inline]
            pub fn register_with_depth<Op, H>(&mut self, handler: H, depth: u32)
            where
                Self: PnpOpHandlerRegistration<Op, H>,
            {
                <Self as PnpOpHandlerRegistration<Op, H>>::set_pnp_op_handler(
                    self,
                    handler,
                    depth,
                );
            }
        }

        impl Default for PnpOps {
            fn default() -> Self {
                Self::new()
            }
        }

        $(
            impl PnpOpHandlerRegistration<$op, $handler> for PnpOps {
                #[inline]
                fn set_pnp_op_handler(&mut self, handler: $handler, depth: u32) {
                    self.$field.set_with_depth(handler, depth);
                }
            }
        )+
    };
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
}

impl Default for ResourceSet {
    fn default() -> Self {
        Self::Descriptors(Vec::new())
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct InitComplete;

#[repr(C)]
#[derive(Debug, Default)]
pub struct SurpriseRemoval;

#[repr(C)]
#[derive(Debug, Default)]
pub struct RemoveDevice;

#[repr(C)]
#[derive(Debug, Default)]
pub struct StopDevice;

pub type PnpHandler<T> = IoHandler<T>;
pub type PnpSlot<T> = HandlerSlot<T>;

define_pnp_ops! {
    start_device {
        op: PnpStartDeviceOp,
        slot: StartDeviceSlot,
        handler: crate::EvtPnpStartDevice,
        variant: StartDevice,
        default: DriverStatus::Success
    },
    init_complete {
        op: PnpInitCompleteOp,
        slot: InitCompleteSlot,
        handler: crate::EvtPnpInitComplete,
        variant: InitComplete,
        default: DriverStatus::Success
    },
    query_device_relations {
        op: PnpQueryDeviceRelationsOp,
        slot: QueryDeviceRelationsSlot,
        handler: crate::EvtPnpQueryDeviceRelations,
        variant: QueryDeviceRelations,
        default: DriverStatus::Success
    },
    query_id {
        op: PnpQueryIdOp,
        slot: QueryIdSlot,
        handler: crate::EvtPnpQueryId,
        variant: QueryId,
        default: DriverStatus::NotImplemented
    },
    register_dma_backing {
        op: PnpRegisterDmaBackingOp,
        slot: RegisterDmaBackingSlot,
        handler: crate::EvtPnpRegisterDmaBacking,
        variant: RegisterDmaBacking,
        default: DriverStatus::NotImplemented
    },
    query_resources {
        op: PnpQueryResourcesOp,
        slot: QueryResourcesSlot,
        handler: crate::EvtPnpQueryResources,
        variant: QueryResources,
        default: DriverStatus::NotImplemented
    },
    surprise_removal {
        op: PnpSurpriseRemovalOp,
        slot: SurpriseRemovalSlot,
        handler: crate::EvtPnpSurpriseRemoval,
        variant: SurpriseRemoval,
        default: DriverStatus::Success
    },
    remove_device {
        op: PnpRemoveDeviceOp,
        slot: RemoveDeviceSlot,
        handler: crate::EvtPnpRemoveDevice,
        variant: RemoveDevice,
        default: DriverStatus::Success
    },
    stop_device {
        op: PnpStopDeviceOp,
        slot: StopDeviceSlot,
        handler: crate::EvtPnpStopDevice,
        variant: StopDevice,
        default: DriverStatus::Success
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
