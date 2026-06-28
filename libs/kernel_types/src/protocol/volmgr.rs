use alloc::sync::Arc;
use crate::device::{DeviceObject, Protocol, ProtocolId, ProtocolVersion};
use crate::io::PartitionInfo;
use crate::status::DriverStatus;

#[repr(C)]
pub struct VolmgrProtocolVTable {
    pub partition_info: extern "C" fn(&Arc<DeviceObject>) -> Result<PartitionInfo, DriverStatus>,
}

pub enum VolmgrProtocol {}

unsafe impl Protocol for VolmgrProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000003);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

    type VTable = VolmgrProtocolVTable;
}
