use alloc::sync::Arc;
use crate::device::{DeviceObject, Protocol, ProtocolId, ProtocolVersion};
use crate::io::{DiskInfo, PartitionInfo};
use crate::status::DriverStatus;

#[repr(C)]
pub struct DiskInfoProtocolVTable {
    pub query: extern "C" fn(&Arc<DeviceObject>) -> Result<DiskInfo, DriverStatus>,
}

pub enum DiskInfoProtocol {}

unsafe impl Protocol for DiskInfoProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000001);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

    type VTable = DiskInfoProtocolVTable;
}

#[repr(C)]
pub struct PartitionInfoProtocolVTable {
    pub query: extern "C" fn(&Arc<DeviceObject>) -> Result<PartitionInfo, DriverStatus>,
}

pub enum PartitionInfoProtocol {}

unsafe impl Protocol for PartitionInfoProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000002);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

    type VTable = PartitionInfoProtocolVTable;
}
