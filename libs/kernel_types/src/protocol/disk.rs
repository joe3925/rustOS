use crate::device::{DeviceObject, Protocol, ProtocolId};
use crate::error::KernelError;
use crate::io::{DiskInfo, PartitionInfo};
use alloc::sync::Arc;

#[repr(C)]
pub struct DiskInfoProtocolVTable {
    pub query: extern "C" fn(&Arc<DeviceObject>) -> Result<DiskInfo, KernelError>,
}

pub enum DiskInfoProtocol {}

unsafe impl Protocol for DiskInfoProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000001);
    type VTable = DiskInfoProtocolVTable;
}

#[repr(C)]
pub struct PartitionInfoProtocolVTable {
    pub query: extern "C" fn(&Arc<DeviceObject>) -> Result<PartitionInfo, KernelError>,
}

pub enum PartitionInfoProtocol {}

unsafe impl Protocol for PartitionInfoProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000002);
    type VTable = PartitionInfoProtocolVTable;
}
