use crate::device::{DeviceObject, Protocol, ProtocolId, ProtocolVersion};
use crate::error::KernelError;
use crate::io::PartitionInfo;
use alloc::sync::Arc;

#[repr(C)]
pub struct VolumeProtocolVTable {
    pub partition_info: extern "C" fn(&Arc<DeviceObject>) -> Result<PartitionInfo, KernelError>,
}

pub enum VolumeProtocol {}

unsafe impl Protocol for VolumeProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000003);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

    type VTable = VolumeProtocolVTable;
}
