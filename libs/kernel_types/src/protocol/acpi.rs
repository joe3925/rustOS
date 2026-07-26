use crate::device::{DeviceObject, Protocol, ProtocolId, ProtocolVersion};
use crate::error::KernelError;
use crate::pci::{EcamSegment, PrtEntry};
use alloc::sync::Arc;
use alloc::vec::Vec;

#[repr(C)]
pub struct AcpiPciProtocolVTable {
    pub get_ecam_segments:
        extern "C" fn(&Arc<DeviceObject>) -> Result<Vec<EcamSegment>, KernelError>,
    pub get_prt_entries: extern "C" fn(&Arc<DeviceObject>) -> Result<Vec<PrtEntry>, KernelError>,
}

pub enum AcpiPciProtocol {}
unsafe impl Protocol for AcpiPciProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000005);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
    type VTable = AcpiPciProtocolVTable;
}
