use crate::device::{DeviceObject, Protocol, ProtocolId};
use crate::pci::{Bar, MsixInfo};
use alloc::sync::Arc;

#[repr(C)]
pub struct PciProtocolVTable {
    pub get_bar: extern "C" fn(&Arc<DeviceObject>, u8) -> Option<Bar>,
    pub get_config_space_phys: extern "C" fn(&Arc<DeviceObject>) -> Option<(u64, u64)>,
    pub get_gsi: extern "C" fn(&Arc<DeviceObject>) -> Option<u16>,
    pub get_interrupt_line: extern "C" fn(&Arc<DeviceObject>) -> Option<u8>,
    pub get_msix: extern "C" fn(&Arc<DeviceObject>) -> Option<MsixInfo>,
}

pub enum PciProtocol {}
unsafe impl Protocol for PciProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000006);
    type VTable = PciProtocolVTable;
}
