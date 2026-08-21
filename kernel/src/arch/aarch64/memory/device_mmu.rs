use crate::machine::MachineInfo;
use crate::memory::device_mmu::{DeviceMmuDiscoveryResult, DeviceMmuSystem};
use crate::platform::DeviceMmuPlatform;

use super::super::platform::Aarch64Platform;

impl DeviceMmuPlatform for Aarch64Platform {
    fn discover_device_mmu(
        _machine: &MachineInfo,
    ) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>> {
        todo!()
    }
}
