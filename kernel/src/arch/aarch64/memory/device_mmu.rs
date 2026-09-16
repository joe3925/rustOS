use crate::machine::MachineInfo;
use crate::memory::device_mmu::{DeviceMmuDiscoveryResult, DeviceMmuSystem};
use crate::platform::DeviceMmuPlatform;

use super::super::platform::Aarch64Platform;
use super::smmu;

impl DeviceMmuPlatform for Aarch64Platform {
    fn discover_device_mmu(
        machine: &MachineInfo,
    ) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>> {
        smmu::discover(machine)
    }
}
