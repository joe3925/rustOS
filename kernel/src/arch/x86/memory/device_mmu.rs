use crate::machine::MachineInfo;
use crate::memory::device_mmu::{DeviceMmuDiscoveryResult, DeviceMmuSystem};
use crate::platform::DeviceMmuPlatform;

use super::super::platform::X86Platform;
use super::iommu::X86DeviceMmu;

impl DeviceMmuPlatform for X86Platform {
    fn discover_device_mmu(
        machine: &MachineInfo,
    ) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>> {
        let Some(tables) = machine.firmware().acpi_tables() else {
            return Ok(None);
        };

        let Some(backend) = X86DeviceMmu::try_init_from_acpi(tables.as_ref())? else {
            return Ok(None);
        };

        Ok(Some(DeviceMmuSystem::from_backend(backend)))
    }
}
