use crate::machine::MachineInfo;
use crate::memory::device_mmu::{DeviceMmuDiscoveryResult, DeviceMmuSystem};
use crate::platform::DeviceMmuPlatform;

use super::super::platform::Aarch64Platform;
use super::smmu;
use kernel_types::irq::{MsiBindingRequest, MsiMessage};
impl DeviceMmuPlatform for Aarch64Platform {
    fn discover_device_mmu(
        machine: &MachineInfo,
    ) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>> {
        smmu::discover(machine)
    }
}
pub(crate) fn prepare_msi_message(
    request: &MsiBindingRequest,
    message: MsiMessage,
) -> Option<MsiMessage> {
    let Some(device) = request.device else {
        return Some(message);
    };

    let address = crate::memory::dma::map_persistent_mmio(device, message.address).ok()?;

    Some(MsiMessage { address, ..message })
}
