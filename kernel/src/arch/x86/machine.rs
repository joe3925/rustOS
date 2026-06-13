use acpi::{AcpiTables, InterruptModel};
use alloc::vec::Vec;

use crate::drivers::ACPI::ACPIImpl;
use crate::machine::{MachineInterruptControllerInfo, MachineInterruptInfo, MachineProcessorInfo};

pub(crate) fn discover_interrupt_info_from_acpi(
    tables: &AcpiTables<ACPIImpl>,
) -> Option<MachineInterruptInfo> {
    let platform_info = tables.platform_info().ok()?;
    let apic = match platform_info.interrupt_model {
        InterruptModel::Apic(apic) => apic,
        _ => return None,
    };

    let processors = platform_info
        .processor_info
        .map(|info| {
            info.application_processors
                .iter()
                .map(|processor| MachineProcessorInfo {
                    platform_cpu_id: processor.local_apic_id as u32,
                })
                .collect()
        })
        .unwrap_or_else(Vec::new);

    let interrupt_controllers = apic
        .io_apics
        .iter()
        .map(|io_apic| MachineInterruptControllerInfo {
            id: io_apic.id,
            address: io_apic.address as u64,
            global_system_interrupt_base: io_apic.global_system_interrupt_base,
        })
        .collect();

    Some(MachineInterruptInfo {
        local_interrupt_controller_address: apic.local_apic_address,
        interrupt_controllers,
        processors,
        has_compatibility_interrupt_controllers: apic.also_has_legacy_pics,
    })
}
