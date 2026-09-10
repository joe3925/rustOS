use acpi::platform::ProcessorState;
use acpi::{AcpiTables, platform::InterruptModel};
use alloc::vec::Vec;

use crate::drivers::ACPI::ACPIImpl;
use crate::machine::{
    CpuTopologyError, FirmwareResources, MachineCpuTopology, MachineInterruptControllerInfo,
    MachineInterruptInfo, MachineProcessorInfo,
};
use crate::platform::MachinePlatform;

use super::platform::X86Platform;

impl MachinePlatform for X86Platform {
    fn discover_cpu_topology(
        firmware: &FirmwareResources,
    ) -> Result<MachineCpuTopology, CpuTopologyError> {
        let tables = firmware.acpi_tables().ok_or(CpuTopologyError {
            reason: "ACPI tables are unavailable",
        })?;
        let (interrupt_model, processor_info) = InterruptModel::new(&tables).map_err(|_| CpuTopologyError {
            reason: "ACPI processor information is invalid",
        })?;
        let _ = interrupt_model;
        let processor_info = processor_info.ok_or(CpuTopologyError {
            reason: "ACPI processor information is unavailable",
        })?;
        let mut processors = Vec::new();
        let boot = processor_info.boot_processor;
        processors.push(MachineProcessorInfo {
            cpu_id: 0,
            platform_cpu_id: boot.local_apic_id,
            hardware_id: boot.local_apic_id as u64,
            is_boot_processor: true,
        });
        for processor in processor_info.application_processors.iter() {
            if processor.state == ProcessorState::Disabled {
                continue;
            }
            processors.push(MachineProcessorInfo {
                cpu_id: processors.len(),
                platform_cpu_id: processor.local_apic_id,
                hardware_id: processor.local_apic_id as u64,
                is_boot_processor: false,
            });
        }
        Ok(MachineCpuTopology {
            processors,
            psci_conduit: None,
        })
    }

    fn discover_interrupt_info_from_acpi(
        tables: &AcpiTables<ACPIImpl>,
    ) -> Option<MachineInterruptInfo> {
        let (interrupt_model, _) = InterruptModel::new(tables).ok()?;
        let apic = match interrupt_model {
            InterruptModel::Apic(apic) => apic,
            _ => return None,
        };

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
        })
    }
}
