use acpi::AcpiTables;

use crate::drivers::ACPI::ACPIImpl;
use crate::machine::MachineInterruptInfo;
use crate::platform::MachinePlatform;

use super::platform::Aarch64Platform;

impl MachinePlatform for Aarch64Platform {
    fn discover_interrupt_info_from_acpi(_tables: &AcpiTables<ACPIImpl>) -> Option<MachineInterruptInfo> {
        todo!()
    }
}
