use crate::drivers::ACPI::{ACPIImpl, AcpiFirmware};
use crate::memory::dma::PlatformIommuInfo;
use crate::util::boot_info;
use acpi::{AcpiTables, InterruptModel};
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_types::fdt::FdtHeader;
use spin::Once;

static MACHINE_INFO: Once<MachineInfo> = Once::new();

pub fn machine_info() -> &'static MachineInfo {
    MACHINE_INFO.call_once(MachineInfo::discover)
}

pub struct MachineInfo {
    firmware: FirmwareResources,
    interrupt_info: Option<MachineInterruptInfo>,
}

impl MachineInfo {
    fn discover() -> Self {
        let firmware = FirmwareResources::discover();
        let interrupt_info = firmware
            .acpi_tables()
            .and_then(|tables| MachineInterruptInfo::from_acpi(tables.as_ref()));

        Self {
            firmware,
            interrupt_info,
        }
    }

    pub fn firmware(&self) -> &FirmwareResources {
        &self.firmware
    }

    pub fn interrupt_info(&self) -> Option<&MachineInterruptInfo> {
        self.interrupt_info.as_ref()
    }

    pub fn discover_required_device_mmu(&self) -> PlatformIommuInfo {
        let tables = self
            .firmware()
            .acpi_tables()
            .expect("mandatory IOMMU policy: ACPI tables are unavailable");
        crate::memory::dma::discover_platform_iommu_from_acpi(tables.as_ref())
    }
}

pub struct FirmwareResources {
    acpi: Option<Arc<AcpiTables<ACPIImpl>>>,
    fdt: Option<*const FdtHeader>,
}

unsafe impl Send for FirmwareResources {}
unsafe impl Sync for FirmwareResources {}

impl FirmwareResources {
    fn discover() -> Self {
        let acpi = AcpiFirmware::from_boot_info().map(|firmware| firmware.into_tables());
        let fdt = boot_info()
            .fdt_header
            .into_option()
            .map(|ptr| ptr.cast::<FdtHeader>() as *const FdtHeader);

        Self { acpi, fdt }
    }

    pub fn acpi_tables(&self) -> Option<Arc<AcpiTables<ACPIImpl>>> {
        self.acpi.clone()
    }

    pub fn fdt_header(&self) -> Option<*const FdtHeader> {
        self.fdt
    }
}

#[derive(Debug, Clone)]
pub struct MachineInterruptInfo {
    pub local_apic_address: u64,
    pub io_apics: Vec<MachineIoApicInfo>,
    pub application_processors: Vec<MachineProcessorInfo>,
    pub also_has_legacy_pics: bool,
}

impl MachineInterruptInfo {
    fn from_acpi(tables: &AcpiTables<ACPIImpl>) -> Option<Self> {
        let platform_info = tables.platform_info().ok()?;
        let apic = match platform_info.interrupt_model {
            InterruptModel::Apic(apic) => apic,
            _ => return None,
        };

        let application_processors = platform_info
            .processor_info
            .map(|info| {
                info.application_processors
                    .iter()
                    .map(|processor| MachineProcessorInfo {
                        local_apic_id: processor.local_apic_id as u32,
                    })
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        let io_apics = apic
            .io_apics
            .iter()
            .map(|io_apic| MachineIoApicInfo {
                id: io_apic.id,
                address: io_apic.address as u64,
                global_system_interrupt_base: io_apic.global_system_interrupt_base,
            })
            .collect();

        Some(Self {
            local_apic_address: apic.local_apic_address,
            io_apics,
            application_processors,
            also_has_legacy_pics: apic.also_has_legacy_pics,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MachineIoApicInfo {
    pub id: u8,
    pub address: u64,
    pub global_system_interrupt_base: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MachineProcessorInfo {
    pub local_apic_id: u32,
}
