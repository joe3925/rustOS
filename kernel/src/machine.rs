use crate::drivers::ACPI::{ACPIImpl, AcpiFirmware};
use crate::memory::dma::PlatformIommuInfo;
use crate::util::boot_info;
use acpi::AcpiTables;
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
        let interrupt_info = firmware.acpi_tables().and_then(|tables| {
            crate::arch::machine::discover_interrupt_info_from_acpi(tables.as_ref())
        });

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
    pub local_interrupt_controller_address: u64,
    pub interrupt_controllers: Vec<MachineInterruptControllerInfo>,
    pub processors: Vec<MachineProcessorInfo>,
    pub has_compatibility_interrupt_controllers: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct MachineInterruptControllerInfo {
    pub id: u8,
    pub address: u64,
    pub global_system_interrupt_base: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MachineProcessorInfo {
    pub platform_cpu_id: u32,
}
