use crate::memory::paging::mmio::map_mmio_region;
use crate::memory::paging::virt_tracker::unmap_range;
use crate::util::boot_info;
use acpi;
use acpi::platform::interrupt::Apic;
use acpi::{AcpiHandler, AcpiTables, InterruptModel, PhysicalMapping, PlatformInfo};
use alloc::alloc::Global;
use core::ptr::NonNull;
use lazy_static::lazy_static;
use x86_64::{PhysAddr, VirtAddr};

lazy_static! {
    pub static ref ACPI_TABLES: ACPI = ACPI::new();
}
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Xsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32, // Deprecated since version 2.0

    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}
unsafe impl Send for ACPI {}
unsafe impl Sync for ACPI {}
pub struct ACPI {
    tables: AcpiTables<ACPIImpl>,
}
impl ACPI {
    pub fn new() -> Self {
        let handler = ACPIImpl::new();
        if boot_info().rsdp_addr.into_option().is_none() {
            panic!("RSDP was not supplied by bootloader");
        }
        let tables = unsafe {
            AcpiTables::from_rsdp(
                handler,
                boot_info().rsdp_addr.into_option().unwrap() as usize,
            )
            .expect("failed to parse ACPI")
        };

        ACPI { tables }
    }
    pub fn get_interrupt_model(&self) -> Option<Apic<Global>> {
        let platform_info = self.tables.platform_info().ok()?;
        match &platform_info.interrupt_model {
            InterruptModel::Apic(apic) => Some(apic.clone()),
            _ => None,
        }
    }
    pub fn get_plat_info(&self) -> Option<PlatformInfo<Global>> {
        self.tables.platform_info().ok()
    }
}
unsafe impl Send for ACPIImpl {}
unsafe impl Sync for ACPIImpl {}
#[derive(Clone)]
pub struct ACPIImpl {}
impl ACPIImpl {
    pub fn new() -> Self {
        ACPIImpl {}
    }
}

impl AcpiHandler for ACPIImpl {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        let virt_addr =
            map_mmio_region(PhysAddr::new(physical_address as u64), size as u64)
                .expect("failed to map io space for ACPI");
        PhysicalMapping::new(
            physical_address,
            NonNull::new(virt_addr.as_mut_ptr()).unwrap(),
            size,
            size,
            self.clone(),
        )
    }

    fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>) {
        unmap_range(
            VirtAddr::new(region.virtual_start().as_ptr() as u64),
            region.region_length() as u64,
        )
    }
}
