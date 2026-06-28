use crate::memory::paging::{map_physical_pages, unmap_physical_pages};
use crate::util::boot_info;
use acpi;
use acpi::{AcpiHandler, AcpiTables, PhysicalMapping, PlatformInfo};
use alloc::alloc::Global;
use alloc::sync::Arc;
use core::ptr::NonNull;

use kernel_types::arch::{PhysAddr, VirtAddr};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Xsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32, // todo: prob remove this

    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}
unsafe impl Send for AcpiFirmware {}
unsafe impl Sync for AcpiFirmware {}
pub struct AcpiFirmware {
    tables: Arc<AcpiTables<ACPIImpl>>,
}
impl AcpiFirmware {
    pub fn from_boot_info() -> Option<Self> {
        let handler = ACPIImpl::new();
        let rsdp = boot_info().rsdp_addr.into_option()?;
        let tables =
            unsafe { AcpiTables::from_rsdp(handler, rsdp as usize).expect("failed to parse ACPI") };
        let arc_tab = Arc::new(tables);
        Some(AcpiFirmware { tables: arc_tab })
    }

    pub fn get_plat_info(&self) -> Option<PlatformInfo<'_, Global>> {
        self.tables.platform_info().ok()
    }
    pub fn get_tables(&self) -> Arc<AcpiTables<ACPIImpl>> {
        self.tables.clone()
    }

    pub fn into_tables(self) -> Arc<AcpiTables<ACPIImpl>> {
        self.tables
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
        let virt_addr = map_physical_pages(
            PhysAddr::new(physical_address as u64).into(),
            size as u64,
            kernel_types::memory::PhysicalMappingCache::Uncached,
        )
        .expect("Failed to map physical region for ACPI");
        PhysicalMapping::new(
            physical_address,
            NonNull::new(virt_addr.as_mut_ptr()).unwrap(),
            size,
            size,
            self.clone(),
        )
    }

    fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>) {
        let _ = unsafe {
            unmap_physical_pages(
                VirtAddr::new(region.virtual_start().as_ptr() as u64).into(),
                region.region_length() as u64,
            )
        };
    }
}
