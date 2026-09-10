use crate::memory::paging::mmio::{map_physical_pages, unmap_physical_pages};
use crate::util::boot_info;
use acpi;
use acpi::{AcpiTables, Handle, Handler, PciAddress, PhysicalMapping};
use alloc::sync::Arc;
use core::ptr::NonNull;

use kernel_types::arch::{PhysAddr, VirtAddr};

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

impl Handler for ACPIImpl {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> { unsafe {
        let virt_addr = map_physical_pages(
            PhysAddr::new(physical_address as u64).into(),
            size as u64,
            kernel_types::memory::PhysicalMappingCache::Cached,
        )
        .expect("Failed to map physical region for ACPI");
        PhysicalMapping { physical_start: physical_address, virtual_start: NonNull::new(virt_addr.as_mut_ptr()).unwrap(), region_length: size, mapped_length: size, handler: self.clone() }
    }}

    fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>) {
        let _ = unsafe {
            unmap_physical_pages(
                VirtAddr::new(region.virtual_start.as_ptr() as u64).into(),
                region.mapped_length as u64,
            )
        };
    }

    fn read_u8(&self, address: usize) -> u8 { unsafe { (address as *const u8).read_volatile() } }
    fn read_u16(&self, address: usize) -> u16 { unsafe { (address as *const u16).read_volatile() } }
    fn read_u32(&self, address: usize) -> u32 { unsafe { (address as *const u32).read_volatile() } }
    fn read_u64(&self, address: usize) -> u64 { unsafe { (address as *const u64).read_volatile() } }
    fn write_u8(&self, address: usize, value: u8) { unsafe { (address as *mut u8).write_volatile(value) } }
    fn write_u16(&self, address: usize, value: u16) { unsafe { (address as *mut u16).write_volatile(value) } }
    fn write_u32(&self, address: usize, value: u32) { unsafe { (address as *mut u32).write_volatile(value) } }
    fn write_u64(&self, address: usize, value: u64) { unsafe { (address as *mut u64).write_volatile(value) } }
    fn read_io_u8(&self, port: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        unsafe { x86_64::instructions::port::Port::new(port).read() }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = port; 0 }
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        #[cfg(target_arch = "x86_64")]
        unsafe { x86_64::instructions::port::Port::new(port).read() }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = port; 0 }
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        #[cfg(target_arch = "x86_64")]
        unsafe { x86_64::instructions::port::Port::new(port).read() }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = port; 0 }
    }
    fn write_io_u8(&self, port: u16, value: u8) {
        #[cfg(target_arch = "x86_64")]
        unsafe { x86_64::instructions::port::Port::new(port).write(value) }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = (port, value); }
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        #[cfg(target_arch = "x86_64")]
        unsafe { x86_64::instructions::port::Port::new(port).write(value) }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = (port, value); }
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        #[cfg(target_arch = "x86_64")]
        unsafe { x86_64::instructions::port::Port::new(port).write(value) }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = (port, value); }
    }
    fn read_pci_u8(&self, _: PciAddress, _: u16) -> u8 { u8::MAX }
    fn read_pci_u16(&self, _: PciAddress, _: u16) -> u16 { u16::MAX }
    fn read_pci_u32(&self, _: PciAddress, _: u16) -> u32 { u32::MAX }
    fn write_pci_u8(&self, _: PciAddress, _: u16, _: u8) {}
    fn write_pci_u16(&self, _: PciAddress, _: u16, _: u16) {}
    fn write_pci_u32(&self, _: PciAddress, _: u16, _: u32) {}
    fn nanos_since_boot(&self) -> u64 { 0 }
    fn stall(&self, microseconds: u64) { for _ in 0..microseconds.saturating_mul(100) { core::hint::spin_loop(); } }
    fn sleep(&self, milliseconds: u64) { self.stall(milliseconds.saturating_mul(1000)); }
    fn create_mutex(&self) -> Handle { Handle(0) }
    fn acquire(&self, _: Handle, _: u16) -> Result<(), acpi::aml::AmlError> { Ok(()) }
    fn release(&self, _: Handle) {}
}
