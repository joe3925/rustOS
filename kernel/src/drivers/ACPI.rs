use crate::memory::paging::{map_physical_pages, unmap_physical_pages};
use crate::util::boot_info;
use acpi;
use acpi::{AcpiHandler, AcpiTables, PhysicalMapping, PlatformInfo};
use alloc::alloc::Global;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::Mutex;
use spin::Once;

use kernel_types::arch::{PhysAddr, VirtAddr};
#[repr(C, align(64))]
pub struct PerCpu {
    pub is_in_interrupt: AtomicBool,
    pub reserved_interrupt_pad: [u8; 0x7],
    pub cpu_id: Once<u64>,
    pub reserved0: [u8; 0x48],
    pub tls_array_pointer: AtomicU64,
}

pub const PERCPU_IS_IN_INTERRUPT_OFF: usize = offset_of!(PerCpu, is_in_interrupt);
pub const PERCPU_TLS_ARRAY_POINTER_OFF: usize = offset_of!(PerCpu, tls_array_pointer);
static PERCPU_SLOTS: Mutex<Vec<Option<&'static PerCpu>>> = Mutex::new(Vec::new());

pub fn alloc_or_get_percpu_for(lapic_id: u32) -> &'static PerCpu {
    let idx = lapic_id as usize;

    let mut v = PERCPU_SLOTS.lock();

    if v.len() <= idx {
        v.resize_with(idx + 1, || None);
    }

    if let Some(p) = v[idx] {
        return p;
    }

    let p: &'static PerCpu = Box::leak(Box::new(PerCpu {
        is_in_interrupt: AtomicBool::new(false),
        reserved_interrupt_pad: [0; 0x7],
        cpu_id: Once::new(),
        reserved0: [0; 0x48],
        tls_array_pointer: AtomicU64::new(0),
    }));
    
    p.cpu_id.call_once(|| lapic_id as u64);

    v[idx] = Some(p);
    p
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
