use alloc::sync::Arc;

use crate::aml::{McfgSeg, PrtEntry};

#[repr(C)]
pub struct AcpiPdoExt {
    pub acpi_path: aml::aml::namespace::AmlName,
    pub ctx: Arc<spin::RwLock<crate::aml::AmlContext>>,
    pub ecam: alloc::vec::Vec<McfgSeg>,
    pub prt: alloc::vec::Vec<PrtEntry>,
}
