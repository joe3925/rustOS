use alloc::sync::Arc;

use crate::aml::McfgSeg;

#[repr(C)]
pub struct AcpiPdoExt {
    pub acpi_path: aml::AmlName,
    pub ctx: Arc<spin::RwLock<aml::AmlContext>>,
    pub ecam: alloc::vec::Vec<McfgSeg>,
}
