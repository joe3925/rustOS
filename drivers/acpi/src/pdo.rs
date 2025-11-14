use alloc::string::{String, ToString};
use alloc::sync::Arc;
use aml::{AmlContext, AmlName, AmlValue, value::Args};
use kernel_api::{
    DeviceObject, DriverStatus, PnpMinorFunction, QueryIdType, Request,
    alloc_api::ffi::pnp_complete_request,
};
use spin::RwLock;

use crate::aml::{McfgSeg, append_ecam_list, build_query_resources_blob, read_ids};

#[repr(C)]
pub struct AcpiPdoExt {
    pub acpi_path: aml::AmlName,
    pub ctx: Arc<spin::RwLock<aml::AmlContext>>,
    pub ecam: alloc::vec::Vec<McfgSeg>,
}
