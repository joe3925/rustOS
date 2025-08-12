use aml::AmlContext;
use spin::RwLock;

#[repr(C)]
pub struct DevExt {
    pub ctx: RwLock<AmlContext>,
}
