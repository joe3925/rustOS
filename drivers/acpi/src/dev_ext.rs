use core::mem::MaybeUninit;

use aml::AmlContext;
use spin::RwLock;

#[repr(C)]
#[derive(Default)]
pub struct DevExt {
    pub ctx: Option<RwLock<AmlContext>>,
    pub i8042_hint: bool,
}
