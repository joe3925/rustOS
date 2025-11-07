use core::mem::MaybeUninit;

use alloc::sync::Arc;
use aml::AmlContext;
use spin::RwLock;

#[repr(C)]
#[derive(Default)]
pub struct DevExt {
    pub ctx: Option<Arc<RwLock<AmlContext>>>,
    pub i8042_hint: bool,
}
