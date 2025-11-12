use core::{mem::MaybeUninit, sync::atomic::AtomicBool};

use alloc::sync::Arc;
use aml::AmlContext;
use spin::{Once, RwLock};

#[repr(C)]
#[derive(Default)]
pub struct DevExt {
    pub ctx: Once<Arc<RwLock<AmlContext>>>,
    pub i8042_hint: AtomicBool,
}
