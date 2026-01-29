use kernel_api::irq::IrqHandle;
use kernel_api::x86_64::VirtAddr;
use spin::{Mutex, Once};

use crate::virtqueue::Virtqueue;

/// Device extension for the virtio-blk FDO.
/// Initialized with empty values in device_add, populated in StartDevice.
#[repr(C)]
pub struct DevExt {
    /// Populated during StartDevice after mapping BARs and parsing caps.
    pub inner: Once<DevExtInner>,
}

pub struct DevExtInner {
    pub common_cfg: VirtAddr,
    pub notify_base: VirtAddr,
    pub notify_off_multiplier: u32,
    pub isr_cfg: VirtAddr,
    pub device_cfg: VirtAddr,
    pub requestq: Mutex<Virtqueue>,
    pub capacity: u64,
    pub irq_handle: Option<IrqHandle>,
    pub mapped_bars: Mutex<alloc::vec::Vec<(VirtAddr, u64)>>,
}

unsafe impl Send for DevExt {}
unsafe impl Sync for DevExt {}
unsafe impl Send for DevExtInner {}
unsafe impl Sync for DevExtInner {}

impl DevExt {
    pub fn new() -> Self {
        Self { inner: Once::new() }
    }
}
