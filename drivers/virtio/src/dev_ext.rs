use alloc::sync::{Arc, Weak};
use core::sync::atomic::AtomicBool;

use kernel_api::device::DeviceObject;
use kernel_api::irq::IrqHandle;
use kernel_api::kernel_types::io::DiskInfo;
use kernel_api::x86_64::VirtAddr;
use spin::{Mutex, Once};

use crate::virtqueue::Virtqueue;

/// Device extension for the virtio-blk FDO.
/// Initialized with empty values in device_add, populated in StartDevice.
#[repr(C)]
pub struct DevExt {
    /// Populated during StartDevice after mapping BARs and parsing caps.
    pub inner: Once<DevExtInner>,
    /// Whether we have already enumerated children.
    pub enumerated: AtomicBool,
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
    /// MSI-X vector number if MSI-X is being used, None for legacy/GSI IRQ.
    pub msix_vector: Option<u8>,
}

/// Device extension for the child disk PDO.
#[repr(C)]
pub struct ChildExt {
    pub parent_device: Weak<DeviceObject>,
    pub disk_info: DiskInfo,
}

unsafe impl Send for DevExt {}
unsafe impl Sync for DevExt {}
unsafe impl Send for DevExtInner {}
unsafe impl Sync for DevExtInner {}
unsafe impl Send for ChildExt {}
unsafe impl Sync for ChildExt {}

impl DevExt {
    pub fn new() -> Self {
        Self {
            inner: Once::new(),
            enumerated: AtomicBool::new(false),
        }
    }
}
