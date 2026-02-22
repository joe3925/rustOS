use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_api::irq::IrqHandle;
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::x86_64::instructions::port::Port;

#[repr(C)]
pub struct Ports {
    pub data: Port<u16>,
    pub error: Port<u8>,
    pub sector_count: Port<u8>,
    pub lba_lo: Port<u8>,
    pub lba_mid: Port<u8>,
    pub lba_hi: Port<u8>,
    pub drive_head: Port<u8>,
    pub command: Port<u8>,
    pub control: Port<u8>,
    pub alternative_command: Port<u8>,
}

impl Ports {
    pub fn new(io_base: u16, ctrl_base: u16) -> Self {
        Self {
            data: Port::new(io_base),
            error: Port::new(io_base + 1),
            sector_count: Port::new(io_base + 2),
            lba_lo: Port::new(io_base + 3),
            lba_mid: Port::new(io_base + 4),
            lba_hi: Port::new(io_base + 5),
            drive_head: Port::new(io_base + 6),
            command: Port::new(io_base + 7),
            control: Port::new(ctrl_base),
            alternative_command: Port::new(ctrl_base),
        }
    }
}

pub struct ControllerState {
    pub ports: Ports,
}

#[repr(C)]
pub struct DevExt {
    pub present: AtomicBool,
    pub enumerated: AtomicBool,
    pub controller: AsyncMutex<ControllerState>,
    /// Set once during StartDevice, then read-only.
    pub irq_handle: UnsafeCell<Option<IrqHandle>>,
}

unsafe impl Send for DevExt {}
unsafe impl Sync for DevExt {}

impl DevExt {
    pub fn new(io_base: u16, ctrl_base: u16) -> Self {
        Self {
            present: AtomicBool::new(false),
            enumerated: AtomicBool::new(false),
            controller: AsyncMutex::new(ControllerState {
                ports: Ports::new(io_base, ctrl_base),
            }),
            irq_handle: UnsafeCell::new(None),
        }
    }

    #[inline]
    pub fn set_present(&self, v: bool) {
        self.present.store(v, Ordering::Release)
    }
    #[inline]
    pub fn is_present(&self) -> bool {
        self.present.load(Ordering::Acquire)
    }
    #[inline]
    pub fn set_enumerated(&self, v: bool) {
        self.enumerated.store(v, Ordering::Release)
    }
    #[inline]
    pub fn is_enumerated(&self) -> bool {
        self.enumerated.load(Ordering::Acquire)
    }

    /// Get the IRQ handle reference (safe after init).
    ///
    /// # Safety
    /// Must only be called after StartDevice has completed writing the handle.
    pub unsafe fn irq(&self) -> &Option<IrqHandle> {
        unsafe { &*self.irq_handle.get() }
    }
}
