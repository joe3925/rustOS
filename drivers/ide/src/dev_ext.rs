use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering};
use kernel_api::irq::IrqHandle;
use kernel_api::kernel_types::no_std_async::Mutex as AsyncMutex;
use kernel_api::x86_64::instructions::port::Port;
use spin::Mutex as SpinMutex;

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
        unsafe {
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
}

#[repr(C)]
pub struct DevExt {
    pub present: AtomicBool,
    pub enumerated: AtomicBool,
    pub ports: SpinMutex<Ports>,
    pub ctrl_lock: AsyncMutex<()>,
    pub irq_handle: SpinMutex<Option<IrqHandle>>,
    pub cmd_base: AtomicU16,
    pub ctrl_base: AtomicU16,

    pub irq_vector: AtomicU8,
}

impl DevExt {
    pub fn new(io_base: u16, ctrl_base: u16) -> Self {
        Self {
            present: AtomicBool::new(false),
            enumerated: AtomicBool::new(false),
            ports: SpinMutex::new(Ports::new(io_base, ctrl_base)),
            ctrl_lock: AsyncMutex::new(()),
            irq_handle: SpinMutex::new(None),
            cmd_base: AtomicU16::new(io_base),
            ctrl_base: AtomicU16::new(ctrl_base),
            irq_vector: AtomicU8::new(0x20 + 0x0E),
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
}
