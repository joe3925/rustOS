use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use kernel_api::device::DeviceObject;
use kernel_api::irq::IrqHandle;
use kernel_api::kernel_types::io::DiskInfo;
use kernel_api::x86_64::VirtAddr;
use spin::{Mutex, Once};

use crate::blk::BlkIoRequestArena;
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
    pub mapped_bars: Mutex<Vec<(u32, VirtAddr, u64)>>,
    /// MSI-X vector number if MSI-X is being used, None for legacy/GSI IRQ.
    pub msix_vector: Option<u8>,
    /// MSI-X table entry programmed for the request queue (if MSI-X is active).
    pub msix_table_index: Option<u16>,
    /// Base virtual address of the MSI-X Pending Bit Array region.
    pub msix_pba: Option<VirtAddr>,
    /// Gate that becomes ready when interrupt setup is complete and tested.
    pub irq_ready: InitGate,
    /// Arena allocator for BlkIoRequest DMA buffers.
    pub request_arena: BlkIoRequestArena,
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

/// A synchronization primitive that allows tasks to wait until initialization is complete.
/// Once `set_ready()` is called, all current and future waiters immediately return `Ready`.
pub struct InitGate {
    ready: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
}

impl InitGate {
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Returns true if the gate is ready (initialization complete).
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Mark the gate as ready and wake all waiting tasks.
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
        let mut waiters = self.waiters.lock();
        for waker in waiters.drain(..) {
            waker.wake();
        }
    }

    /// Returns a future that resolves when the gate becomes ready.
    pub fn wait(&self) -> InitGateWait<'_> {
        InitGateWait { gate: self }
    }
}

/// Future returned by `InitGate::wait()`.
pub struct InitGateWait<'a> {
    gate: &'a InitGate,
}

impl<'a> Future for InitGateWait<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Fast path: already ready
        if self.gate.ready.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        // Register waker before re-checking to avoid race
        {
            let mut waiters = self.gate.waiters.lock();
            // Double-check after acquiring lock
            if self.gate.ready.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            waiters.push(cx.waker().clone());
        }

        Poll::Pending
    }
}
