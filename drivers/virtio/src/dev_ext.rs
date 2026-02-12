use alloc::sync::Weak;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use kernel_api::device::DeviceObject;
use kernel_api::irq::IrqHandle;
use kernel_api::kernel_types::io::DiskInfo;
use kernel_api::util::{get_current_cpu_id, get_current_lapic_id};
use kernel_api::x86_64::VirtAddr;
use spin::mutex::SpinMutex;
use spin::{Mutex, Once};

use crate::blk::BlkIoArena;
use crate::virtqueue::Virtqueue;

/// Strategy for selecting which queue to use for I/O requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueSelectionStrategy {
    /// Select queue based on current CPU ID (cpu_id % queue_count).
    /// Best for cache locality when each CPU handles its own I/O.
    CpuAffinity,
    /// Round-robin across queues using atomic counter.
    /// Best for load balancing when I/O is submitted from few CPUs.
    RoundRobin,
}

/// Per-queue state: queue, arena, and IRQ handle.
pub struct QueueState {
    /// The virtqueue for this request queue.
    pub queue: SpinMutex<Virtqueue>,
    /// Pre-allocated arena for this queue's BlkIoRequest slots.
    pub arena: BlkIoArena,
    /// Maximum safe data payload per request on this queue (512-byte aligned).
    pub max_request_bytes: u32,
    /// Maximum number of data descriptors we will use for a single request.
    pub max_data_segments: u16,
    /// IRQ handle for this queue (MSI-X or shared legacy).
    /// UnsafeCell to allow temporarily disabling for polling benchmarks.
    pub irq_handle: UnsafeCell<Option<IrqHandle>>,
    /// MSI-X vector number if MSI-X is being used for this queue.
    pub msix_vector: Option<u8>,
    /// MSI-X table entry index for this queue.
    pub msix_table_index: Option<u16>,
    /// Number of tasks currently waiting on this queue's interrupt.
    pub waiting_tasks: AtomicU32,
}

unsafe impl Send for QueueState {}
unsafe impl Sync for QueueState {}

impl QueueState {
    /// Get a reference to the Virtqueue for atomic-only operations (lock-free).
    /// SAFETY: Caller must only call methods that use atomics and don't mutate
    /// the free list (free_head, num_free).
    #[inline]
    fn vq_ref(&self) -> &Virtqueue {
        // SAFETY: We're only accessing atomic fields through immutable references.
        // The Mutex ensures exclusive access for mutable operations (push_chain, free_chain).
        // spin::Mutex stores data inline, so we can get a pointer to the inner data.
        unsafe { &*self.queue.as_mut_ptr() }
    }

    /// Get the current drain epoch (lock-free).
    #[inline]
    pub fn drain_epoch(&self) -> u64 {
        self.vq_ref().drain_epoch()
    }

    /// Check if head is completed and take the completion (lock-free).
    #[inline]
    pub fn take_completion(&self, head: u16) -> Option<u32> {
        self.vq_ref().take_completion(head)
    }

    /// Try to acquire the single-drainer gate (lock-free).
    #[inline]
    pub fn try_acquire_drainer(&self) -> bool {
        self.vq_ref().try_acquire_drainer()
    }

    /// Release the single-drainer gate (lock-free).
    #[inline]
    pub fn release_drainer(&self) {
        self.vq_ref().release_drainer()
    }

    /// Enqueue a descriptor chain head for deferred freeing (lock-free).
    #[inline]
    pub fn defer_free_chain(&self, head: u16) {
        self.vq_ref().defer_free_chain(head)
    }

    /// Drain used ring to completions using CAS (lock-free).
    #[inline]
    pub fn drain_used_to_completions_lockfree(&self) -> usize {
        self.vq_ref().drain_used_to_completions_lockfree()
    }

    /// Check if there are any pending completions in the used ring (lock-free).
    #[inline]
    pub fn has_pending_used(&self) -> bool {
        self.vq_ref().has_pending_used()
    }
}

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
    /// All request queues (index 0 is always present).
    pub queues: Vec<QueueState>,
    /// Number of queues actually in use.
    pub queue_count: usize,
    /// Queue selection strategy for I/O requests.
    pub queue_strategy: QueueSelectionStrategy,
    /// Round-robin counter (only used if strategy is RoundRobin).
    pub rr_counter: AtomicUsize,
    pub capacity: u64,
    pub mapped_bars: Mutex<Vec<(u32, VirtAddr, u64)>>,
    /// Base virtual address of the MSI-X Pending Bit Array region.
    pub msix_pba: Option<VirtAddr>,
    /// Gate that becomes ready when interrupt setup is complete and tested.
    pub irq_ready: InitGate,
}

impl DevExtInner {
    /// Select a queue for I/O based on the configured strategy.
    /// Returns the queue index to use.
    #[inline]
    pub fn select_queue(&self) -> usize {
        match self.queue_strategy {
            QueueSelectionStrategy::CpuAffinity => get_current_lapic_id() % self.queue_count,
            QueueSelectionStrategy::RoundRobin => {
                self.rr_counter.fetch_add(1, Ordering::Relaxed) % self.queue_count
            }
        }
    }

    /// Get a reference to a specific queue state.
    #[inline]
    pub fn get_queue(&self, idx: usize) -> &QueueState {
        &self.queues[idx]
    }
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
