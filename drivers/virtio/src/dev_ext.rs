use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicUsize, Ordering};

use kernel_api::device::DeviceObject;
use kernel_api::irq::IrqHandle;
use kernel_api::kernel_types::dma::{FromDevice, ToDevice};
use kernel_api::kernel_types::io::DiskInfo;
use kernel_api::memory::VirtAddr;
use kernel_api::util::get_current_platform_cpu_id;
use spin::{Mutex, Once, RwLock, RwLockReadGuard};

use crate::blk::BlkIoSlots;
use crate::completion::CompletionTable;
use crate::outstanding::{PendingOpPool, SubmittedCompletionPool};
use crate::virtqueue::Virtqueue;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueSelectionStrategy {
    CpuAffinity,
    RoundRobin,
}

pub struct QueueState {
    pub queue: RwLock<Virtqueue>,
    pub arena: BlkIoSlots,
    pub irq_handle: UnsafeCell<Option<IrqHandle>>,
    pub msix_vector: Option<u8>,
    pub msix_table_index: Option<u16>,
    pub submitting_tasks: AtomicU32,
    pub use_indirect: bool,
    pub completion_slots: CompletionTable,
    pub read_ops: PendingOpPool<FromDevice>,
    pub write_ops: PendingOpPool<ToDevice>,
    pub submitted_completions: SubmittedCompletionPool,
    pub used_idx: *const AtomicU16,
    pub last_drained_used_idx: AtomicU16,
}

unsafe impl Send for QueueState {}
unsafe impl Sync for QueueState {}

impl QueueState {
    #[inline]
    pub fn vq_ref(&self) -> RwLockReadGuard<'_, Virtqueue> {
        self.queue.read()
    }

    #[inline]
    pub fn has_pending_used(&self) -> bool {
        let used_idx = unsafe { (*self.used_idx).load(Ordering::Acquire) };
        used_idx != self.last_drained_used_idx.load(Ordering::Acquire)
    }
}

#[repr(C)]
pub struct DevExt {
    pub inner: Once<Arc<DevExtInner>>,
    pub enumerated: AtomicBool,
}

pub struct DevExtInner {
    pub common_cfg: VirtAddr,
    pub notify_base: VirtAddr,
    pub notify_off_multiplier: u32,
    pub isr_cfg: VirtAddr,
    pub device_cfg: VirtAddr,
    pub queues: Vec<QueueState>,
    pub queue_count: usize,
    pub queue_strategy: QueueSelectionStrategy,
    pub rr_counter: AtomicUsize,
    pub capacity: u64,
    pub mapped_bars: Mutex<Vec<(u32, VirtAddr, u64)>>,
    pub msix_pba: Option<VirtAddr>,
    pub indirect_desc_enabled: bool,
    pub flush_supported: bool,
}

impl DevExtInner {
    #[inline]
    pub fn select_queue(&self) -> usize {
        match self.queue_strategy {
            QueueSelectionStrategy::CpuAffinity => get_current_platform_cpu_id() % self.queue_count,
            QueueSelectionStrategy::RoundRobin => {
                self.rr_counter.fetch_add(1, Ordering::Relaxed) % self.queue_count
            }
        }
    }

    #[inline]
    pub fn get_queue(&self, idx: usize) -> &QueueState {
        &self.queues[idx]
    }
}

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
