use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped_contiguous, deallocate_kernel_range,
    unmap_range, virt_to_phys,
};
use kernel_api::x86_64::{PhysAddr, VirtAddr};

use crate::pci;

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[derive(Clone, Copy)]
pub struct DescState {
    /// true if this descriptor slot is free
    pub free: bool,
}

pub struct Virtqueue {
    pub idx: u16,
    pub size: u16,
    pub queue_notify_off: u16,

    pub desc_va: VirtAddr,
    pub avail_va: VirtAddr,
    pub used_va: VirtAddr,

    pub desc_phys: PhysAddr,
    pub avail_phys: PhysAddr,
    pub used_phys: PhysAddr,

    desc_size: u64,
    avail_size: u64,
    used_size: u64,

    pub free_head: u16,
    pub num_free: u16,

    /// Last used ring index we've processed (atomic for lock-free draining).
    last_used_idx: AtomicU16,

    /// Completion status array indexed by descriptor head.
    /// - 0: not completed
    /// - non-zero: completed, value is (len + 1) to distinguish from "not completed"
    completions: Box<[AtomicU32]>,

    /// Single-drainer gate: true if a drain operation is in progress.
    /// Only one task should drain at a time to prevent thundering herd.
    draining: AtomicBool,

    /// Epoch counter incremented each time drain_used_to_completions() drains entries.
    /// Waiters can use this to detect when new completions have been processed.
    drain_epoch: AtomicU64,

    /// Lock-free stack of descriptor chain heads pending free.
    /// 0xFFFF = empty sentinel.
    deferred_free_head: AtomicU16,

    /// Per-descriptor "next" pointers for the deferred free stack.
    /// Only written by wait_for_completion (producers), read by submitter (consumer).
    deferred_free_next: Box<[AtomicU16]>,
}

fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

impl Virtqueue {
    /// Allocate and initialise a split virtqueue.
    /// Writes the physical addresses into the device via common_cfg.
    pub fn new(queue_idx: u16, common_cfg: VirtAddr) -> Option<Self> {
        unsafe { pci::common_write_u16(common_cfg, pci::COMMON_QUEUE_SELECT, queue_idx) };

        let max_size = unsafe { pci::common_read_u16(common_cfg, pci::COMMON_QUEUE_SIZE) };
        if max_size == 0 {
            return None;
        }
        // Use the full queue size advertised by the device.
        let size = max_size;
        unsafe { pci::common_write_u16(common_cfg, pci::COMMON_QUEUE_SIZE, size) };

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

        let desc_bytes = align_up(size as u64 * 16, 4096);
        let desc_va = allocate_auto_kernel_range_mapped_contiguous(desc_bytes, flags).ok()?;
        let desc_phys = virt_to_phys(desc_va)?;

        let avail_bytes = align_up(6 + size as u64 * 2, 4096);
        let avail_va = allocate_auto_kernel_range_mapped_contiguous(avail_bytes, flags).ok()?;
        let avail_phys = virt_to_phys(avail_va)?;

        let used_bytes = align_up(6 + size as u64 * 8, 4096);
        let used_va = allocate_auto_kernel_range_mapped_contiguous(used_bytes, flags).ok()?;
        let used_phys = virt_to_phys(used_va)?;

        unsafe {
            core::ptr::write_bytes(desc_va.as_u64() as *mut u8, 0, desc_bytes as usize);
            core::ptr::write_bytes(avail_va.as_u64() as *mut u8, 0, avail_bytes as usize);
            core::ptr::write_bytes(used_va.as_u64() as *mut u8, 0, used_bytes as usize);
        }

        for i in 0..size {
            let desc_ptr = (desc_va.as_u64() + i as u64 * 16) as *mut VirtqDesc;
            unsafe {
                (*desc_ptr).next = if i + 1 < size { i + 1 } else { 0 };
                (*desc_ptr).flags = 0;
            }
        }

        let completions = core::iter::repeat_with(|| AtomicU32::new(0))
            .take(size as usize)
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let deferred_free_next = core::iter::repeat_with(|| AtomicU16::new(0xFFFF))
            .take(size as usize)
            .collect::<Vec<_>>()
            .into_boxed_slice();

        // Cache the per-queue notify offset while this queue is selected.
        let queue_notify_off =
            unsafe { pci::common_read_u16(common_cfg, pci::COMMON_QUEUE_NOTIFY_OFF) };

        unsafe {
            pci::common_write_u64(common_cfg, pci::COMMON_QUEUE_DESC, desc_phys.as_u64());
            pci::common_write_u64(common_cfg, pci::COMMON_QUEUE_DRIVER, avail_phys.as_u64());
            pci::common_write_u64(common_cfg, pci::COMMON_QUEUE_DEVICE, used_phys.as_u64());
        }

        Some(Self {
            idx: queue_idx,
            size,
            desc_va,
            avail_va,
            used_va,
            desc_phys,
            avail_phys,
            used_phys,
            desc_size: desc_bytes,
            avail_size: avail_bytes,
            used_size: used_bytes,
            queue_notify_off,
            free_head: 0,
            num_free: size,
            last_used_idx: AtomicU16::new(0),
            completions,
            draining: AtomicBool::new(false),
            drain_epoch: AtomicU64::new(0),
            deferred_free_head: AtomicU16::new(0xFFFF),
            deferred_free_next,
        })
    }

    /// Enable the queue after all configuration (including MSI-X vector) is set.
    pub fn enable(&self, common_cfg: VirtAddr) {
        unsafe {
            // Re-select the queue before enabling to ensure the register window is pointed at us.
            pci::common_write_u16(common_cfg, pci::COMMON_QUEUE_SELECT, self.idx);
            pci::common_write_u16(common_cfg, pci::COMMON_QUEUE_ENABLE, 1);
        }
    }

    /// Allocate a single descriptor from the free list. Returns descriptor index.
    fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let idx = self.free_head;
        let desc = self.desc_ptr(idx);
        self.free_head = unsafe { (*desc).next };
        self.num_free -= 1;
        Some(idx)
    }

    /// Free a descriptor back to the free list.
    fn free_desc(&mut self, idx: u16) {
        let desc = self.desc_ptr(idx);
        unsafe {
            (*desc).flags = 0;
            (*desc).next = self.free_head;
        }
        self.free_head = idx;
        self.num_free += 1;
    }

    fn desc_ptr(&self, idx: u16) -> *mut VirtqDesc {
        (self.desc_va.as_u64() + idx as u64 * 16) as *mut VirtqDesc
    }

    /// Push a chain of buffers into the virtqueue.
    /// `bufs` is a slice of (physical_addr, length, flags) where flags uses VRING_DESC_F_WRITE
    /// for device-writable buffers.
    ///
    /// Returns the head descriptor index of the chain.
    pub fn push_chain(&mut self, bufs: &[(PhysAddr, u32, u16)]) -> Option<u16> {
        // Drain any deferred frees first (we hold the lock)
        self.drain_deferred_frees();

        if bufs.is_empty() || bufs.len() as u16 > self.num_free {
            return None;
        }

        let head = self.alloc_desc()?;
        let mut prev = head;

        for (i, &(paddr, len, flags)) in bufs.iter().enumerate() {
            let idx = if i == 0 { head } else { self.alloc_desc()? };

            let desc = self.desc_ptr(idx);
            unsafe {
                (*desc).addr = paddr.as_u64();
                (*desc).len = len;
                (*desc).flags = flags;
            }

            if i > 0 {
                let prev_desc = self.desc_ptr(prev);
                unsafe {
                    (*prev_desc).flags |= VRING_DESC_F_NEXT;
                    (*prev_desc).next = idx;
                }
            }
            prev = idx;
        }

        let avail_base = self.avail_va.as_u64() as *mut u16;
        let avail_idx = unsafe { core::ptr::read_volatile(avail_base.add(1)) };
        let ring_entry = avail_base.wrapping_add(2 + (avail_idx % self.size) as usize);
        unsafe {
            core::ptr::write_volatile(ring_entry, head);
            // Memory barrier before updating idx
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(avail_base.add(1), avail_idx.wrapping_add(1));
        }

        Some(head)
    }

    /// Write to the device's notify register to kick the queue.
    pub fn notify(&self, notify_base: VirtAddr, notify_off_multiplier: u32) {
        let offset = self.queue_notify_off as u64 * notify_off_multiplier as u64;
        let addr = (notify_base.as_u64() + offset) as *mut u16;
        // Ensure avail ring updates are visible before the MMIO notify.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::write_volatile(addr, self.idx) };
    }

    /// Check if the queue needs a notification after adding descriptors.
    /// Returns true if the queue was empty before the current batch of submissions.
    /// This allows batching multiple submissions with a single notify.
    pub fn needs_notify(&self, avail_idx_before_batch: u16) -> bool {
        // Notify if the queue transitioned from empty to non-empty.
        // The queue was "empty" if avail_idx == last_used_idx before we started submitting.
        avail_idx_before_batch == self.last_used_idx.load(Ordering::Acquire)
    }

    /// Get the current available ring index. Use this before a batch of submissions
    /// to determine if a notify is needed afterward.
    pub fn avail_idx(&self) -> u16 {
        let avail_base = self.avail_va.as_u64() as *const u16;
        unsafe { core::ptr::read_volatile(avail_base.add(1)) }
    }

    /// Pop completed entries from the used ring (requires mutable access).
    /// Returns a list of (descriptor_head_index, bytes_written).
    /// Note: For lock-free draining, use drain_used_to_completions_lockfree() instead.
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        let used_base = self.used_va.as_u64() as *const u16;
        let used_idx = unsafe { core::ptr::read_volatile(used_base.add(1)) };

        let last = self.last_used_idx.load(Ordering::Acquire);
        if last == used_idx {
            return None;
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        let elem_offset = 4 + (last % self.size) as usize * 8;
        let elem_ptr = (self.used_va.as_u64() + elem_offset as u64) as *const VirtqUsedElem;
        let elem = unsafe { core::ptr::read_volatile(elem_ptr) };
        self.last_used_idx.store(last.wrapping_add(1), Ordering::Release);

        Some((elem.id as u16, elem.len))
    }

    /// Drain all pending used ring entries into the completions array.
    /// Returns the number of entries drained.
    pub fn drain_used_to_completions(&mut self) -> usize {
        let mut count = 0;
        while let Some((head, len)) = self.pop_used() {
            // Store len+1 so 0 means "not completed"
            self.completions[head as usize].store(len.wrapping_add(1), Ordering::Release);
            count += 1;
        }
        if count > 0 {
            // Increment epoch to signal waiters that new completions are available
            self.drain_epoch.fetch_add(1, Ordering::Release);
        }
        count
    }

    /// Drain used ring to completions using CAS (fully lock-free).
    /// Multiple callers can race; each entry is claimed by exactly one caller via CAS.
    /// Returns the number of entries successfully drained by this call.
    pub fn drain_used_to_completions_lockfree(&self) -> usize {
        let mut count = 0;

        loop {
            // Read device's used_idx (volatile read from used ring)
            let used_base = self.used_va.as_u64() as *const u16;
            let device_used_idx = unsafe { core::ptr::read_volatile(used_base.add(1)) };

            // Load our current last_used_idx atomically
            let our_last = self.last_used_idx.load(Ordering::Acquire);

            // If equal, nothing to drain
            if our_last == device_used_idx {
                break;
            }

            // Try to claim ONE entry by CAS'ing last_used_idx forward
            let next_idx = our_last.wrapping_add(1);
            match self.last_used_idx.compare_exchange_weak(
                our_last,
                next_idx,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // We successfully claimed the entry at position our_last
                    // Memory barrier to ensure used ring entry is read after claiming
                    core::sync::atomic::fence(Ordering::Acquire);

                    let elem_offset = 4 + (our_last % self.size) as usize * 8;
                    let elem_ptr =
                        (self.used_va.as_u64() + elem_offset as u64) as *const VirtqUsedElem;
                    let elem = unsafe { core::ptr::read_volatile(elem_ptr) };

                    // Store completion (len + 1, where 0 means "not completed")
                    let head = elem.id as u16;
                    self.completions[head as usize]
                        .store(elem.len.wrapping_add(1), Ordering::Release);

                    count += 1;
                    // Continue to try draining more entries
                }
                Err(_) => {
                    // Another thread claimed this entry, retry from the top
                    continue;
                }
            }
        }

        if count > 0 {
            self.drain_epoch.fetch_add(1, Ordering::Release);
        }

        count
    }

    /// Try to acquire the single-drainer gate.
    /// Returns true if this caller is now the drainer, false if another drainer is active.
    /// Use `release_drainer()` when done draining.
    #[inline]
    pub fn try_acquire_drainer(&self) -> bool {
        self.draining
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Release the single-drainer gate after draining is complete.
    #[inline]
    pub fn release_drainer(&self) {
        self.draining.store(false, Ordering::Release);
    }

    /// Check if a drain operation is currently in progress.
    #[inline]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Get the current drain epoch. Waiters can compare this value before and after
    /// sleeping to detect if new completions have been processed.
    #[inline]
    pub fn drain_epoch(&self) -> u64 {
        self.drain_epoch.load(Ordering::Acquire)
    }

    /// Check if head is completed and take the completion (atomic swap to 0).
    /// Returns Some(len) if completed, None if not.
    /// This is lock-free and can be called without holding the virtqueue mutex.
    pub fn take_completion(&self, head: u16) -> Option<u32> {
        let val = self.completions[head as usize].swap(0, Ordering::AcqRel);
        if val == 0 {
            None
        } else {
            Some(val - 1) // Recover original len
        }
    }

    /// Check if head is completed without taking the completion.
    /// This is lock-free and useful for polling without consuming the completion.
    #[inline]
    pub fn peek_completion(&self, head: u16) -> bool {
        self.completions[head as usize].load(Ordering::Acquire) != 0
    }

    /// Check if there are any pending completions in the used ring.
    /// This is useful for deciding whether to drain before waiting.
    /// Lock-free: only reads atomics and volatile memory.
    #[inline]
    pub fn has_pending_used(&self) -> bool {
        let used_base = self.used_va.as_u64() as *const u16;
        let used_idx = unsafe { core::ptr::read_volatile(used_base.add(1)) };
        self.last_used_idx.load(Ordering::Acquire) != used_idx
    }

    /// Free a descriptor chain starting from `head`.
    pub fn free_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            let desc = self.desc_ptr(idx);
            let flags = unsafe { (*desc).flags };
            let next = unsafe { (*desc).next };
            self.free_desc(idx);
            if flags & VRING_DESC_F_NEXT != 0 {
                idx = next;
            } else {
                break;
            }
        }
    }

    /// Enqueue a descriptor chain head for deferred freeing (lock-free push).
    /// Called from wait_for_completion without holding any locks.
    /// The submitter will drain these under its existing lock via drain_deferred_frees().
    pub fn defer_free_chain(&self, head: u16) {
        loop {
            let old_head = self.deferred_free_head.load(Ordering::Acquire);

            // Set our next pointer to the old head
            self.deferred_free_next[head as usize].store(old_head, Ordering::Release);

            // CAS to become the new head
            match self.deferred_free_head.compare_exchange_weak(
                old_head,
                head,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    /// Drain all deferred free entries and free them.
    /// Called from push_chain UNDER the queue lock.
    /// Returns number of descriptor chains freed.
    pub fn drain_deferred_frees(&mut self) -> usize {
        // Atomically take the entire list (single swap)
        let mut head = self.deferred_free_head.swap(0xFFFF, Ordering::AcqRel);

        if head == 0xFFFF {
            return 0; // Empty
        }

        let mut count = 0;

        while head != 0xFFFF {
            let next = self.deferred_free_next[head as usize].load(Ordering::Acquire);

            // Actually free this descriptor chain
            self.free_chain(head);
            count += 1;

            head = next;
        }

        count
    }

    /// Deallocate all DMA memory for this virtqueue.
    pub fn destroy(&self) {
        unsafe { unmap_range(self.desc_va, self.desc_size) };
        unsafe { unmap_range(self.avail_va, self.avail_size) };
        unsafe { unmap_range(self.used_va, self.used_size) };
    }
}
