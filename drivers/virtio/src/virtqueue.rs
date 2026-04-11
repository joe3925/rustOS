use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU16, Ordering};
use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped_contiguous, unmap_range, virt_to_phys,
};
use kernel_api::x86_64::{PhysAddr, VirtAddr};

use crate::pci;

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

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

    /// Last used ring index we've processed.
    /// Only accessed by the drain task under the queue write lock.
    last_used_idx: AtomicU16,
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
        })
    }

    /// Enable the queue after all configuration (including MSI-X vector) is set.
    pub fn enable(&self, common_cfg: VirtAddr) {
        unsafe {
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
    /// Returns the head descriptor index of the chain.
    pub fn push_chain(&mut self, bufs: &[(PhysAddr, u32, u16)]) -> Option<u16> {
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
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(avail_base.add(1), avail_idx.wrapping_add(1));
        }

        Some(head)
    }

    /// Push a single indirect descriptor table into the virtqueue.
    /// Returns the head descriptor index.
    pub fn push_indirect(&mut self, table_phys: PhysAddr, table_len: u32) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }

        let head = self.alloc_desc()?;
        let desc = self.desc_ptr(head);
        unsafe {
            (*desc).addr = table_phys.as_u64();
            (*desc).len = table_len;
            (*desc).flags = VRING_DESC_F_INDIRECT;
            (*desc).next = 0;
        }

        let avail_base = self.avail_va.as_u64() as *mut u16;
        let avail_idx = unsafe { core::ptr::read_volatile(avail_base.add(1)) };
        let ring_entry = avail_base.wrapping_add(2 + (avail_idx % self.size) as usize);
        unsafe {
            core::ptr::write_volatile(ring_entry, head);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(avail_base.add(1), avail_idx.wrapping_add(1));
        }

        Some(head)
    }

    /// Write to the device's notify register to kick the queue.
    pub fn notify(&self, notify_base: VirtAddr, notify_off_multiplier: u32) {
        let offset = self.queue_notify_off as u64 * notify_off_multiplier as u64;
        let addr = (notify_base.as_u64() + offset) as *mut u16;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::write_volatile(addr, self.idx) };
    }

    /// Pop one completed entry from the used ring.
    /// Called exclusively by the drain task under the queue write lock.
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
        self.last_used_idx
            .store(last.wrapping_add(1), Ordering::Release);

        Some((elem.id as u16, elem.len))
    }

    /// Free a descriptor chain starting from `head`.
    pub fn free_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            let desc = self.desc_ptr(idx);
            let flags = unsafe { (*desc).flags };
            let next = unsafe { (*desc).next };

            // For an indirect descriptor, only free the single head descriptor.
            if (flags & VRING_DESC_F_INDIRECT) != 0 {
                self.free_desc(idx);
                return;
            }

            self.free_desc(idx);

            if (flags & VRING_DESC_F_NEXT) != 0 {
                idx = next;
            } else {
                break;
            }
        }
    }

    // TODO: defer_free_chain (lock-free deferred free stack) is preserved here
    // for a future multi-queue scenario where non-drain tasks need to return
    // descriptor chains without holding the write lock.

    /// Deallocate all DMA memory for this virtqueue.
    pub fn destroy(&self) {
        unsafe { unmap_range(self.desc_va, self.desc_size) };
        unsafe { unmap_range(self.avail_va, self.avail_size) };
        unsafe { unmap_range(self.used_va, self.used_size) };
    }
}
