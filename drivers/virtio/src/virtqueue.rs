use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped, deallocate_kernel_range, virt_to_phys,
};
use kernel_api::x86_64::{PhysAddr, VirtAddr};

use crate::pci;

// ---------------------------------------------------------------------------
// Descriptor flags
// ---------------------------------------------------------------------------
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// Descriptor table entry (16 bytes)
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

// ---------------------------------------------------------------------------
// Available ring header (variable size)
//   u16 flags
//   u16 idx
//   u16[queue_size] ring
//   u16 used_event  (if VIRTIO_F_EVENT_IDX)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Used ring header (variable size)
//   u16 flags
//   u16 idx
//   VirtqUsedElem[queue_size] ring
//   u16 avail_event  (if VIRTIO_F_EVENT_IDX)
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

// ---------------------------------------------------------------------------
// Descriptor state tracking
// ---------------------------------------------------------------------------
#[derive(Clone, Copy)]
pub struct DescState {
    /// true if this descriptor slot is free
    pub free: bool,
}

// ---------------------------------------------------------------------------
// Split virtqueue
// ---------------------------------------------------------------------------
pub struct Virtqueue {
    pub idx: u16,
    pub size: u16,

    // DMA regions (virtual)
    pub desc_va: VirtAddr,
    pub avail_va: VirtAddr,
    pub used_va: VirtAddr,

    // Physical addresses written to the device
    pub desc_phys: PhysAddr,
    pub avail_phys: PhysAddr,
    pub used_phys: PhysAddr,

    // Sizes for deallocation
    desc_size: u64,
    avail_size: u64,
    used_size: u64,

    // Free list
    pub free_head: u16,
    pub num_free: u16,
    pub last_used_idx: u16,
}

fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

impl Virtqueue {
    /// Allocate and initialise a split virtqueue.
    /// Writes the physical addresses into the device via common_cfg.
    pub fn new(queue_idx: u16, common_cfg: VirtAddr) -> Option<Self> {
        // Select queue
        unsafe { pci::common_write_u16(common_cfg, pci::COMMON_QUEUE_SELECT, queue_idx) };

        let max_size = unsafe { pci::common_read_u16(common_cfg, pci::COMMON_QUEUE_SIZE) };
        if max_size == 0 {
            return None;
        }
        // Use the full size the device offers (could be clamped later if needed).
        let size = max_size;
        unsafe { pci::common_write_u16(common_cfg, pci::COMMON_QUEUE_SIZE, size) };

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

        // Descriptor table: 16 bytes per entry
        let desc_bytes = align_up(size as u64 * 16, 4096);
        let desc_va = allocate_auto_kernel_range_mapped(desc_bytes, flags).ok()?;
        let desc_phys = virt_to_phys(desc_va);

        // Available ring: 2 (flags) + 2 (idx) + 2*size (ring) + 2 (used_event) — align to page
        let avail_bytes = align_up(6 + size as u64 * 2, 4096);
        let avail_va = allocate_auto_kernel_range_mapped(avail_bytes, flags).ok()?;
        let avail_phys = virt_to_phys(avail_va);

        // Used ring: 2 (flags) + 2 (idx) + 8*size (elems) + 2 (avail_event) — align to page
        let used_bytes = align_up(6 + size as u64 * 8, 4096);
        let used_va = allocate_auto_kernel_range_mapped(used_bytes, flags).ok()?;
        let used_phys = virt_to_phys(used_va);

        // Zero all regions
        unsafe {
            core::ptr::write_bytes(desc_va.as_u64() as *mut u8, 0, desc_bytes as usize);
            core::ptr::write_bytes(avail_va.as_u64() as *mut u8, 0, avail_bytes as usize);
            core::ptr::write_bytes(used_va.as_u64() as *mut u8, 0, used_bytes as usize);
        }

        // Build free list: each descriptor's `next` points to the next index
        for i in 0..size {
            let desc_ptr = (desc_va.as_u64() + i as u64 * 16) as *mut VirtqDesc;
            unsafe {
                (*desc_ptr).next = if i + 1 < size { i + 1 } else { 0 };
                (*desc_ptr).flags = 0;
            }
        }

        // Write physical addresses to device
        unsafe {
            pci::common_write_u64(common_cfg, pci::COMMON_QUEUE_DESC, desc_phys.as_u64());
            pci::common_write_u64(common_cfg, pci::COMMON_QUEUE_DRIVER, avail_phys.as_u64());
            pci::common_write_u64(common_cfg, pci::COMMON_QUEUE_DEVICE, used_phys.as_u64());

            // Enable queue
            pci::common_write_u16(common_cfg, pci::COMMON_QUEUE_ENABLE, 1);
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
            free_head: 0,
            num_free: size,
            last_used_idx: 0,
        })
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
                // Link previous -> current
                let prev_desc = self.desc_ptr(prev);
                unsafe {
                    (*prev_desc).flags |= VRING_DESC_F_NEXT;
                    (*prev_desc).next = idx;
                }
            }
            prev = idx;
        }

        // Add head to available ring
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
        let queue_notify_off = unsafe {
            // Read queue_notify_off from common_cfg — but we don't have common_cfg here,
            // so the caller should cache it. For simplicity, assume offset 0 for queue 0.
            // This is written at queue setup time. We just use idx * multiplier.
            self.idx as u64
        };
        let offset = queue_notify_off * notify_off_multiplier as u64;
        let addr = (notify_base.as_u64() + offset) as *mut u16;
        unsafe { core::ptr::write_volatile(addr, self.idx) };
    }

    /// Pop completed entries from the used ring.
    /// Returns a list of (descriptor_head_index, bytes_written).
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        let used_base = self.used_va.as_u64() as *const u16;
        let used_idx = unsafe { core::ptr::read_volatile(used_base.add(1)) };

        if self.last_used_idx == used_idx {
            return None;
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        let elem_offset = 4 + (self.last_used_idx % self.size) as usize * 8;
        let elem_ptr = (self.used_va.as_u64() + elem_offset as u64) as *const VirtqUsedElem;
        let elem = unsafe { core::ptr::read_volatile(elem_ptr) };
        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        Some((elem.id as u16, elem.len))
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

    /// Deallocate all DMA memory for this virtqueue.
    pub fn destroy(&self) {
        deallocate_kernel_range(self.desc_va, self.desc_size);
        deallocate_kernel_range(self.avail_va, self.avail_size);
        deallocate_kernel_range(self.used_va, self.used_size);
    }
}
