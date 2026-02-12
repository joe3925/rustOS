use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped, deallocate_kernel_range, unmap_range,
    virt_to_phys,
};
use kernel_api::x86_64::{PhysAddr, VirtAddr};

use crate::pci;
use crate::virtqueue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, Virtqueue};

/// Number of preallocated slots with 4KB data regions (common I/O size)
pub const ARENA_PREALLOCATED_SLOTS: usize = 48;

/// Number of dynamic slots (arbitrary data size, mapped on demand)
pub const ARENA_DYNAMIC_SLOTS: usize = 16;

/// Maximum arena capacity before overflow requests are not cached
pub const ARENA_MAX_CAPACITY: usize = 1024;

/// Size of preallocated data regions in bytes
/// TODO: Changing this value can significantly impact performance maybe should be tunable at runtime?
pub const PREALLOCATED_DATA_SIZE: usize = 64 * 1024;

// =============================================================================
// Slot State Constants
// =============================================================================

const SLOT_FREE: u16 = 0;
const SLOT_IN_USE: u16 = 1;

/// Pack generation counter and state into a single u32 for atomic operations
#[inline]
const fn pack_slot_state(generation: u16, state: u16) -> u32 {
    ((generation as u32) << 16) | (state as u32)
}

/// Extract generation counter from packed state
#[inline]
const fn unpack_generation(packed: u32) -> u16 {
    (packed >> 16) as u16
}

/// Extract state from packed state
#[inline]
const fn unpack_state(packed: u32) -> u16 {
    packed as u16
}

// =============================================================================
// Slot Structures
// =============================================================================

/// A preallocated slot with all DMA buffers ready (header, 4KB data, status).
/// These slots require no runtime allocation for I/O <= 4KB.
#[repr(C)]
pub struct PreallocatedSlot {
    /// Packed state: high 16 bits = generation, low 16 bits = state
    pub state: AtomicU32,
    /// Header DMA buffer (4KB page, 16 bytes used)
    pub header_va: VirtAddr,
    pub header_phys: PhysAddr,
    /// Data DMA buffer (preallocated 4KB)
    pub data_va: VirtAddr,
    pub data_phys: PhysAddr,
    /// Status DMA buffer (4KB page, 1 byte used)
    pub status_va: VirtAddr,
    pub status_phys: PhysAddr,
}

/// A dynamic slot with header/status preallocated, data mapped on demand.
/// Used for I/O requests larger than 4KB.
#[repr(C)]
pub struct DynamicSlot {
    /// Packed state: high 16 bits = generation, low 16 bits = state
    pub state: AtomicU32,
    /// Header DMA buffer (preallocated)
    pub header_va: VirtAddr,
    pub header_phys: PhysAddr,
    /// Status DMA buffer (preallocated)
    pub status_va: VirtAddr,
    pub status_phys: PhysAddr,
    /// Data buffer virtual address (0 when not allocated)
    pub data_va: AtomicU64,
    /// Data buffer physical address (0 when not allocated)
    pub data_phys: AtomicU64,
    /// Data buffer length in bytes
    pub data_len: AtomicU32,
}

// =============================================================================
// Arena Structure
// =============================================================================

/// Lock-free arena allocator for BlkIoRequest.
/// Pre-allocates DMA buffers to avoid allocation overhead on the hot path.
pub struct BlkIoArena {
    /// Bitmap for preallocated slots: 1 = free, 0 = in use
    preallocated_bitmap: AtomicU64,
    /// Bitmap for dynamic slots: 1 = free, 0 = in use
    dynamic_bitmap: AtomicU64,
    /// Hint for next preallocated allocation (reduces contention)
    preallocated_hint: AtomicUsize,
    /// Hint for next dynamic allocation
    dynamic_hint: AtomicUsize,
    /// Storage for preallocated slots
    preallocated_slots: [UnsafeCell<MaybeUninit<PreallocatedSlot>>; ARENA_PREALLOCATED_SLOTS],
    /// Storage for dynamic slots
    dynamic_slots: [UnsafeCell<MaybeUninit<DynamicSlot>>; ARENA_DYNAMIC_SLOTS],
    /// Current count of overflow allocations (for growth tracking)
    overflow_count: AtomicUsize,
}

// SAFETY: Arena uses atomic operations for all shared state
unsafe impl Send for BlkIoArena {}
unsafe impl Sync for BlkIoArena {}

// =============================================================================
// Request Handle
// =============================================================================

/// Handle to an arena-allocated or overflow BlkIoRequest.
/// Implements Drop to automatically return slots to the arena.
pub enum BlkIoRequestHandle<'a> {
    /// Slot from the preallocated pool (48 slots, 4KB data max)
    Preallocated {
        arena: &'a BlkIoArena,
        slot_idx: u16,
        generation: u16,
        /// Actual requested data length (may be < PREALLOCATED_DATA_SIZE)
        data_len: u32,
    },
    /// Slot from the dynamic pool (16 slots, arbitrary data size)
    Dynamic {
        arena: &'a BlkIoArena,
        slot_idx: u16,
        generation: u16,
    },
    /// Overflow request allocated traditionally (freed on drop)
    Overflow(BlkIoRequest),
}

// =============================================================================
// Arena Implementation
// =============================================================================

impl BlkIoArena {
    /// Initialize the arena, allocating all DMA buffers upfront.
    /// Returns None if DMA allocation fails.
    pub fn init() -> Option<Self> {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

        // Create uninitialized storage arrays
        // SAFETY: We will initialize each slot before use
        let preallocated_slots: [UnsafeCell<MaybeUninit<PreallocatedSlot>>;
            ARENA_PREALLOCATED_SLOTS] = unsafe { MaybeUninit::uninit().assume_init() };
        let dynamic_slots: [UnsafeCell<MaybeUninit<DynamicSlot>>; ARENA_DYNAMIC_SLOTS] =
            unsafe { MaybeUninit::uninit().assume_init() };

        // Initialize preallocated slots with all DMA buffers
        for i in 0..ARENA_PREALLOCATED_SLOTS {
            let header_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
            let header_phys = virt_to_phys(header_va)?;

            let data_va =
                allocate_auto_kernel_range_mapped(PREALLOCATED_DATA_SIZE as u64, flags).ok()?;
            let data_phys = virt_to_phys(data_va)?;

            let status_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
            let status_phys = virt_to_phys(status_va)?;

            // Initialize status sentinel
            unsafe {
                core::ptr::write_volatile(status_va.as_u64() as *mut u8, 0xFF);
            }

            let slot = PreallocatedSlot {
                state: AtomicU32::new(pack_slot_state(0, SLOT_FREE)),
                header_va,
                header_phys,
                data_va,
                data_phys,
                status_va,
                status_phys,
            };

            // SAFETY: We own this slot and are initializing it
            unsafe {
                (*preallocated_slots[i].get()).write(slot);
            }
        }

        // Initialize dynamic slots (header + status only, data on demand)
        for i in 0..ARENA_DYNAMIC_SLOTS {
            let header_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
            let header_phys = virt_to_phys(header_va)?;

            let status_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
            let status_phys = virt_to_phys(status_va)?;

            // Initialize status sentinel
            unsafe {
                core::ptr::write_volatile(status_va.as_u64() as *mut u8, 0xFF);
            }

            let slot = DynamicSlot {
                state: AtomicU32::new(pack_slot_state(0, SLOT_FREE)),
                header_va,
                header_phys,
                status_va,
                status_phys,
                data_va: AtomicU64::new(0),
                data_phys: AtomicU64::new(0),
                data_len: AtomicU32::new(0),
            };

            // SAFETY: We own this slot and are initializing it
            unsafe {
                (*dynamic_slots[i].get()).write(slot);
            }
        }

        // Set all bits in bitmaps (all slots start free)
        // For preallocated: bits 0-47 set
        let preallocated_mask = (1u64 << ARENA_PREALLOCATED_SLOTS) - 1;
        // For dynamic: bits 0-15 set
        let dynamic_mask = (1u64 << ARENA_DYNAMIC_SLOTS) - 1;

        Some(Self {
            preallocated_bitmap: AtomicU64::new(preallocated_mask),
            dynamic_bitmap: AtomicU64::new(dynamic_mask),
            preallocated_hint: AtomicUsize::new(0),
            dynamic_hint: AtomicUsize::new(0),
            preallocated_slots,
            dynamic_slots,
            overflow_count: AtomicUsize::new(0),
        })
    }

    /// Get a reference to a preallocated slot by index.
    /// SAFETY: Caller must ensure idx < ARENA_PREALLOCATED_SLOTS and slot is initialized.
    #[inline]
    fn get_preallocated_slot(&self, idx: usize) -> &PreallocatedSlot {
        debug_assert!(idx < ARENA_PREALLOCATED_SLOTS);
        // SAFETY: Slot was initialized in init() and index is valid
        unsafe { (*self.preallocated_slots[idx].get()).assume_init_ref() }
    }

    /// Get a reference to a dynamic slot by index.
    /// SAFETY: Caller must ensure idx < ARENA_DYNAMIC_SLOTS and slot is initialized.
    #[inline]
    fn get_dynamic_slot(&self, idx: usize) -> &DynamicSlot {
        debug_assert!(idx < ARENA_DYNAMIC_SLOTS);
        // SAFETY: Slot was initialized in init() and index is valid
        unsafe { (*self.dynamic_slots[idx].get()).assume_init_ref() }
    }

    /// Allocate a request slot. Returns None only if arena is exhausted
    /// AND overflow allocation fails.
    pub fn allocate(&self, data_len: u32) -> Option<BlkIoRequestHandle<'_>> {
        // Fast path: if data fits in 4KB, try preallocated slots first
        if data_len <= PREALLOCATED_DATA_SIZE as u32 {
            if let Some(handle) = self.try_allocate_preallocated(data_len) {
                return Some(handle);
            }
        }

        // Try dynamic slots (can handle any size)
        if let Some(handle) = self.try_allocate_dynamic(data_len) {
            return Some(handle);
        }

        // If data fits in 4KB but preallocated was full, we already tried above
        // Fallback: allocate overflow request
        self.allocate_overflow(data_len)
    }

    /// Try to allocate from the preallocated slot pool using lock-free CAS.
    fn try_allocate_preallocated(&self, data_len: u32) -> Option<BlkIoRequestHandle<'_>> {
        loop {
            let bits = self.preallocated_bitmap.load(Ordering::Acquire);
            if bits == 0 {
                return None; // No free slots
            }

            // Find first set bit (free slot)
            let bit_idx = bits.trailing_zeros() as usize;
            if bit_idx >= ARENA_PREALLOCATED_SLOTS {
                return None;
            }

            let mask = 1u64 << bit_idx;

            // Try to claim the slot atomically by clearing the bit
            match self.preallocated_bitmap.compare_exchange_weak(
                bits,
                bits & !mask,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // Successfully claimed slot
                    self.preallocated_hint
                        .store(bit_idx.wrapping_add(1), Ordering::Relaxed);

                    // Update slot state with new generation
                    let slot = self.get_preallocated_slot(bit_idx);
                    let old_state = slot.state.load(Ordering::Acquire);
                    let new_gen = unpack_generation(old_state).wrapping_add(1);
                    slot.state
                        .store(pack_slot_state(new_gen, SLOT_IN_USE), Ordering::Release);

                    return Some(BlkIoRequestHandle::Preallocated {
                        arena: self,
                        slot_idx: bit_idx as u16,
                        generation: new_gen,
                        data_len,
                    });
                }
                Err(_) => continue, // Retry on contention
            }
        }
    }

    /// Try to allocate from the dynamic slot pool using lock-free CAS.
    fn try_allocate_dynamic(&self, data_len: u32) -> Option<BlkIoRequestHandle<'_>> {
        loop {
            let bits = self.dynamic_bitmap.load(Ordering::Acquire);
            if bits == 0 {
                return None; // No free slots
            }

            let bit_idx = bits.trailing_zeros() as usize;
            if bit_idx >= ARENA_DYNAMIC_SLOTS {
                return None;
            }

            let mask = 1u64 << bit_idx;

            match self.dynamic_bitmap.compare_exchange_weak(
                bits,
                bits & !mask,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.dynamic_hint
                        .store(bit_idx.wrapping_add(1), Ordering::Relaxed);

                    let slot = self.get_dynamic_slot(bit_idx);

                    // Allocate data buffer on demand
                    let flags = PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::NO_CACHE;
                    let data_pages = ((data_len as u64) + 4095) & !4095;
                    let data_va =
                        match allocate_auto_kernel_range_mapped(data_pages.max(4096), flags) {
                            Ok(va) => va,
                            Err(_) => {
                                // Failed to allocate data buffer, return slot to pool
                                self.dynamic_bitmap.fetch_or(mask, Ordering::Release);
                                return None;
                            }
                        };
                    let data_phys = match virt_to_phys(data_va) {
                        Some(p) => p,
                        None => {
                            // Failed to get physical address, clean up and return slot
                            unsafe { unmap_range(data_va, data_pages.max(4096)) };
                            self.dynamic_bitmap.fetch_or(mask, Ordering::Release);
                            return None;
                        }
                    };

                    // Store data info atomically
                    slot.data_va.store(data_va.as_u64(), Ordering::Release);
                    slot.data_phys.store(data_phys.as_u64(), Ordering::Release);
                    slot.data_len.store(data_len, Ordering::Release);

                    // Update generation
                    let old_state = slot.state.load(Ordering::Acquire);
                    let new_gen = unpack_generation(old_state).wrapping_add(1);
                    slot.state
                        .store(pack_slot_state(new_gen, SLOT_IN_USE), Ordering::Release);

                    return Some(BlkIoRequestHandle::Dynamic {
                        arena: self,
                        slot_idx: bit_idx as u16,
                        generation: new_gen,
                    });
                }
                Err(_) => continue,
            }
        }
    }

    /// Allocate an overflow request using traditional allocation.
    fn allocate_overflow(&self, data_len: u32) -> Option<BlkIoRequestHandle<'_>> {
        // Track overflow count (informational, not limiting)
        self.overflow_count.fetch_add(1, Ordering::Relaxed);

        // Use traditional BlkIoRequest allocation
        let req = BlkIoRequest::new_internal(data_len)?;
        Some(BlkIoRequestHandle::Overflow(req))
    }

    /// Return a preallocated slot to the pool.
    fn return_preallocated(&self, slot_idx: u16, generation: u16) {
        let idx = slot_idx as usize;
        if idx >= ARENA_PREALLOCATED_SLOTS {
            return;
        }

        let slot = self.get_preallocated_slot(idx);

        // Verify generation matches (prevents ABA issues)
        let current_state = slot.state.load(Ordering::Acquire);
        if unpack_generation(current_state) != generation {
            return; // Slot was already recycled (shouldn't happen)
        }

        // Reset status sentinel for next use
        unsafe {
            core::ptr::write_volatile(slot.status_va.as_u64() as *mut u8, 0xFF);
        }

        // Mark slot as free (keep generation for ABA detection)
        slot.state
            .store(pack_slot_state(generation, SLOT_FREE), Ordering::Release);

        // Return to free pool by setting bit
        let mask = 1u64 << idx;
        self.preallocated_bitmap.fetch_or(mask, Ordering::Release);

        // Update hint for faster allocation
        self.preallocated_hint.store(idx, Ordering::Relaxed);
    }

    /// Return a dynamic slot to the pool, freeing the data buffer.
    fn return_dynamic(&self, slot_idx: u16, generation: u16) {
        let idx = slot_idx as usize;
        if idx >= ARENA_DYNAMIC_SLOTS {
            return;
        }

        let slot = self.get_dynamic_slot(idx);

        // Verify generation
        let current_state = slot.state.load(Ordering::Acquire);
        if unpack_generation(current_state) != generation {
            return;
        }

        // Free the dynamically allocated data buffer
        let data_va = slot.data_va.swap(0, Ordering::AcqRel);
        let data_len = slot.data_len.swap(0, Ordering::AcqRel);
        slot.data_phys.store(0, Ordering::Release);

        if data_va != 0 {
            let data_pages = ((data_len as u64) + 4095) & !4095;
            unsafe {
                unmap_range(VirtAddr::new(data_va), data_pages.max(4096));
            }
        }

        // Reset status sentinel
        unsafe {
            core::ptr::write_volatile(slot.status_va.as_u64() as *mut u8, 0xFF);
        }

        // Mark free and return to pool
        slot.state
            .store(pack_slot_state(generation, SLOT_FREE), Ordering::Release);

        let mask = 1u64 << idx;
        self.dynamic_bitmap.fetch_or(mask, Ordering::Release);
        self.dynamic_hint.store(idx, Ordering::Relaxed);
    }

    /// Create a new request using the arena.
    pub fn new_request(
        &self,
        req_type: u32,
        sector: u64,
        data_len: u32,
    ) -> Option<BlkIoRequestHandle<'_>> {
        let mut handle = self.allocate(data_len)?;
        handle.set_header(req_type, sector);

        // Zero the data buffer
        unsafe {
            core::ptr::write_bytes(
                handle.data_va().as_u64() as *mut u8,
                0,
                handle.data_len() as usize,
            );
        }

        Some(handle)
    }
}

// =============================================================================
// BlkIoRequestHandle Implementation
// =============================================================================

impl<'a> BlkIoRequestHandle<'a> {
    /// Get the header virtual address.
    #[inline]
    pub fn header_va(&self) -> VirtAddr {
        match self {
            Self::Preallocated {
                arena, slot_idx, ..
            } => arena.get_preallocated_slot(*slot_idx as usize).header_va,
            Self::Dynamic {
                arena, slot_idx, ..
            } => arena.get_dynamic_slot(*slot_idx as usize).header_va,
            Self::Overflow(req) => req.header_va,
        }
    }

    /// Get the header physical address.
    #[inline]
    pub fn header_phys(&self) -> PhysAddr {
        match self {
            Self::Preallocated {
                arena, slot_idx, ..
            } => arena.get_preallocated_slot(*slot_idx as usize).header_phys,
            Self::Dynamic {
                arena, slot_idx, ..
            } => arena.get_dynamic_slot(*slot_idx as usize).header_phys,
            Self::Overflow(req) => req.header_phys,
        }
    }

    /// Get the data virtual address.
    #[inline]
    pub fn data_va(&self) -> VirtAddr {
        match self {
            Self::Preallocated {
                arena, slot_idx, ..
            } => arena.get_preallocated_slot(*slot_idx as usize).data_va,
            Self::Dynamic {
                arena, slot_idx, ..
            } => {
                let slot = arena.get_dynamic_slot(*slot_idx as usize);
                VirtAddr::new(slot.data_va.load(Ordering::Acquire))
            }
            Self::Overflow(req) => req.data_va,
        }
    }

    /// Get the data physical address.
    #[inline]
    pub fn data_phys(&self) -> PhysAddr {
        match self {
            Self::Preallocated {
                arena, slot_idx, ..
            } => arena.get_preallocated_slot(*slot_idx as usize).data_phys,
            Self::Dynamic {
                arena, slot_idx, ..
            } => {
                let slot = arena.get_dynamic_slot(*slot_idx as usize);
                PhysAddr::new(slot.data_phys.load(Ordering::Acquire))
            }
            Self::Overflow(req) => req.data_phys,
        }
    }

    /// Get the data length in bytes.
    #[inline]
    pub fn data_len(&self) -> u32 {
        match self {
            Self::Preallocated { data_len, .. } => *data_len,
            Self::Dynamic {
                arena, slot_idx, ..
            } => {
                let slot = arena.get_dynamic_slot(*slot_idx as usize);
                slot.data_len.load(Ordering::Acquire)
            }
            Self::Overflow(req) => req.data_len,
        }
    }

    /// Get the status virtual address.
    #[inline]
    pub fn status_va(&self) -> VirtAddr {
        match self {
            Self::Preallocated {
                arena, slot_idx, ..
            } => arena.get_preallocated_slot(*slot_idx as usize).status_va,
            Self::Dynamic {
                arena, slot_idx, ..
            } => arena.get_dynamic_slot(*slot_idx as usize).status_va,
            Self::Overflow(req) => req.status_va,
        }
    }

    /// Get the status physical address.
    #[inline]
    pub fn status_phys(&self) -> PhysAddr {
        match self {
            Self::Preallocated {
                arena, slot_idx, ..
            } => arena.get_preallocated_slot(*slot_idx as usize).status_phys,
            Self::Dynamic {
                arena, slot_idx, ..
            } => arena.get_dynamic_slot(*slot_idx as usize).status_phys,
            Self::Overflow(req) => req.status_phys,
        }
    }

    /// Initialize the request header.
    pub fn set_header(&self, req_type: u32, sector: u64) {
        unsafe {
            let hdr = self.header_va().as_u64() as *mut VirtioBlkReqHeader;
            core::ptr::write_volatile(
                hdr,
                VirtioBlkReqHeader {
                    req_type,
                    reserved: 0,
                    sector,
                },
            );
        }
    }

    /// Read the status byte from the DMA buffer.
    #[inline]
    pub fn status(&self) -> u8 {
        unsafe { core::ptr::read_volatile(self.status_va().as_u64() as *const u8) }
    }

    /// Get a slice view of the data buffer.
    #[inline]
    pub fn data_slice(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.data_va().as_u64() as *const u8,
                self.data_len() as usize,
            )
        }
    }

    /// Get a mutable slice view of the data buffer.
    #[inline]
    pub fn data_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.data_va().as_u64() as *mut u8,
                self.data_len() as usize,
            )
        }
    }

    /// Build the descriptor chain for this request and push it to the virtqueue.
    /// Returns the head descriptor index.
    pub fn submit(&self, vq: &mut Virtqueue, is_write: bool) -> Option<u16> {
        let data_flags = if is_write { 0 } else { VRING_DESC_F_WRITE };

        let mut bufs: Vec<(PhysAddr, u32, u16)> = Vec::new();
        bufs.push((self.header_phys(), 16, 0u16));

        let mut offset = 0u64;
        let total = self.data_len() as u64;
        let data_va_base = self.data_va();
        let data_phys_base = self.data_phys();

        while offset < total {
            let vaddr = VirtAddr::new(data_va_base.as_u64() + offset);
            let phys = match virt_to_phys(vaddr) {
                Some(p) => p,
                None => {
                    // Fallback: use base physical + offset (assumes contiguous)
                    PhysAddr::new(data_phys_base.as_u64() + offset)
                }
            };
            let page_off = (vaddr.as_u64() & 0xFFF) as u64;
            let chunk = core::cmp::min(4096u64 - page_off, total - offset);
            let seg_phys = PhysAddr::new(phys.as_u64());

            // Coalesce contiguous physical segments to keep descriptor count low.
            if let Some(last) = bufs.last_mut() {
                let last_end = last.0.as_u64() + last.1 as u64;
                if last.2 == data_flags && last_end == seg_phys.as_u64() {
                    last.1 = last.1.saturating_add(chunk as u32);
                    offset += chunk;
                    continue;
                }
            }

            bufs.push((seg_phys, chunk as u32, data_flags));
            offset += chunk;
        }

        bufs.push((self.status_phys(), 1, VRING_DESC_F_WRITE));

        vq.push_chain(&bufs)
    }
}

// =============================================================================
// Drop Implementation
// =============================================================================

impl<'a> Drop for BlkIoRequestHandle<'a> {
    fn drop(&mut self) {
        match self {
            BlkIoRequestHandle::Preallocated {
                arena,
                slot_idx,
                generation,
                ..
            } => {
                arena.return_preallocated(*slot_idx, *generation);
            }
            BlkIoRequestHandle::Dynamic {
                arena,
                slot_idx,
                generation,
            } => {
                arena.return_dynamic(*slot_idx, *generation);
            }
            BlkIoRequestHandle::Overflow(req) => {
                // Free all DMA buffers for overflow requests
                unsafe {
                    unmap_range(req.header_va, 4096);
                    let data_pages = ((req.data_len as u64) + 4095) & !4095;
                    unmap_range(req.data_va, data_pages.max(4096));
                    unmap_range(req.status_va, 4096);
                }
            }
        }
    }
}

pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;

#[repr(C)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
/// Mandatory for modern virtio-pci devices.
pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;

const DEVCFG_CAPACITY: usize = 0x00; // u64 — capacity in 512-byte sectors

/// Negotiate features and read device configuration.
/// Returns the disk capacity in 512-byte sectors.
pub fn init_device(common_cfg: VirtAddr, device_cfg: VirtAddr) -> Option<u64> {
    unsafe { pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, 0) };

    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE,
        )
    };

    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        )
    };

    // Read 64-bit device feature set.
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DEVICE_FEATURE_SELECT, 0) };
    let dev_features_lo = unsafe { pci::common_read_u32(common_cfg, pci::COMMON_DEVICE_FEATURE) };
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DEVICE_FEATURE_SELECT, 1) };
    let dev_features_hi = unsafe { pci::common_read_u32(common_cfg, pci::COMMON_DEVICE_FEATURE) };
    let dev_features = (dev_features_hi as u64) << 32 | dev_features_lo as u64;

    // Modern virtio-pci requires VERSION_1; fail early if missing.
    if dev_features & VIRTIO_F_VERSION_1 == 0 {
        unsafe {
            pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, VIRTIO_STATUS_FAILED)
        };
        return None;
    }

    let supported_features = VIRTIO_F_VERSION_1;
    let driver_features = dev_features & supported_features;
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DRIVER_FEATURE_SELECT, 0) };
    unsafe {
        pci::common_write_u32(
            common_cfg,
            pci::COMMON_DRIVER_FEATURE,
            driver_features as u32,
        )
    };
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DRIVER_FEATURE_SELECT, 1) };
    unsafe {
        pci::common_write_u32(
            common_cfg,
            pci::COMMON_DRIVER_FEATURE,
            (driver_features >> 32) as u32,
        )
    };

    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
        )
    };

    let status = unsafe { pci::common_read_u8(common_cfg, pci::COMMON_DEVICE_STATUS) };
    if status & VIRTIO_STATUS_FEATURES_OK == 0 {
        unsafe {
            pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, VIRTIO_STATUS_FAILED)
        };
        return None;
    }

    let capacity = unsafe {
        core::ptr::read_volatile(
            (device_cfg.as_u64() as *const u8).add(DEVCFG_CAPACITY) as *const u64
        )
    };

    Some(capacity)
}

/// Set the DRIVER_OK status bit, completing device initialization.
pub fn set_driver_ok(common_cfg: VirtAddr) {
    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        )
    };
}

/// Reset the device by writing 0 to device_status.
pub fn reset_device(common_cfg: VirtAddr) {
    unsafe { pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, 0) };
}

/// A prepared block I/O request with DMA buffers allocated.
pub struct BlkIoRequest {
    /// DMA buffer containing the 16-byte request header.
    pub header_va: VirtAddr,
    pub header_phys: PhysAddr,
    /// DMA buffer for data transfer.
    pub data_va: VirtAddr,
    pub data_phys: PhysAddr,
    pub data_len: u32,
    /// DMA buffer for the 1-byte status response.
    pub status_va: VirtAddr,
    pub status_phys: PhysAddr,
}

impl BlkIoRequest {
    /// Allocate DMA buffers and prepare a block I/O request.
    /// `req_type` is VIRTIO_BLK_T_IN (read) or VIRTIO_BLK_T_OUT (write).
    /// `sector` is the starting 512-byte sector.
    /// `data_len` is the number of bytes to transfer (must be sector-aligned).
    pub fn new(req_type: u32, sector: u64, data_len: u32) -> Option<Self> {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

        let header_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
        let header_phys = virt_to_phys(header_va)?;
        unsafe {
            let hdr = header_va.as_u64() as *mut VirtioBlkReqHeader;
            core::ptr::write_volatile(
                hdr,
                VirtioBlkReqHeader {
                    req_type,
                    reserved: 0,
                    sector,
                },
            );
        }

        let data_pages = ((data_len as u64) + 4095) & !4095;
        let data_va = allocate_auto_kernel_range_mapped(data_pages.max(4096), flags).ok()?;
        let data_phys = virt_to_phys(data_va)?;
        unsafe { core::ptr::write_bytes(data_va.as_u64() as *mut u8, 0, data_len as usize) };

        let status_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
        let status_phys = virt_to_phys(status_va)?;
        unsafe { core::ptr::write_volatile(status_va.as_u64() as *mut u8, 0xFF) }; // sentinel

        Some(Self {
            header_va,
            header_phys,
            data_va,
            data_phys,
            data_len,
            status_va,
            status_phys,
        })
    }

    /// Internal allocation without header initialization (used by arena overflow).
    /// Header must be set separately via BlkIoRequestHandle::set_header.
    pub(crate) fn new_internal(data_len: u32) -> Option<Self> {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

        let header_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
        let header_phys = virt_to_phys(header_va)?;

        let data_pages = ((data_len as u64) + 4095) & !4095;
        let data_va = allocate_auto_kernel_range_mapped(data_pages.max(4096), flags).ok()?;
        let data_phys = virt_to_phys(data_va)?;

        let status_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
        let status_phys = virt_to_phys(status_va)?;
        unsafe { core::ptr::write_volatile(status_va.as_u64() as *mut u8, 0xFF) }; // sentinel

        Some(Self {
            header_va,
            header_phys,
            data_va,
            data_phys,
            data_len,
            status_va,
            status_phys,
        })
    }

    /// Build the 3-descriptor chain for this request and push it to the virtqueue.
    /// Returns the head descriptor index.
    pub fn submit(&self, vq: &mut Virtqueue, is_write: bool) -> Option<u16> {
        let data_flags = if is_write { 0 } else { VRING_DESC_F_WRITE };

        let mut bufs: Vec<(PhysAddr, u32, u16)> = Vec::new();
        bufs.push((self.header_phys, 16, 0u16));

        let mut offset = 0u64;
        let total = self.data_len as u64;
        while offset < total {
            let vaddr = VirtAddr::new(self.data_va.as_u64() + offset);
            let phys = virt_to_phys(vaddr)?;
            let page_off = (vaddr.as_u64() & 0xFFF) as u64;
            let chunk = core::cmp::min(4096u64 - page_off, total - offset);
            let seg_phys = PhysAddr::new(phys.as_u64() + page_off);

            // Coalesce contiguous physical segments to keep descriptor count low.
            if let Some(last) = bufs.last_mut() {
                let last_end = last.0.as_u64() + last.1 as u64;
                if last.2 == data_flags && last_end == seg_phys.as_u64() {
                    last.1 = last.1.saturating_add(chunk as u32);
                    offset += chunk;
                    continue;
                }
            }

            bufs.push((seg_phys, chunk as u32, data_flags));
            offset += chunk;
        }

        bufs.push((self.status_phys, 1, VRING_DESC_F_WRITE));

        vq.push_chain(&bufs)
    }

    /// Read the status byte from the DMA buffer.
    pub fn status(&self) -> u8 {
        unsafe { core::ptr::read_volatile(self.status_va.as_u64() as *const u8) }
    }

    /// Get a slice view of the data buffer.
    pub fn data_slice(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(self.data_va.as_u64() as *const u8, self.data_len as usize)
        }
    }

    /// Get a mutable slice view of the data buffer (for writing data before an OUT request).
    pub fn data_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.data_va.as_u64() as *mut u8,
                self.data_len as usize,
            )
        }
    }

    /// Free all DMA buffers.
    pub fn destroy(self) {
        unsafe { unmap_range(self.header_va, 4096) };
        let data_pages = ((self.data_len as u64) + 4095) & !4095;
        unsafe { unmap_range(self.data_va, data_pages.max(4096)) };
        unsafe { unmap_range(self.status_va, 4096) };
    }
}
