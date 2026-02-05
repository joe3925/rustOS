use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped, deallocate_kernel_range, unmap_range,
    virt_to_phys,
};
use kernel_api::x86_64::{PhysAddr, VirtAddr};
use spin::Mutex;

use crate::pci;
use crate::virtqueue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, Virtqueue};

// ============================================================================
// Arena Allocator Constants
// ============================================================================

/// Size class for 4KB data buffers
pub const SIZE_CLASS_4K: usize = 0;
/// Size class for 16KB data buffers
pub const SIZE_CLASS_16K: usize = 1;
/// Size class for 64KB data buffers
pub const SIZE_CLASS_64K: usize = 2;
/// Number of size classes
pub const NUM_SIZE_CLASSES: usize = 3;
/// Size in bytes for each size class
pub const SIZE_CLASS_BYTES: [u64; NUM_SIZE_CLASSES] = [4096, 16384, 65536];

/// Initial number of slots per arena block
pub const INITIAL_ARENA_SLOTS: usize = 64;
/// Maximum total slots across all blocks (4x initial)
pub const MAX_ARENA_SLOTS: usize = 256;
/// Maximum number of arena blocks
pub const MAX_ARENA_BLOCKS: usize = 4;

// ============================================================================
// Arena Allocator Types
// ============================================================================

/// Pre-allocated DMA buffers for header and status (fixed 4KB each)
pub struct ArenaSlot {
    /// Header buffer virtual address (4KB)
    pub header_va: VirtAddr,
    /// Header buffer physical address
    pub header_phys: PhysAddr,
    /// Status buffer virtual address (4KB)
    pub status_va: VirtAddr,
    /// Status buffer physical address
    pub status_phys: PhysAddr,
}

/// Pre-allocated data buffer for a specific size class
pub struct DataBufferSlot {
    /// Data buffer virtual address
    pub va: VirtAddr,
    /// Data buffer physical address
    pub phys: PhysAddr,
    /// Size in bytes
    pub size: u64,
}

/// A block of pre-allocated arena slots (64 slots per block)
pub struct ArenaBlock {
    /// Header/status slot storage
    slots: Vec<ArenaSlot>,
    /// Free bitmap: bit N = 1 means slot N is free
    free_bitmap: AtomicU64,
    /// Number of slots in this block
    num_slots: usize,
}

/// Pool of pre-allocated data buffers for a single size class
pub struct DataBufferPool {
    /// Data buffer storage
    buffers: Vec<DataBufferSlot>,
    /// Free bitmap: bit N = 1 means buffer N is free
    free_bitmap: AtomicU64,
    /// Size class index
    size_class: usize,
    /// Number of buffers in this pool
    num_buffers: usize,
}

/// Handle tracking where an allocation came from
#[derive(Clone, Copy)]
pub struct ArenaHandle {
    /// Block index (0-3)
    block_idx: u8,
    /// Slot index within block (0-63)
    slot_idx: u8,
    /// Data buffer size class (0-2)
    data_size_class: u8,
    /// Data buffer index within its pool
    data_buf_idx: u8,
}

/// A BlkIoRequest allocated from the arena (or dynamically as fallback)
pub struct ArenaBlkIoRequest {
    /// The actual request data
    pub request: BlkIoRequest,
    /// Arena handle for deallocation (None = fallback allocation)
    handle: Option<ArenaHandle>,
}

/// Arena allocator for BlkIoRequest DMA buffers
pub struct BlkIoRequestArena {
    /// Arena blocks for header/status buffers
    blocks: Mutex<Vec<ArenaBlock>>,
    /// Data buffer pools by size class [4KB, 16KB, 64KB]
    data_pools: [Mutex<DataBufferPool>; NUM_SIZE_CLASSES],
    /// Total slots allocated across all blocks
    total_slots: AtomicUsize,
    /// Statistics: allocations from arena
    arena_allocs: AtomicU64,
    /// Statistics: fallback dynamic allocations
    fallback_allocs: AtomicU64,
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

// ============================================================================
// Arena Block Implementation
// ============================================================================

impl ArenaBlock {
    /// Create a new arena block with the specified number of slots.
    /// Allocates DMA buffers for header and status.
    /// Returns None if allocation fails.
    pub fn new(num_slots: usize) -> Option<Self> {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
        let mut slots: Vec<ArenaSlot> = Vec::with_capacity(num_slots);

        for _ in 0..num_slots {
            let header_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
            let header_phys = virt_to_phys(header_va)?;

            let status_va = match allocate_auto_kernel_range_mapped(4096, flags).ok() {
                Some(va) => va,
                None => {
                    // Cleanup header on failure
                    unsafe { unmap_range(header_va, 4096) };
                    // Cleanup all previously allocated slots
                    for slot in slots.drain(..) {
                        unsafe {
                            unmap_range(slot.header_va, 4096);
                            unmap_range(slot.status_va, 4096);
                        }
                    }
                    return None;
                }
            };
            let status_phys = match virt_to_phys(status_va) {
                Some(p) => p,
                None => {
                    unsafe {
                        unmap_range(header_va, 4096);
                        unmap_range(status_va, 4096);
                    }
                    for slot in slots.drain(..) {
                        unsafe {
                            unmap_range(slot.header_va, 4096);
                            unmap_range(slot.status_va, 4096);
                        }
                    }
                    return None;
                }
            };

            slots.push(ArenaSlot {
                header_va,
                header_phys,
                status_va,
                status_phys,
            });
        }

        // All bits set = all slots free
        let free_bitmap = if num_slots == 64 {
            AtomicU64::new(u64::MAX)
        } else {
            AtomicU64::new((1u64 << num_slots) - 1)
        };

        Some(Self {
            slots,
            free_bitmap,
            num_slots,
        })
    }

    /// Try to allocate a slot. Returns slot index if successful.
    pub fn alloc_slot(&self) -> Option<usize> {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            if bitmap == 0 {
                return None; // No free slots
            }

            let idx = bitmap.trailing_zeros() as usize;
            if idx >= self.num_slots {
                return None;
            }

            let new_bitmap = bitmap & !(1u64 << idx);
            if self
                .free_bitmap
                .compare_exchange_weak(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
            // CAS failed, retry
        }
    }

    /// Free a slot back to the block.
    pub fn free_slot(&self, idx: usize) {
        debug_assert!(idx < self.num_slots);
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            let new_bitmap = bitmap | (1u64 << idx);
            if self
                .free_bitmap
                .compare_exchange_weak(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Get a reference to a slot by index.
    pub fn get_slot(&self, idx: usize) -> &ArenaSlot {
        &self.slots[idx]
    }

    /// Cleanup all DMA buffers in this block.
    fn cleanup(&mut self) {
        for slot in self.slots.drain(..) {
            unsafe {
                unmap_range(slot.header_va, 4096);
                unmap_range(slot.status_va, 4096);
            }
        }
    }
}

impl Drop for ArenaBlock {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ============================================================================
// Data Buffer Pool Implementation
// ============================================================================

impl DataBufferPool {
    /// Create a new data buffer pool for the given size class.
    pub fn new(size_class: usize, num_buffers: usize) -> Option<Self> {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
        let buffer_size = SIZE_CLASS_BYTES[size_class];
        let mut buffers: Vec<DataBufferSlot> = Vec::with_capacity(num_buffers);

        for _ in 0..num_buffers {
            let va = allocate_auto_kernel_range_mapped(buffer_size, flags).ok()?;
            let phys = match virt_to_phys(va) {
                Some(p) => p,
                None => {
                    unsafe { unmap_range(va, buffer_size) };
                    // Cleanup all previously allocated buffers
                    for buf in buffers.drain(..) {
                        unsafe { unmap_range(buf.va, buf.size) };
                    }
                    return None;
                }
            };

            buffers.push(DataBufferSlot {
                va,
                phys,
                size: buffer_size,
            });
        }

        let free_bitmap = if num_buffers == 64 {
            AtomicU64::new(u64::MAX)
        } else if num_buffers == 0 {
            AtomicU64::new(0)
        } else {
            AtomicU64::new((1u64 << num_buffers) - 1)
        };

        Some(Self {
            buffers,
            free_bitmap,
            size_class,
            num_buffers,
        })
    }

    /// Create an empty pool (for initialization)
    pub fn empty(size_class: usize) -> Self {
        Self {
            buffers: Vec::new(),
            free_bitmap: AtomicU64::new(0),
            size_class,
            num_buffers: 0,
        }
    }

    /// Try to allocate a buffer. Returns buffer index if successful.
    pub fn alloc_buffer(&self) -> Option<usize> {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            if bitmap == 0 {
                return None;
            }

            let idx = bitmap.trailing_zeros() as usize;
            if idx >= self.num_buffers {
                return None;
            }

            let new_bitmap = bitmap & !(1u64 << idx);
            if self
                .free_bitmap
                .compare_exchange_weak(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
        }
    }

    /// Free a buffer back to the pool.
    pub fn free_buffer(&self, idx: usize) {
        debug_assert!(idx < self.num_buffers);
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            let new_bitmap = bitmap | (1u64 << idx);
            if self
                .free_bitmap
                .compare_exchange_weak(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Get a reference to a buffer by index.
    pub fn get_buffer(&self, idx: usize) -> &DataBufferSlot {
        &self.buffers[idx]
    }

    /// Grow the pool by adding more buffers. Returns true if successful.
    pub fn grow(&mut self, additional: usize) -> bool {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
        let buffer_size = SIZE_CLASS_BYTES[self.size_class];

        let new_total = self.num_buffers + additional;
        if new_total > 64 {
            return false; // Can't exceed 64 buffers per pool (bitmap limit)
        }

        for _ in 0..additional {
            let va = match allocate_auto_kernel_range_mapped(buffer_size, flags).ok() {
                Some(v) => v,
                None => return false,
            };
            let phys = match virt_to_phys(va) {
                Some(p) => p,
                None => {
                    unsafe { unmap_range(va, buffer_size) };
                    return false;
                }
            };

            self.buffers.push(DataBufferSlot {
                va,
                phys,
                size: buffer_size,
            });
        }

        // Update bitmap to mark new buffers as free
        let old_count = self.num_buffers;
        self.num_buffers = new_total;

        // Set bits for the new buffers
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            let new_bits = if new_total == 64 {
                u64::MAX
            } else {
                (1u64 << new_total) - 1
            };
            // Keep existing allocation state for old buffers, mark new ones as free
            let new_bitmap = bitmap | (new_bits & !((1u64 << old_count) - 1));
            if self
                .free_bitmap
                .compare_exchange_weak(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        true
    }

    /// Cleanup all DMA buffers.
    fn cleanup(&mut self) {
        for buf in self.buffers.drain(..) {
            unsafe { unmap_range(buf.va, buf.size) };
        }
    }
}

impl Drop for DataBufferPool {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ============================================================================
// BlkIoRequestArena Implementation
// ============================================================================

impl BlkIoRequestArena {
    /// Create a new arena with initial capacity (64 slots).
    pub fn new() -> Option<Self> {
        // Create initial block with 64 slots
        let initial_block = ArenaBlock::new(INITIAL_ARENA_SLOTS)?;

        // Create data pools with proportional sizes
        // 4KB: 64 buffers, 16KB: 32 buffers, 64KB: 16 buffers
        let pool_4k = DataBufferPool::new(SIZE_CLASS_4K, 64)?;
        let pool_16k = DataBufferPool::new(SIZE_CLASS_16K, 32)?;
        let pool_64k = DataBufferPool::new(SIZE_CLASS_64K, 16)?;

        Some(Self {
            blocks: Mutex::new(alloc::vec![initial_block]),
            data_pools: [
                Mutex::new(pool_4k),
                Mutex::new(pool_16k),
                Mutex::new(pool_64k),
            ],
            total_slots: AtomicUsize::new(INITIAL_ARENA_SLOTS),
            arena_allocs: AtomicU64::new(0),
            fallback_allocs: AtomicU64::new(0),
        })
    }

    /// Determine the size class for a given data length.
    /// Returns None if the length exceeds maximum arena buffer size.
    fn size_class_for_len(data_len: u32) -> Option<usize> {
        if data_len <= 4096 {
            Some(SIZE_CLASS_4K)
        } else if data_len <= 16384 {
            Some(SIZE_CLASS_16K)
        } else if data_len <= 65536 {
            Some(SIZE_CLASS_64K)
        } else {
            None // Exceeds max, use fallback
        }
    }

    /// Try to grow the arena by adding a new block.
    /// Returns true if growth succeeded.
    fn grow(&self) -> bool {
        let current_slots = self.total_slots.load(Ordering::Acquire);
        if current_slots >= MAX_ARENA_SLOTS {
            return false;
        }

        let mut blocks = self.blocks.lock();
        // Double-check after acquiring lock
        let current_slots = self.total_slots.load(Ordering::Acquire);
        if current_slots >= MAX_ARENA_SLOTS {
            return false;
        }

        // Allocate new block
        let new_block = match ArenaBlock::new(INITIAL_ARENA_SLOTS) {
            Some(b) => b,
            None => return false,
        };

        blocks.push(new_block);
        self.total_slots
            .fetch_add(INITIAL_ARENA_SLOTS, Ordering::Release);

        // Grow data pools proportionally
        {
            let mut pool_4k = self.data_pools[SIZE_CLASS_4K].lock();
            let current = pool_4k.num_buffers;
            let _ = pool_4k.grow(64.min(64 - current));
        }
        {
            let mut pool_16k = self.data_pools[SIZE_CLASS_16K].lock();
            let current = pool_16k.num_buffers;
            let _ = pool_16k.grow(32.min(64 - current));
        }
        {
            let mut pool_64k = self.data_pools[SIZE_CLASS_64K].lock();
            let current = pool_64k.num_buffers;
            let _ = pool_64k.grow(16.min(64 - current));
        }

        true
    }

    /// Allocate a BlkIoRequest from the arena.
    /// Falls back to dynamic allocation if arena is full.
    pub fn alloc(&self, req_type: u32, sector: u64, data_len: u32) -> Option<ArenaBlkIoRequest> {
        // Determine size class
        let size_class = match Self::size_class_for_len(data_len) {
            Some(sc) => sc,
            None => {
                // Data too large for arena, use fallback
                return self.alloc_fallback(req_type, sector, data_len);
            }
        };

        // Try to allocate from arena
        let mut retry_count = 0;
        loop {
            // Try to find a free slot
            let (block_idx, slot_idx) = {
                let blocks = self.blocks.lock();
                let mut found = None;
                for (bi, block) in blocks.iter().enumerate() {
                    if let Some(si) = block.alloc_slot() {
                        found = Some((bi, si));
                        break;
                    }
                }
                match found {
                    Some(f) => f,
                    None => {
                        drop(blocks);
                        // No free slots, try to grow
                        if retry_count < MAX_ARENA_BLOCKS && self.grow() {
                            retry_count += 1;
                            continue;
                        }
                        // Can't grow, use fallback
                        return self.alloc_fallback(req_type, sector, data_len);
                    }
                }
            };

            // Try to allocate data buffer
            let data_buf_idx = {
                let pool = self.data_pools[size_class].lock();
                pool.alloc_buffer()
            };

            let data_buf_idx = match data_buf_idx {
                Some(idx) => idx,
                None => {
                    // Free the slot we just allocated
                    let blocks = self.blocks.lock();
                    blocks[block_idx].free_slot(slot_idx);
                    // Use fallback
                    return self.alloc_fallback(req_type, sector, data_len);
                }
            };

            // Get the slot and buffer info
            let (header_va, header_phys, status_va, status_phys) = {
                let blocks = self.blocks.lock();
                let slot = blocks[block_idx].get_slot(slot_idx);
                (slot.header_va, slot.header_phys, slot.status_va, slot.status_phys)
            };

            let (data_va, data_phys) = {
                let pool = self.data_pools[size_class].lock();
                let buf = pool.get_buffer(data_buf_idx);
                (buf.va, buf.phys)
            };

            // Initialize header
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

            // Zero data buffer
            unsafe {
                core::ptr::write_bytes(data_va.as_u64() as *mut u8, 0, data_len as usize);
            }

            // Initialize status with sentinel
            unsafe {
                core::ptr::write_volatile(status_va.as_u64() as *mut u8, 0xFF);
            }

            self.arena_allocs.fetch_add(1, Ordering::Relaxed);

            return Some(ArenaBlkIoRequest {
                request: BlkIoRequest {
                    header_va,
                    header_phys,
                    data_va,
                    data_phys,
                    data_len,
                    status_va,
                    status_phys,
                },
                handle: Some(ArenaHandle {
                    block_idx: block_idx as u8,
                    slot_idx: slot_idx as u8,
                    data_size_class: size_class as u8,
                    data_buf_idx: data_buf_idx as u8,
                }),
            });
        }
    }

    /// Fallback to dynamic allocation.
    fn alloc_fallback(
        &self,
        req_type: u32,
        sector: u64,
        data_len: u32,
    ) -> Option<ArenaBlkIoRequest> {
        let request = BlkIoRequest::new(req_type, sector, data_len)?;
        self.fallback_allocs.fetch_add(1, Ordering::Relaxed);
        Some(ArenaBlkIoRequest {
            request,
            handle: None,
        })
    }

    /// Free a BlkIoRequest back to the arena.
    pub fn free(&self, req: ArenaBlkIoRequest) {
        match req.handle {
            Some(handle) => {
                // Return slot to block
                {
                    let blocks = self.blocks.lock();
                    blocks[handle.block_idx as usize].free_slot(handle.slot_idx as usize);
                }
                // Return buffer to pool
                {
                    let pool = self.data_pools[handle.data_size_class as usize].lock();
                    pool.free_buffer(handle.data_buf_idx as usize);
                }
            }
            None => {
                // Fallback allocation, destroy normally
                req.request.destroy();
            }
        }
    }
}

// ============================================================================
// ArenaBlkIoRequest Implementation
// ============================================================================

impl ArenaBlkIoRequest {
    /// Read the status byte from the DMA buffer.
    pub fn status(&self) -> u8 {
        self.request.status()
    }

    /// Get a slice view of the data buffer.
    pub fn data_slice(&self) -> &[u8] {
        self.request.data_slice()
    }

    /// Get a mutable slice view of the data buffer.
    pub fn data_slice_mut(&mut self) -> &mut [u8] {
        self.request.data_slice_mut()
    }

    /// Submit the request to the virtqueue.
    pub fn submit(&self, vq: &mut Virtqueue, is_write: bool) -> Option<u16> {
        self.request.submit(vq, is_write)
    }
}
