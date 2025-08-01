use core::sync::atomic::AtomicUsize;
use alloc::sync::Arc;
use x86_64::{structures::paging::PageTableFlags, VirtAddr};
use crate::{memory::paging::{constants::{MANAGED_KERNEL_RANGE_END, MANAGED_KERNEL_RANGE_START}, frame_alloc::BootInfoFrameAllocator, paging::{align_up_4k, map_range_with_huge_pages, unmap_range_impl, PageMapError}, tables::init_mapper}, structs::range_tracker::{RangeAllocationError, RangeTracker}, util::boot_info};
use lazy_static::lazy_static;


pub(crate) const MAX_PENDING_FREES: usize = 64;
static mut PENDING_FREES: [Option<(u64, u64)>; MAX_PENDING_FREES] = [None; MAX_PENDING_FREES];
static PENDING_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    pub static ref KERNEL_RANGE_TRACKER: Arc<RangeTracker> = Arc::new(RangeTracker::new(
        MANAGED_KERNEL_RANGE_START,
        MANAGED_KERNEL_RANGE_END,
    ));
}

/// Any‑address allocation, but start and length are both 4 KiB‑aligned.
pub fn allocate_auto_kernel_range(size: u64) -> Option<VirtAddr> {
    let aligned_size = align_up_4k(size); // round length up
    let addr = KERNEL_RANGE_TRACKER.alloc_auto(aligned_size)?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0); // start aligned
    Some(addr)
}

/// Fixed‑address allocation; reject unaligned `base`, round size up to 4 KiB.
pub fn allocate_kernel_range(base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
    if base & 0xFFF != 0 {
        return Err(RangeAllocationError::Unaligned);
    }
    let aligned_size = align_up_4k(size);
    let addr = KERNEL_RANGE_TRACKER.alloc(base, aligned_size)?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);
    Ok(addr)
}
pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    let align_size = align_up_4k(size);
    let addr = allocate_auto_kernel_range(align_size).ok_or(PageMapError::NoMemory())?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    map_range_with_huge_pages(&mut mapper, addr, align_size, &mut frame_allocator, flags)?;
    Ok(addr)
}

pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    let align_size = align_up_4k(size);
    debug_assert_eq!(base & 0xFFF, 0);

    let addr = allocate_kernel_range(base, align_size).map_err(|_| PageMapError::NoMemory())?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    map_range_with_huge_pages(&mut mapper, addr, align_size, &mut frame_allocator, flags)?;
    Ok(addr)
}

pub fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);
    let aligned_size = align_up_4k(size);
    KERNEL_RANGE_TRACKER.dealloc(addr.as_u64(), aligned_size);
}

pub fn unmap_range(virtual_addr: VirtAddr, size: u64) {
    deallocate_kernel_range(virtual_addr, size);

    unsafe { unmap_range_impl(virtual_addr, size) };
}