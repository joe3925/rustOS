use crate::{
    memory::paging::{
        constants::{MANAGED_KERNEL_RANGE_END, MANAGED_KERNEL_RANGE_START},
        frame_alloc::BootInfoFrameAllocator,
        paging::{align_up_4k, map_range_with_huge_pages, unmap_range_impl},
        tables::init_mapper,
    },
    structs::range_tracker::{RangeAllocationError, RangeTracker},
    util::boot_info,
};
use alloc::sync::Arc;
use core::sync::atomic::AtomicUsize;
use kernel_types::status::PageMapError;
use lazy_static::lazy_static;
use x86_64::{
    structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

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
pub extern "win64" fn allocate_auto_kernel_range_mapped(
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

    unsafe {
        map_range_with_huge_pages(&mut mapper, addr, align_size, &mut frame_allocator, flags)
    }?;
    Ok(addr)
}

pub extern "win64" fn allocate_auto_kernel_range_mapped_contiguous(
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    let align_size = align_up_4k(size);
    if align_size == 0 {
        return Err(PageMapError::NoMemory());
    }

    let num_pages = (align_size / 0x1000) as usize;
    let addr = allocate_auto_kernel_range(align_size).ok_or(PageMapError::NoMemory())?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let phys_base = BootInfoFrameAllocator::allocate_contiguous_frames(num_pages)
        .ok_or(PageMapError::NoMemory())?;

    map_contiguous_range(
        &mut mapper,
        &mut frame_allocator,
        addr,
        phys_base,
        align_size,
        flags,
    )?;

    Ok(addr)
}

pub extern "win64" fn allocate_kernel_range_mapped(
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

    unsafe {
        map_range_with_huge_pages(&mut mapper, addr, align_size, &mut frame_allocator, flags)
    }?;
    Ok(addr)
}
/// Allocate with specific alignment requirement
pub fn allocate_auto_kernel_range_aligned(size: u64, alignment: u64) -> Option<VirtAddr> {
    let aligned_size = align_up_4k(size);

    if alignment > 0x1000 {
        let extra = alignment - 0x1000;
        let total_request = aligned_size + extra;

        let addr = KERNEL_RANGE_TRACKER.alloc_auto(total_request)?;

        let aligned_addr = (addr.as_u64() + alignment - 1) & !(alignment - 1);

        let wasted_before = aligned_addr - addr.as_u64();

        if wasted_before > 0 {
            KERNEL_RANGE_TRACKER.dealloc(addr.as_u64(), wasted_before);
        }

        let wasted_after = extra - wasted_before;
        if wasted_after > 0 {
            let suffix_start = aligned_addr + aligned_size;
            KERNEL_RANGE_TRACKER.dealloc(suffix_start, wasted_after);
        }

        Some(VirtAddr::new(aligned_addr))
    } else {
        let addr = KERNEL_RANGE_TRACKER.alloc_auto(aligned_size)?;
        debug_assert_eq!(addr.as_u64() & 0xFFF, 0);
        Some(addr)
    }
}

pub fn allocate_auto_kernel_range_mapped_aligned(
    size: u64,
    alignment: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    let align_size = align_up_4k(size);
    let addr =
        allocate_auto_kernel_range_aligned(align_size, alignment).ok_or(PageMapError::NoMemory())?;

    debug_assert_eq!(addr.as_u64() & (alignment - 1), 0, "Alignment violated");

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    unsafe {
        map_range_with_huge_pages(&mut mapper, addr, align_size, &mut frame_allocator, flags)
    }?;
    Ok(addr)
}
pub extern "win64" fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);
    let aligned_size = align_up_4k(size);
    KERNEL_RANGE_TRACKER.dealloc(addr.as_u64(), aligned_size);
}

pub extern "win64" fn unmap_range(virtual_addr: VirtAddr, size: u64) {
    deallocate_kernel_range(virtual_addr, size);

    unsafe { unmap_range_impl(virtual_addr, size) };
}

fn map_contiguous_range<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    virt_base: VirtAddr,
    phys_base: PhysAddr,
    size: u64,
    flags: PageTableFlags,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB>,
{
    let mut cur_virt = virt_base;
    let mut cur_phys = phys_base;
    let mut remaining = align_up_4k(size);

    while remaining > 0 {
        let page = Page::<Size4KiB>::containing_address(cur_virt);
        let frame = PhysFrame::containing_address(cur_phys);

        unsafe {
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(PageMapError::Page4KiB)?
                .flush();
        }

        cur_virt += 0x1000;
        cur_phys += 0x1000;
        remaining -= 0x1000;
    }

    Ok(())
}
