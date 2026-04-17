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
    structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB},
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

    // Pick alignment so huge pages can be used when the allocation is large enough.
    const FRAMES_PER_2M: usize = 512; // 2MiB / 4KiB
    const FRAMES_PER_1G: usize = 262144; // 1GiB / 4KiB
    let (virt_align, phys_align_frames) = if num_pages >= FRAMES_PER_1G {
        (1u64 << 30, FRAMES_PER_1G)
    } else if num_pages >= FRAMES_PER_2M {
        (2u64 << 20, FRAMES_PER_2M)
    } else {
        (0x1000u64, 1)
    };

    let addr = allocate_auto_kernel_range_aligned(align_size, virt_align)
        .ok_or(PageMapError::NoMemory())?;

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let phys_base =
        BootInfoFrameAllocator::allocate_contiguous_frames_aligned(num_pages, phys_align_frames)
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

    if alignment < 0x1000 {
        return None;
    }
    if (alignment & (alignment - 1)) != 0 {
        return None;
    }
    if (alignment & 0xFFF) != 0 {
        return None;
    }

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
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    use crate::cpu::get_cpu_info;

    let mut cur_virt = virt_base.as_u64();
    let mut cur_phys = phys_base.as_u64();
    let mut remaining = align_up_4k(size);
    let gib = 1u64 << 30;
    let mib2 = 2u64 << 20;
    let huge_flags = flags | PageTableFlags::HUGE_PAGE;
    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    while remaining > 0 {
        if supports_1g
            && remaining >= gib
            && (cur_virt & (gib - 1)) == 0
            && (cur_phys & (gib - 1)) == 0
        {
            let page = Page::<Size1GiB>::containing_address(VirtAddr::new(cur_virt));
            let frame = PhysFrame::<Size1GiB>::containing_address(PhysAddr::new(cur_phys));
            unsafe {
                mapper
                    .map_to(page, frame, huge_flags, frame_allocator)
                    .map_err(PageMapError::Page1GiB)?
                    .flush();
            }
            cur_virt += gib;
            cur_phys += gib;
            remaining -= gib;
            continue;
        }

        if remaining >= mib2 && (cur_virt & (mib2 - 1)) == 0 && (cur_phys & (mib2 - 1)) == 0 {
            let page = Page::<Size2MiB>::containing_address(VirtAddr::new(cur_virt));
            let frame = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(cur_phys));
            unsafe {
                mapper
                    .map_to(page, frame, huge_flags, frame_allocator)
                    .map_err(PageMapError::Page2MiB)?
                    .flush();
            }
            cur_virt += mib2;
            cur_phys += mib2;
            remaining -= mib2;
            continue;
        }

        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(cur_virt));
        let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(cur_phys));
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
