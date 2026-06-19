use spin::Mutex;

use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;

use super::layout::{align_down, align_up_to_base_page, base_page_size, largest_mapping_size_for};
use super::map::{map_contiguous_physical_range, unmap_range_keep_frames_unchecked};
use super::types::LocalTlbFlush;
use super::virt_tracker::{allocate_auto_kernel_range_aligned, deallocate_kernel_range};

static MMIO_MAP_LOCK: Mutex<()> = Mutex::new(());

pub fn map_physical_pages(
    phys: PhysAddr,
    size: u64,
    cache: PhysicalMappingCache,
) -> Result<VirtAddr, PageMapError> {
    let base_page = base_page_size();
    let phys_addr = phys.as_u64();
    let off = phys_addr % base_page;
    let aligned_phys = phys_addr - off;
    let total_size = align_up_to_base_page(size + off).ok_or(PageMapError::TranslationFailed())?;

    let va_alignment = largest_mapping_size_for(total_size, Some(aligned_phys));
    map_physical_pages_aligned(phys, size, va_alignment, cache)
}

pub fn map_physical_pages_aligned(
    phys: PhysAddr,
    size: u64,
    va_alignment: u64,
    cache: PhysicalMappingCache,
) -> Result<VirtAddr, PageMapError> {
    let _lock = MMIO_MAP_LOCK.lock();

    if size == 0 {
        return Err(PageMapError::TranslationFailed());
    }

    let base_page = base_page_size();
    if va_alignment < base_page || !va_alignment.is_power_of_two() || va_alignment % base_page != 0
    {
        return Err(PageMapError::TranslationFailed());
    }

    let phys_addr = phys.as_u64();
    let off = phys_addr % base_page;
    let aligned_phys = align_down(phys_addr, base_page).ok_or(PageMapError::TranslationFailed())?;
    let total_size = align_up_to_base_page(size + off).ok_or(PageMapError::TranslationFailed())?;

    let virtual_addr = allocate_auto_kernel_range_aligned(total_size, va_alignment)
        .ok_or(PageMapError::NoMemory())?;

    let flags = PageFlags::PRESENT | PageFlags::WRITABLE;
    if let Err(err) = unsafe {
        map_contiguous_physical_range(
            virtual_addr,
            PhysAddr::new(aligned_phys),
            total_size,
            flags,
            Some(cache),
            LocalTlbFlush::Flush,
        )
    } {
        deallocate_kernel_range(virtual_addr, total_size);
        return Err(err);
    }

    Ok(VirtAddr::new(virtual_addr.as_u64() + off))
}

pub fn unmap_physical_pages(base: VirtAddr, size: u64) -> Result<(), PageMapError> {
    let _lock = MMIO_MAP_LOCK.lock();

    if size == 0 {
        return Ok(());
    }

    let base_page = base_page_size();
    let off = base.as_u64() % base_page;
    let start = VirtAddr::new(base.as_u64() - off);
    let total = align_up_to_base_page(size + off).ok_or(PageMapError::TranslationFailed())?;

    unsafe {
        unmap_range_keep_frames_unchecked(start, total);
    }
    deallocate_kernel_range(start, total);

    Ok(())
}
