use spin::Mutex;

use kernel_types::arch::{PageFlags, PhysAddr};
use kernel_types::memory::KernelMapping;
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;

use super::layout::{base_page_size, largest_mapping_size_for};
use super::map::map_physical_into_reservation;
use super::virt_tracker::reserve_auto_kernel_range_aligned;

static MMIO_MAP_LOCK: Mutex<()> = Mutex::new(());

pub fn map_physical_pages(
    phys: PhysAddr,
    size: u64,
    cache: PhysicalMappingCache,
) -> Result<KernelMapping, PageMapError> {
    let va_alignment = largest_mapping_size_for(size, Some(phys.as_u64()));
    map_physical_pages_aligned(phys, size, va_alignment, cache)
}

pub fn map_physical_pages_aligned(
    phys: PhysAddr,
    size: u64,
    va_alignment: u64,
    cache: PhysicalMappingCache,
) -> Result<KernelMapping, PageMapError> {
    let _lock = MMIO_MAP_LOCK.lock();

    if size == 0 {
        return Err(PageMapError::TranslationFailed());
    }

    let base_page = base_page_size();
    if va_alignment < base_page || !va_alignment.is_power_of_two() || va_alignment % base_page != 0
    {
        return Err(PageMapError::TranslationFailed());
    }

    if phys.as_u64() % base_page != 0 || size % base_page != 0 {
        return Err(PageMapError::TranslationFailed());
    }

    let flags = PageFlags::PRESENT | PageFlags::WRITABLE;
    let reservation = reserve_auto_kernel_range_aligned(size, va_alignment)
        .map_err(|_| PageMapError::NoMemory())?;
    map_physical_into_reservation(reservation, 0, phys, size, flags, Some(cache))
        .map_err(|(_, err)| err)
}
