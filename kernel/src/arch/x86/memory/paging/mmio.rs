use spin::Mutex;

use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;
use x86_64::{
    structures::paging::{Mapper as _, Page, PageTableFlags, Size1GiB, Size2MiB, Size4KiB},
    PhysAddr, VirtAddr,
};

use crate::{
    cpu::get_cpu_info,
    memory::paging::{
        frame_alloc::BootInfoFrameAllocator,
        paging::{align_up_4k, map_contiguous_physical_range, TlbFlush},
        tables::init_mapper,
        virt_tracker::{allocate_auto_kernel_range_aligned, deallocate_kernel_range},
    },
    util::boot_info,
};

static MMIO_MAP_LOCK: Mutex<()> = Mutex::new(());

const GIB: u64 = 1 << 30;
const MIB2: u64 = 2 * 1024 * 1024;
const KIB4: u64 = 4 * 1024;

#[inline(always)]
fn is_pow2(x: u64) -> bool {
    x != 0 && (x & (x - 1)) == 0
}

#[inline(always)]
fn is_valid_mmio_va_alignment(x: u64) -> bool {
    is_pow2(x) && x >= KIB4 && (x & (KIB4 - 1)) == 0
}

#[inline(always)]
fn choose_mmio_va_alignment(aligned_phys: u64, total_size: u64, supports_1g: bool) -> u64 {
    if supports_1g && total_size >= GIB && (aligned_phys & (GIB - 1)) == 0 {
        return GIB;
    }
    if total_size >= MIB2 && (aligned_phys & (MIB2 - 1)) == 0 {
        return MIB2;
    }
    KIB4
}

fn cache_to_flags(cache: PhysicalMappingCache) -> PageTableFlags {
    match cache {
        PhysicalMappingCache::Cached => PageTableFlags::empty(),
        PhysicalMappingCache::WriteCombining => {
            PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH
        }
        PhysicalMappingCache::Uncached => PageTableFlags::NO_CACHE,
    }
}

pub extern "C" fn map_physical_pages(
    phys: PhysAddr,
    size: u64,
    cache: PhysicalMappingCache,
) -> Result<VirtAddr, PageMapError> {
    let phys_addr = phys.as_u64();
    let off = phys_addr & 0xFFF;
    let aligned_phys = phys_addr - off;
    let total_size = align_up_4k(size + off);

    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    let va_align = choose_mmio_va_alignment(aligned_phys, total_size, supports_1g);
    map_physical_pages_aligned(phys, size, va_align, cache)
}

pub extern "C" fn map_physical_pages_aligned(
    phys: PhysAddr,
    size: u64,
    va_alignment: u64,
    cache: PhysicalMappingCache,
) -> Result<VirtAddr, PageMapError> {
    let _lock = MMIO_MAP_LOCK.lock();

    if size == 0 {
        return Err(PageMapError::TranslationFailed());
    }
    if !is_valid_mmio_va_alignment(va_alignment) {
        return Err(PageMapError::TranslationFailed());
    }

    let phys_addr = phys.as_u64();
    let off = phys_addr & 0xFFF;
    let aligned_phys = phys_addr - off;
    let total_size = align_up_4k(size + off);

    let virtual_addr = allocate_auto_kernel_range_aligned(total_size, va_alignment)
        .ok_or(PageMapError::NoMemory())?;

    let boot_info = boot_info();
    let recursive_index = boot_info
        .recursive_index
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;
    let mut mapper = init_mapper(recursive_index);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let base_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | cache_to_flags(cache);
    if let Err(err) = unsafe {
        map_contiguous_physical_range(
            &mut mapper,
            &mut frame_allocator,
            virtual_addr,
            PhysAddr::new(aligned_phys),
            total_size,
            base_flags,
            TlbFlush::Flush,
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

    let off = base.as_u64() & 0xFFF;
    let start = VirtAddr::new(base.as_u64() - off);
    let total = align_up_4k(size + off);

    let boot_info = boot_info();
    let recursive_index = boot_info
        .recursive_index
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;
    let mut mapper = init_mapper(recursive_index);

    let mut cur = start;
    let mut remaining = total;

    while remaining > 0 {
        if remaining >= GIB && (cur.as_u64() & (GIB - 1)) == 0 {
            let page = Page::<Size1GiB>::containing_address(cur);
            if let Ok((_frame, flush)) = mapper.unmap(page) {
                flush.flush();
                cur += GIB;
                remaining -= GIB;
                continue;
            }
        }

        if remaining >= MIB2 && (cur.as_u64() & (MIB2 - 1)) == 0 {
            let page = Page::<Size2MiB>::containing_address(cur);
            if let Ok((_frame, flush)) = mapper.unmap(page) {
                flush.flush();
                cur += MIB2;
                remaining -= MIB2;
                continue;
            }
        }

        let page = Page::<Size4KiB>::containing_address(cur);
        if let Ok((_frame, flush)) = mapper.unmap(page) {
            flush.flush();
        }

        cur += KIB4;
        remaining -= KIB4;
    }

    Ok(())
}
