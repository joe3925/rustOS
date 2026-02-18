use core::sync::atomic::AtomicU64;
use spin::Mutex;

use kernel_types::status::PageMapError;
use x86_64::{
    structures::paging::{
        mapper::MapToError, Mapper as _, Page, PageTableFlags, PhysFrame, Size1GiB, Size2MiB,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    cpu::get_cpu_info,
    memory::paging::{
        constants::MMIO_BASE, frame_alloc::BootInfoFrameAllocator, paging::align_up_4k,
        tables::init_mapper, virt_tracker::allocate_auto_kernel_range_aligned,
    },
    util::boot_info,
};

static NEXT_MMIO_VADDR: AtomicU64 = AtomicU64::new(MMIO_BASE);
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

pub extern "win64" fn map_mmio_region(
    mmio_base: PhysAddr,
    mmio_size: u64,
) -> Result<VirtAddr, PageMapError> {
    let phys_addr = mmio_base.as_u64();
    let off = phys_addr & 0xFFF;
    let aligned_phys = phys_addr - off;
    let total_size = align_up_4k(mmio_size + off);

    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    let va_align = choose_mmio_va_alignment(aligned_phys, total_size, supports_1g);
    map_mmio_region_aligned(mmio_base, mmio_size, va_align)
}

pub extern "win64" fn map_mmio_region_aligned(
    mmio_base: PhysAddr,
    mmio_size: u64,
    va_alignment: u64,
) -> Result<VirtAddr, PageMapError> {
    let _lock = MMIO_MAP_LOCK.lock();

    if mmio_size == 0 {
        return Err(PageMapError::TranslationFailed());
    }
    if !is_valid_mmio_va_alignment(va_alignment) {
        return Err(PageMapError::TranslationFailed());
    }

    let phys_addr = mmio_base.as_u64();
    let off = phys_addr & 0xFFF;
    let aligned_phys = phys_addr - off;
    let total_size = align_up_4k(mmio_size + off);

    let virtual_addr = allocate_auto_kernel_range_aligned(total_size, va_alignment)
        .ok_or(PageMapError::NoMemory())?;

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    let base_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

    let mut cur_v = virtual_addr;
    let mut cur_p = aligned_phys;
    let mut remaining = total_size;

    while remaining > 0 {
        if supports_1g
            && remaining >= GIB
            && (cur_v.as_u64() & (GIB - 1)) == 0
            && (cur_p & (GIB - 1)) == 0
        {
            let page: Page<Size1GiB> = Page::containing_address(cur_v);
            let frame: PhysFrame<Size1GiB> = PhysFrame::containing_address(PhysAddr::new(cur_p));
            match unsafe {
                mapper.map_to(
                    page,
                    frame,
                    base_flags | PageTableFlags::HUGE_PAGE,
                    &mut frame_allocator,
                )
            } {
                Ok(flush) => {
                    flush.flush();
                    cur_v += GIB;
                    cur_p += GIB;
                    remaining -= GIB;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => return Err(PageMapError::Page1GiB(e)),
            }
        }

        if remaining >= MIB2 && (cur_v.as_u64() & (MIB2 - 1)) == 0 && (cur_p & (MIB2 - 1)) == 0 {
            let page: Page<Size2MiB> = Page::containing_address(cur_v);
            let frame: PhysFrame<Size2MiB> = PhysFrame::containing_address(PhysAddr::new(cur_p));
            match unsafe {
                mapper.map_to(
                    page,
                    frame,
                    base_flags | PageTableFlags::HUGE_PAGE,
                    &mut frame_allocator,
                )
            } {
                Ok(flush) => {
                    flush.flush();
                    cur_v += MIB2;
                    cur_p += MIB2;
                    remaining -= MIB2;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => return Err(PageMapError::Page2MiB(e)),
            }
        }

        let page: Page<Size4KiB> = Page::containing_address(cur_v);
        let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(PhysAddr::new(cur_p));
        unsafe {
            mapper
                .map_to(page, frame, base_flags, &mut frame_allocator)?
                .flush();
        }

        cur_v += KIB4;
        cur_p += KIB4;
        remaining -= KIB4;
    }

    Ok(VirtAddr::new(virtual_addr.as_u64() + off))
}

pub fn unmap_mmio_region(base: VirtAddr, size: u64) -> Result<(), PageMapError> {
    let _lock = MMIO_MAP_LOCK.lock();

    if size == 0 {
        return Ok(());
    }

    let off = base.as_u64() & 0xFFF;
    let start = VirtAddr::new(base.as_u64() - off);
    let total = align_up_4k(size + off);

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("missing phys-mem offset"),
    );

    let mut mapper = init_mapper(phys_mem_offset);

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
