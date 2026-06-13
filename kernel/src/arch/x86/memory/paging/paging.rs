use crate::arch::drivers::interrupt_index::IpiDest;
use crate::arch::drivers::interrupt_index::IpiKind;
use crate::arch::drivers::interrupt_index::LocalApic;
use crate::arch::drivers::timer_driver::NUM_CORES;
use crate::arch::MAX_CPUS;
use crate::idt::{InterruptGuard, NestedInterruptEnableGuard, TLB_FLUSH_VECTOR};
use crate::{
    arch::drivers::interrupt_index::{current_cpu_id, send_eoi, APIC},
    cpu::get_cpu_info,
    memory::paging::{frame_alloc::BootInfoFrameAllocator, tables::init_mapper},
    util::boot_info,
    KERNEL_INITIALIZED,
};
use core::arch::naked_asm;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use kernel_types::status::PageMapError;
use x86_64::{
    instructions,
    structures::paging::{
        mapper::{MapToError, MapperFlush},
        FrameAllocator, Mapper, Page, PageSize, PageTableFlags, PhysFrame, Size1GiB, Size2MiB,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};

const TLB_SHOOTDOWN_MODE_FULL: usize = 0;
const TLB_SHOOTDOWN_MODE_RANGES: usize = 1;
const TLB_SHOOTDOWN_RANGE_FLUSH_PAGE_LIMIT: u64 = 4096;
const CANONICAL_LOW_END: u64 = 1 << 47;

static TLB_SHOOTDOWN_LOCK: spin::Mutex<()> = spin::Mutex::new(());
static TLB_SHOOTDOWN_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static TLB_SHOOTDOWN_ACKS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static TLB_SHOOTDOWN_MODE: AtomicUsize = AtomicUsize::new(TLB_SHOOTDOWN_MODE_FULL);
static TLB_SHOOTDOWN_RANGES: AtomicPtr<TlbShootdownRange> = AtomicPtr::new(null_mut());
static TLB_SHOOTDOWN_RANGE_COUNT: AtomicUsize = AtomicUsize::new(0);

pub const fn num_frames_4k(size: usize) -> usize {
    ((size + 0xFFF) >> 12)
}

#[derive(Clone, Copy)]
pub(crate) enum TlbFlush {
    Flush,
    Defer,
}

#[derive(Clone, Copy)]
pub struct TlbShootdownRange {
    pub start: VirtAddr,
    pub size: u64,
    page_size: u64,
}

impl TlbShootdownRange {
    pub const fn new(start: VirtAddr, size: u64) -> Self {
        Self {
            start,
            size,
            page_size: Size4KiB::SIZE,
        }
    }

    pub const fn new_2mib(start: VirtAddr, size: u64) -> Self {
        Self {
            start,
            size,
            page_size: Size2MiB::SIZE,
        }
    }
}

#[inline(always)]
fn finish_mapping<S: PageSize>(flush: MapperFlush<S>, mode: TlbFlush) {
    match mode {
        TlbFlush::Flush => flush.flush(),
        TlbFlush::Defer => flush.ignore(),
    }
}

// TODO: it is possible to remove all this unsafe, not urgent.

/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
pub unsafe fn map_range_with_huge_pages<M>(
    mapper: &mut M,
    addr: VirtAddr,
    size: u64,
    fa: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    map_range_with_huge_pages_impl(
        mapper,
        addr,
        size,
        fa,
        flags,
        ignore_already_mapped,
        TlbFlush::Flush,
    )
}

unsafe fn map_range_with_huge_pages_impl<M>(
    mapper: &mut M,
    addr: VirtAddr,
    size: u64,
    fa: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
    ignore_already_mapped: bool,
    flush: TlbFlush,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    let mut cur = addr;
    debug_assert_eq!(cur.as_u64() & 0xFFF, 0);
    let mut remaining = align_up_4k(size);
    let mut mapped = 0u64;
    let gib = 1u64 << 30;
    let mib2 = 2u64 * 1024 * 1024;
    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    while remaining > 0 {
        if supports_1g && remaining >= gib && (cur.as_u64() & (gib - 1)) == 0 {
            match unsafe { map_1gib_page_inner(mapper, cur, flags, fa, flush) } {
                Ok(_) => {
                    cur += gib;
                    remaining -= gib;
                    mapped += gib;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(MapToError::PageAlreadyMapped(_)) if ignore_already_mapped => {
                    cur += gib;
                    remaining -= gib;
                    continue;
                }
                Err(MapToError::ParentEntryHugePage) if ignore_already_mapped => {
                    cur += gib;
                    remaining -= gib;
                    continue;
                }
                Err(e) => {
                    if !ignore_already_mapped {
                        unsafe {
                            rollback_allocated_range_mapping(mapper, fa, addr, mapped);
                        }
                    }
                    return Err(PageMapError::Page1GiB(e.into()));
                }
            };
        }

        if remaining >= mib2 && (cur.as_u64() & (mib2 - 1)) == 0 {
            match unsafe { map_2mib_page_inner(mapper, cur, flags, fa, flush) } {
                Ok(_) => {
                    cur += mib2;
                    remaining -= mib2;
                    mapped += mib2;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(MapToError::PageAlreadyMapped(_)) if ignore_already_mapped => {
                    cur += mib2;
                    remaining -= mib2;
                    continue;
                }
                Err(MapToError::ParentEntryHugePage) if ignore_already_mapped => {
                    cur += mib2;
                    remaining -= mib2;
                    continue;
                }
                Err(e) => {
                    if !ignore_already_mapped {
                        unsafe {
                            rollback_allocated_range_mapping(mapper, fa, addr, mapped);
                        }
                    }
                    return Err(PageMapError::Page2MiB(e.into()));
                }
            };
        }

        let page4k = Page::<Size4KiB>::containing_address(cur);
        match unsafe { map_page_inner(mapper, page4k, fa, flags, flush) } {
            Ok(_) => {}
            Err(MapToError::PageAlreadyMapped(_)) if ignore_already_mapped => {}
            Err(MapToError::ParentEntryHugePage) if ignore_already_mapped => {}
            Err(e) => {
                if !ignore_already_mapped {
                    unsafe {
                        rollback_allocated_range_mapping(mapper, fa, addr, mapped);
                    }
                }
                return Err(PageMapError::Page4KiB(e.into()));
            }
        }
        cur += 0x1000;
        remaining -= 0x1000;
        mapped += 0x1000;
    }

    Ok(())
}

unsafe fn rollback_allocated_range_mapping<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    virt_base: VirtAddr,
    size: u64,
) where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    if size != 0 {
        unsafe {
            unmap_range_with_mapper(
                mapper,
                frame_allocator,
                virt_base,
                size,
                UnmapFrameMode::Accounted,
                TlbFlush::Flush,
            );
        }
    }
}
/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
pub unsafe fn unmap_range_unchecked(virtual_addr: VirtAddr, size: u64) {
    unmap_range_impl(virtual_addr, size)
}
pub(crate) unsafe fn unmap_range_impl(virtual_addr: VirtAddr, size: u64) {
    unmap_range_with_frame_mode(virtual_addr, size, UnmapFrameMode::Accounted)
}

pub(crate) unsafe fn unmap_range_keep_frames_unchecked(virtual_addr: VirtAddr, size: u64) {
    unmap_range_with_frame_mode(virtual_addr, size, UnmapFrameMode::KeepFrames)
}

pub(crate) unsafe fn unmap_reserved_range_unchecked(virtual_addr: VirtAddr, size: u64) {
    unmap_range_with_frame_mode(virtual_addr, size, UnmapFrameMode::Reserved)
}

#[derive(Clone, Copy)]
enum UnmapFrameMode {
    Accounted,
    Reserved,
    KeepFrames,
}

unsafe fn unmap_range_with_frame_mode(virtual_addr: VirtAddr, size: u64, mode: UnmapFrameMode) {
    let boot_info = boot_info();
    let recursive_index = boot_info
        .recursive_index
        .into_option()
        .expect("missing recursive page-table mapping");
    let mut mapper = init_mapper(recursive_index);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    unsafe {
        unmap_range_with_mapper(
            &mut mapper,
            &mut frame_allocator,
            virtual_addr,
            size,
            mode,
            TlbFlush::Flush,
        );
    }
}

unsafe fn unmap_range_with_mapper<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    virtual_addr: VirtAddr,
    size: u64,
    mode: UnmapFrameMode,
    flush_mode: TlbFlush,
) where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    // Constants
    const GI_B: u64 = 1 << 30;
    const MI_B2: u64 = 2 * 1024 * 1024;
    const KI_B4: u64 = 4 * 1024;

    let mut cur = virtual_addr;
    let mut remaining = align_up_4k(size);

    while remaining > 0 {
        // Try 1 GiB page
        if remaining >= GI_B
            && (cur.as_u64() & (GI_B - 1)) == 0
            && unmap_page::<Size1GiB>(mapper, frame_allocator, cur, mode, flush_mode)
        {
            cur += GI_B;
            remaining -= GI_B;
            continue;
        }

        // Try 2 MiB page
        if remaining >= MI_B2
            && (cur.as_u64() & (MI_B2 - 1)) == 0
            && unmap_page::<Size2MiB>(mapper, frame_allocator, cur, mode, flush_mode)
        {
            cur += MI_B2;
            remaining -= MI_B2;
            continue;
        }

        // Fall back to 4 KiB page
        if unmap_page::<Size4KiB>(mapper, frame_allocator, cur, mode, flush_mode) {
            // nothing else to do
        }
        cur += KI_B4;
        remaining -= KI_B4;
    }
}

/// Generic helper for a single unmap + frame free.
/// Returns `true` on success so the caller can adjust its cursors.
fn unmap_page<S: x86_64::structures::paging::page::PageSize>(
    mapper: &mut impl Mapper<S>,
    frame_allocator: &mut BootInfoFrameAllocator,
    addr: VirtAddr,
    mode: UnmapFrameMode,
    flush_mode: TlbFlush,
) -> bool {
    let page = Page::<S>::containing_address(addr);
    match mapper.unmap(page) {
        Ok((frame, flush)) => {
            finish_mapping(flush, flush_mode);
            // SAFETY: the frame is no longer mapped
            match mode {
                UnmapFrameMode::Accounted => frame_allocator.deallocate_frame(frame),
                UnmapFrameMode::Reserved => frame_allocator.release_reserved_frame(frame),
                UnmapFrameMode::KeepFrames => {}
            }
            true
        }
        Err(_) => false,
    }
}
#[inline(always)]
pub const fn align_up_4k(x: u64) -> u64 {
    (x + 0xFFF) & !0xFFF
}
#[inline(always)]
pub const fn align_up_2mib(x: u64) -> u64 {
    const TWO_MIB: u64 = 2 * 1024 * 1024; // 2 MiB
    (x + (TWO_MIB - 1)) & !(TWO_MIB - 1)
}
/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
pub unsafe extern "C" fn identity_map_page(
    phys_addr: PhysAddr,
    range: usize,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let boot_info = boot_info();
    let recursive_index = boot_info
        .recursive_index
        .into_option()
        .ok_or(MapToError::FrameAllocationFailed)?;
    let mut mapper = init_mapper(recursive_index);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
    let page_size = 0x1000;

    let num_pages = (range + 0xFFF) / page_size;
    for i in 0..num_pages {
        let addr = PhysAddr::new(phys_addr.as_u64() + (page_size * i) as u64);
        let page = Page::containing_address(VirtAddr::new(addr.as_u64()));
        let frame = PhysFrame::containing_address(addr);

        unsafe {
            mapper
                .map_to(
                    page,
                    frame,
                    flags | PageTableFlags::PRESENT,
                    &mut frame_allocator,
                )?
                .flush();
        }
    }

    Ok(())
}
unsafe fn map_page_inner(
    mapper: &mut impl Mapper<Size4KiB>,
    page: Page<Size4KiB>,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
    flush: TlbFlush,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    match unsafe { mapper.map_to(page, frame, flags, frame_allocator) } {
        Ok(map_flush) => finish_mapping(map_flush, flush),
        Err(err) => {
            frame_allocator.deallocate_frame(frame);
            return Err(err);
        }
    }
    Ok(())
}

unsafe fn map_existing_frame_inner<S>(
    mapper: &mut impl Mapper<S>,
    addr: VirtAddr,
    phys_addr: PhysAddr,
    flags: PageTableFlags,
    frame_allocator: &mut BootInfoFrameAllocator,
    flush: TlbFlush,
) -> Result<(), MapToError<S>>
where
    S: PageSize,
{
    let page = Page::<S>::containing_address(addr);
    let frame = PhysFrame::<S>::containing_address(phys_addr);
    let effective_flags = if S::SIZE > Size4KiB::SIZE && !flags.contains(PageTableFlags::HUGE_PAGE)
    {
        flags | PageTableFlags::HUGE_PAGE
    } else {
        flags
    };

    let map_flush = unsafe { mapper.map_to(page, frame, effective_flags, frame_allocator) }?;
    finish_mapping(map_flush, flush);
    Ok(())
}

pub(crate) unsafe fn map_contiguous_physical_range<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    virt_base: VirtAddr,
    phys_base: PhysAddr,
    size: u64,
    flags: PageTableFlags,
    flush: TlbFlush,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    let mut cur_virt = virt_base;
    let mut cur_phys = phys_base;
    let mut remaining = align_up_4k(size);
    let mut mapped = 0u64;
    let gib = 1u64 << 30;
    let mib2 = 2u64 * 1024 * 1024;
    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    while remaining > 0 {
        if supports_1g
            && remaining >= gib
            && (cur_virt.as_u64() & (gib - 1)) == 0
            && (cur_phys.as_u64() & (gib - 1)) == 0
        {
            match unsafe {
                map_existing_frame_inner::<Size1GiB>(
                    mapper,
                    cur_virt,
                    cur_phys,
                    flags,
                    frame_allocator,
                    flush,
                )
            } {
                Ok(()) => {
                    cur_virt += gib;
                    cur_phys = PhysAddr::new(cur_phys.as_u64() + gib);
                    remaining -= gib;
                    mapped += gib;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => {
                    unsafe {
                        rollback_existing_range_mapping(mapper, frame_allocator, virt_base, mapped);
                    }
                    return Err(PageMapError::Page1GiB(e.into()));
                }
            }
        }

        if remaining >= mib2
            && (cur_virt.as_u64() & (mib2 - 1)) == 0
            && (cur_phys.as_u64() & (mib2 - 1)) == 0
        {
            match unsafe {
                map_existing_frame_inner::<Size2MiB>(
                    mapper,
                    cur_virt,
                    cur_phys,
                    flags,
                    frame_allocator,
                    flush,
                )
            } {
                Ok(()) => {
                    cur_virt += mib2;
                    cur_phys = PhysAddr::new(cur_phys.as_u64() + mib2);
                    remaining -= mib2;
                    mapped += mib2;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => {
                    unsafe {
                        rollback_existing_range_mapping(mapper, frame_allocator, virt_base, mapped);
                    }
                    return Err(PageMapError::Page2MiB(e.into()));
                }
            }
        }

        match unsafe {
            map_existing_frame_inner::<Size4KiB>(
                mapper,
                cur_virt,
                cur_phys,
                flags,
                frame_allocator,
                flush,
            )
        } {
            Ok(()) => {
                cur_virt += 0x1000;
                cur_phys = PhysAddr::new(cur_phys.as_u64() + 0x1000);
                remaining -= 0x1000;
                mapped += 0x1000;
            }
            Err(e) => {
                unsafe {
                    rollback_existing_range_mapping(mapper, frame_allocator, virt_base, mapped);
                }
                return Err(PageMapError::Page4KiB(e.into()));
            }
        }
    }

    Ok(())
}

unsafe fn rollback_existing_range_mapping<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    virt_base: VirtAddr,
    size: u64,
) where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    if size != 0 {
        unsafe {
            unmap_range_with_mapper(
                mapper,
                frame_allocator,
                virt_base,
                size,
                UnmapFrameMode::KeepFrames,
                TlbFlush::Defer,
            );
        }
    }
}

pub(crate) unsafe fn map_existing_kernel_range(
    addr: VirtAddr,
    phys_addr: PhysAddr,
    size: u64,
    flags: PageTableFlags,
    flush: TlbFlush,
) -> Result<(), PageMapError> {
    let boot_info = boot_info();
    let recursive_index = boot_info.recursive_index.into_option().unwrap();
    let mut mapper = init_mapper(recursive_index);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    unsafe {
        map_contiguous_physical_range(
            &mut mapper,
            &mut frame_allocator,
            addr,
            phys_addr,
            size,
            flags,
            flush,
        )
    }
}

/// Maps missing 2 MiB units in a fixed kernel virtual window.
///
/// `frame_cache` is indexed by 2 MiB unit. A non-zero entry means that unit is
/// already backed and left untouched. New mappings are treated as fresh and do
/// not flush TLB entries; callers must have flushed any previous unmap first.
pub(crate) unsafe fn ensure_kernel_2mib_units_mapped(
    base_addr: VirtAddr,
    start_unit: usize,
    units: usize,
    frame_cache: &mut [usize],
    flags: PageTableFlags,
) -> Result<(), PageMapError> {
    if units == 0 {
        return Ok(());
    }
    let end_unit = start_unit
        .checked_add(units)
        .ok_or(PageMapError::NoMemory())?;
    if end_unit > frame_cache.len() || (base_addr.as_u64() & (Size2MiB::SIZE - 1)) != 0 {
        return Err(PageMapError::TranslationFailed());
    }

    let boot_info = boot_info();
    let recursive_index = boot_info.recursive_index.into_option().unwrap();
    let mut mapper = init_mapper(recursive_index);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let mut unit = start_unit;
    while unit < end_unit {
        if frame_cache[unit] != 0 {
            unit += 1;
            continue;
        }

        let run_start = unit;
        while unit < end_unit && frame_cache[unit] == 0 {
            unit += 1;
        }

        unsafe {
            map_fresh_2mib_unit_run(
                &mut mapper,
                &mut frame_allocator,
                base_addr,
                run_start,
                unit - run_start,
                frame_cache,
                flags,
            )?;
        }
    }

    Ok(())
}

unsafe fn map_fresh_2mib_unit_run<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    base_addr: VirtAddr,
    start_unit: usize,
    units: usize,
    frame_cache: &mut [usize],
    flags: PageTableFlags,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    if let Some(phys_base) = BootInfoFrameAllocator::allocate_contiguous_2mib_frames(units) {
        return unsafe {
            map_fresh_contiguous_2mib_unit_run(
                mapper,
                frame_allocator,
                base_addr,
                start_unit,
                units,
                frame_cache,
                flags,
                phys_base,
            )
        };
    }

    unsafe {
        map_fresh_sparse_2mib_unit_run(
            mapper,
            frame_allocator,
            base_addr,
            start_unit,
            units,
            frame_cache,
            flags,
        )
    }
}

unsafe fn map_fresh_contiguous_2mib_unit_run<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    base_addr: VirtAddr,
    start_unit: usize,
    units: usize,
    frame_cache: &mut [usize],
    flags: PageTableFlags,
    phys_base: PhysAddr,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    let unit_size = Size2MiB::SIZE as usize;
    for offset in 0..units {
        let unit = start_unit + offset;
        let virt = base_addr + (unit * unit_size) as u64;
        let phys = PhysAddr::new(phys_base.as_u64() + (offset * unit_size) as u64);

        match unsafe {
            map_existing_frame_inner::<Size2MiB>(
                mapper,
                virt,
                phys,
                flags,
                frame_allocator,
                TlbFlush::Defer,
            )
        } {
            Ok(()) => frame_cache[unit] = phys.as_u64() as usize,
            Err(e) => {
                unsafe {
                    rollback_2mib_unit_mappings(
                        mapper,
                        frame_allocator,
                        base_addr,
                        start_unit,
                        offset,
                        frame_cache,
                    );
                }
                for free_offset in offset..units {
                    let free_phys =
                        PhysAddr::new(phys_base.as_u64() + (free_offset * unit_size) as u64);
                    frame_allocator
                        .deallocate_frame(PhysFrame::<Size2MiB>::containing_address(free_phys));
                }
                return Err(PageMapError::Page2MiB(e.into()));
            }
        }
    }

    Ok(())
}

unsafe fn map_fresh_sparse_2mib_unit_run<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    base_addr: VirtAddr,
    start_unit: usize,
    units: usize,
    frame_cache: &mut [usize],
    flags: PageTableFlags,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    let unit_size = Size2MiB::SIZE as usize;
    for offset in 0..units {
        let unit = start_unit + offset;
        let Some(frame) =
            <BootInfoFrameAllocator as FrameAllocator<Size2MiB>>::allocate_frame(frame_allocator)
        else {
            unsafe {
                rollback_2mib_unit_mappings(
                    mapper,
                    frame_allocator,
                    base_addr,
                    start_unit,
                    offset,
                    frame_cache,
                );
            }
            return Err(PageMapError::NoMemory());
        };

        let virt = base_addr + (unit * unit_size) as u64;
        let phys = frame.start_address();
        match unsafe {
            map_existing_frame_inner::<Size2MiB>(
                mapper,
                virt,
                phys,
                flags,
                frame_allocator,
                TlbFlush::Defer,
            )
        } {
            Ok(()) => frame_cache[unit] = phys.as_u64() as usize,
            Err(e) => {
                frame_allocator.deallocate_frame(frame);
                unsafe {
                    rollback_2mib_unit_mappings(
                        mapper,
                        frame_allocator,
                        base_addr,
                        start_unit,
                        offset,
                        frame_cache,
                    );
                }
                return Err(PageMapError::Page2MiB(e.into()));
            }
        }
    }

    Ok(())
}

unsafe fn rollback_2mib_unit_mappings<M>(
    mapper: &mut M,
    frame_allocator: &mut BootInfoFrameAllocator,
    base_addr: VirtAddr,
    start_unit: usize,
    units: usize,
    frame_cache: &mut [usize],
) where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    if units == 0 {
        return;
    }

    let unit_size = Size2MiB::SIZE as usize;
    unsafe {
        unmap_range_with_mapper(
            mapper,
            frame_allocator,
            base_addr + (start_unit * unit_size) as u64,
            (units * unit_size) as u64,
            UnmapFrameMode::Accounted,
            TlbFlush::Defer,
        );
    }
    for unit in start_unit..start_unit + units {
        frame_cache[unit] = 0;
    }
}
unsafe fn map_1gib_page_inner<M>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut BootInfoFrameAllocator,
    flush: TlbFlush,
) -> Result<(), MapToError<Size1GiB>>
where
    M: Mapper<Size1GiB>,
{
    let page = Page::<Size1GiB>::containing_address(addr);
    let frame = fa
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;

    let effective_flags = if flags.contains(PageTableFlags::HUGE_PAGE) {
        flags
    } else {
        flags | PageTableFlags::HUGE_PAGE
    };

    match unsafe { mapper.map_to(page, frame, effective_flags, fa) } {
        Ok(map_flush) => finish_mapping(map_flush, flush),
        Err(err) => {
            fa.deallocate_frame(frame);
            return Err(err);
        }
    }
    Ok(())
}
unsafe fn map_2mib_page_inner<M>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut BootInfoFrameAllocator,
    flush: TlbFlush,
) -> Result<(), MapToError<Size2MiB>>
where
    M: Mapper<Size2MiB>,
{
    let page = Page::<Size2MiB>::containing_address(addr);
    let frame = fa
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;

    // ── ensure HUGE_PAGE flag ─────────────────────────────────────────────
    let effective_flags = if flags.contains(PageTableFlags::HUGE_PAGE) {
        flags
    } else {
        flags | PageTableFlags::HUGE_PAGE
    };

    match unsafe { mapper.map_to(page, frame, effective_flags, fa) } {
        Ok(map_flush) => finish_mapping(map_flush, flush),
        Err(err) => {
            fa.deallocate_frame(frame);
            return Err(err);
        }
    }
    Ok(())
}
/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
pub unsafe fn map_kernel_range(
    addr: VirtAddr,
    size: u64,
    flags: PageTableFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    unsafe {
        map_kernel_range_with_flush(addr, size, flags, ignore_already_mapped, TlbFlush::Flush)
    }
}

unsafe fn map_kernel_range_with_flush(
    addr: VirtAddr,
    size: u64,
    flags: PageTableFlags,
    ignore_already_mapped: bool,
    flush: TlbFlush,
) -> Result<(), PageMapError> {
    let boot_info = boot_info();
    let recursive_index = boot_info.recursive_index.into_option().unwrap();
    let mut mapper = init_mapper(recursive_index);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    unsafe {
        map_range_with_huge_pages_impl(
            &mut mapper,
            addr,
            size,
            &mut frame_allocator,
            flags,
            ignore_already_mapped,
            flush,
        )
    }
}

/// SAFETY: Same as `map_kernel_range`. This skips TLB invalidation and is only
/// valid for fresh virtual ranges that have not been accessed while unmapped.
pub unsafe fn map_fresh_kernel_range_no_flush(
    addr: VirtAddr,
    size: u64,
    flags: PageTableFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    unsafe {
        map_kernel_range_with_flush(addr, size, flags, ignore_already_mapped, TlbFlush::Defer)
    }
}

#[inline(always)]
fn tlb_range_bounds(range: TlbShootdownRange) -> Option<(u64, u64)> {
    let start = range.start.as_u64() & !(range.page_size - 1);
    if range.size == 0 {
        return Some((start, start));
    }

    let end_unaligned = range.start.as_u64().checked_add(range.size)?;
    let end = end_unaligned
        .checked_add(range.page_size - 1)
        .map(|x| x & !(range.page_size - 1))?;
    if end < start || (start < CANONICAL_LOW_END && end > CANONICAL_LOW_END) {
        return None;
    }

    Some((start, end))
}

#[inline(always)]
fn tlb_range_page_count(range: TlbShootdownRange) -> Option<u64> {
    let (start, end) = tlb_range_bounds(range)?;
    Some((end - start) / range.page_size)
}

fn tlb_ranges_page_count(ranges: &[TlbShootdownRange]) -> Option<u64> {
    let mut total = 0u64;
    for range in ranges {
        total = total.checked_add(tlb_range_page_count(*range)?)?;
    }
    Some(total)
}

fn should_flush_all_for_tlb_ranges(ranges: &[TlbShootdownRange]) -> bool {
    match tlb_ranges_page_count(ranges) {
        Some(pages) => pages > TLB_SHOOTDOWN_RANGE_FLUSH_PAGE_LIMIT,
        None => true,
    }
}

fn flush_tlb_range(range: TlbShootdownRange) -> bool {
    let Some((mut addr, end)) = tlb_range_bounds(range) else {
        return false;
    };

    while addr < end {
        let Ok(virt) = VirtAddr::try_new(addr) else {
            return false;
        };
        instructions::tlb::flush(virt);
        let Some(next) = addr.checked_add(range.page_size) else {
            return false;
        };
        addr = next;
    }

    true
}

fn flush_tlb_ranges_or_all(ranges: &[TlbShootdownRange]) {
    if should_flush_all_for_tlb_ranges(ranges) {
        instructions::tlb::flush_all();
        return;
    }

    for range in ranges {
        if !flush_tlb_range(*range) {
            instructions::tlb::flush_all();
            return;
        }
    }
}

fn flush_tlb_shootdown_request(ranges: Option<&[TlbShootdownRange]>) {
    match ranges {
        Some(ranges) => flush_tlb_ranges_or_all(ranges),
        None => instructions::tlb::flush_all(),
    }
}

fn clear_tlb_shootdown_request() {
    TLB_SHOOTDOWN_MODE.store(TLB_SHOOTDOWN_MODE_FULL, Ordering::SeqCst);
    TLB_SHOOTDOWN_RANGES.store(null_mut(), Ordering::SeqCst);
    TLB_SHOOTDOWN_RANGE_COUNT.store(0, Ordering::SeqCst);
}

fn flush_current_tlb_shootdown_request() {
    if TLB_SHOOTDOWN_MODE.load(Ordering::SeqCst) != TLB_SHOOTDOWN_MODE_RANGES {
        instructions::tlb::flush_all();
        return;
    }

    let count = TLB_SHOOTDOWN_RANGE_COUNT.load(Ordering::SeqCst);
    if count == 0 {
        return;
    }

    let ptr = TLB_SHOOTDOWN_RANGES.load(Ordering::SeqCst);
    if ptr.is_null() {
        instructions::tlb::flush_all();
        return;
    }

    let ranges = unsafe { core::slice::from_raw_parts(ptr as *const TlbShootdownRange, count) };
    flush_tlb_ranges_or_all(ranges);
}

extern "C" fn tlb_flush_ipi() {
    let _guard = InterruptGuard::new();
    //let _nested_interrupts = NestedInterruptEnableGuard::new();
    flush_current_tlb_shootdown_request();
    let cpu = current_cpu_id();
    if cpu < MAX_CPUS {
        let sequence = TLB_SHOOTDOWN_SEQUENCE.load(Ordering::SeqCst);
        TLB_SHOOTDOWN_ACKS[cpu].store(sequence, Ordering::SeqCst);
    }
    send_eoi(TLB_FLUSH_VECTOR);
}
#[unsafe(naked)]
pub extern "C" fn tlb_flush_entry() {
    naked_asm!(
        "cli",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",

        "mov  rcx, rsp",
        "mov  rbx, rsp",
        "cld",
        "and  rsp, -16",
        "sub  rsp, 32",
        "call {handler}",
        "mov  rsp, rbx",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",
        handler = sym tlb_flush_ipi,
    );
}

pub fn trigger_tlb_shootdown() {
    trigger_tlb_shootdown_request(None);
}

pub fn trigger_tlb_shootdown_range(start: VirtAddr, size: u64) {
    let range = TlbShootdownRange::new(start, size);
    trigger_tlb_shootdown_ranges(core::slice::from_ref(&range));
}

pub fn trigger_tlb_shootdown_ranges(ranges: &[TlbShootdownRange]) {
    if matches!(tlb_ranges_page_count(ranges), Some(0)) {
        return;
    }
    trigger_tlb_shootdown_request(Some(ranges));
}

fn trigger_tlb_shootdown_request(ranges: Option<&[TlbShootdownRange]>) {
    let cpu_count = NUM_CORES.load(Ordering::Acquire);
    if cpu_count <= 1 || !KERNEL_INITIALIZED.load(Ordering::Acquire) {
        flush_tlb_shootdown_request(ranges);
        return;
    }

    assert!(
        cpu_count <= MAX_CPUS,
        "TLB shootdown CPU count {} exceeds ack table size {}",
        cpu_count,
        MAX_CPUS
    );
    assert!(
        instructions::interrupts::are_enabled(),
        "synchronous TLB shootdown attempted with interrupts disabled"
    );

    let _guard = TLB_SHOOTDOWN_LOCK.lock();
    match ranges {
        Some(ranges) => {
            TLB_SHOOTDOWN_RANGES.store(ranges.as_ptr() as *mut TlbShootdownRange, Ordering::SeqCst);
            TLB_SHOOTDOWN_RANGE_COUNT.store(ranges.len(), Ordering::SeqCst);
            TLB_SHOOTDOWN_MODE.store(TLB_SHOOTDOWN_MODE_RANGES, Ordering::SeqCst);
        }
        None => clear_tlb_shootdown_request(),
    }

    let sequence = TLB_SHOOTDOWN_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1;
    let current_cpu = current_cpu_id();

    let mut sent = false;
    unsafe {
        if let Some(a) = APIC.lock().as_ref() {
            a.lapic.send_ipi(
                IpiDest::AllExcludingSelf,
                IpiKind::Fixed {
                    vector: TLB_FLUSH_VECTOR,
                },
            );
            sent = true;
        }
    }
    flush_tlb_shootdown_request(ranges);
    if current_cpu < MAX_CPUS {
        TLB_SHOOTDOWN_ACKS[current_cpu].store(sequence, Ordering::SeqCst);
    }

    if !sent {
        clear_tlb_shootdown_request();
        return;
    }

    for cpu in 0..cpu_count {
        if cpu == current_cpu {
            continue;
        }

        while TLB_SHOOTDOWN_ACKS[cpu].load(Ordering::SeqCst) < sequence {
            core::hint::spin_loop();
        }
    }

    clear_tlb_shootdown_request();
}
