use crate::drivers::interrupt_index::IpiDest;
use crate::drivers::interrupt_index::IpiKind;
use crate::drivers::interrupt_index::LocalApic;
use crate::idt::TLB_FLUSH_VECTOR;
use crate::{
    cpu::get_cpu_info,
    drivers::interrupt_index::{send_eoi, APIC},
    memory::paging::{frame_alloc::BootInfoFrameAllocator, tables::init_mapper},
    util::boot_info,
};
use core::arch::naked_asm;
use kernel_types::status::PageMapError;
use x86_64::{
    instructions,
    structures::paging::{
        mapper::MapToError, FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size1GiB,
        Size2MiB, Size4KiB,
    },
    PhysAddr, VirtAddr,
};
pub const fn num_frames_4k(size: usize) -> usize {
    ((size + 0xFFF) >> 12)
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
    map_range_with_huge_pages_impl(mapper, addr, size, fa, flags, ignore_already_mapped, true)
}

/// SAFETY: Same as `map_range_with_huge_pages`. The caller must only use this
/// for fresh virtual ranges that have not been accessed since they became
/// unmapped, so there cannot be a stale present TLB entry.
pub unsafe fn map_fresh_range_with_huge_pages_no_flush<M>(
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
    map_range_with_huge_pages_impl(mapper, addr, size, fa, flags, ignore_already_mapped, false)
}

unsafe fn map_range_with_huge_pages_impl<M>(
    mapper: &mut M,
    addr: VirtAddr,
    size: u64,
    fa: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
    ignore_already_mapped: bool,
    flush_each: bool,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    let mut cur = addr;
    debug_assert_eq!(cur.as_u64() & 0xFFF, 0);
    let mut remaining = align_up_4k(size);
    let gib = 1u64 << 30;
    let mib2 = 2u64 * 1024 * 1024;
    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    while remaining > 0 {
        if supports_1g && remaining >= gib && (cur.as_u64() & (gib - 1)) == 0 {
            match unsafe { map_1gib_page_inner(mapper, cur, flags, fa, flush_each) } {
                Ok(_) => {
                    cur += gib;
                    remaining -= gib;
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
                    return Err(PageMapError::Page1GiB(e));
                }
            };
        }

        if remaining >= mib2 && (cur.as_u64() & (mib2 - 1)) == 0 {
            match unsafe { map_2mib_page_inner(mapper, cur, flags, fa, flush_each) } {
                Ok(_) => {
                    cur += mib2;
                    remaining -= mib2;
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
                    return Err(PageMapError::Page2MiB(e));
                }
            };
        }

        let page4k = Page::<Size4KiB>::containing_address(cur);
        match unsafe { map_page_inner(mapper, page4k, fa, flags, flush_each) } {
            Ok(_) => {}
            Err(MapToError::PageAlreadyMapped(_)) if ignore_already_mapped => {}
            Err(MapToError::ParentEntryHugePage) if ignore_already_mapped => {}
            Err(e) => return Err(PageMapError::Page4KiB(e)),
        }
        cur += 0x1000;
        remaining -= 0x1000;
    }

    Ok(())
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
    let phys_mem_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("missing phys‑mem offset"),
    );

    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

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
            && unmap_page::<Size1GiB>(&mut mapper, &mut frame_allocator, cur, mode)
        {
            cur += GI_B;
            remaining -= GI_B;
            continue;
        }

        // Try 2 MiB page
        if remaining >= MI_B2
            && (cur.as_u64() & (MI_B2 - 1)) == 0
            && unmap_page::<Size2MiB>(&mut mapper, &mut frame_allocator, cur, mode)
        {
            cur += MI_B2;
            remaining -= MI_B2;
            continue;
        }

        // Fall back to 4 KiB page
        if unmap_page::<Size4KiB>(&mut mapper, &mut frame_allocator, cur, mode) {
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
) -> bool {
    let page = Page::<S>::containing_address(addr);
    match mapper.unmap(page) {
        Ok((frame, flush)) => {
            flush.flush();
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
pub unsafe extern "win64" fn identity_map_page(
    phys_addr: PhysAddr,
    range: usize,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .ok_or(MapToError::FrameAllocationFailed)?,
    );
    let mut mapper = init_mapper(phys_mem_offset);
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
/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
pub unsafe fn map_page(
    mapper: &mut impl Mapper<Size4KiB>,
    page: Page<Size4KiB>,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    map_page_inner(mapper, page, frame_allocator, flags, true)
}

unsafe fn map_page_inner(
    mapper: &mut impl Mapper<Size4KiB>,
    page: Page<Size4KiB>,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
    flush: bool,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    match unsafe { mapper.map_to(page, frame, flags, frame_allocator) } {
        Ok(map_flush) => {
            if flush {
                map_flush.flush();
            }
        }
        Err(err) => {
            frame_allocator.deallocate_frame(frame);
            return Err(err);
        }
    }
    Ok(())
}
/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
#[inline(always)]
unsafe fn map_1gib_page<M>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut BootInfoFrameAllocator,
) -> Result<(), MapToError<Size1GiB>>
where
    M: Mapper<Size1GiB>,
{
    map_1gib_page_inner(mapper, addr, flags, fa, true)
}

unsafe fn map_1gib_page_inner<M>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut BootInfoFrameAllocator,
    flush: bool,
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
        Ok(map_flush) => {
            if flush {
                map_flush.flush();
            }
        }
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
#[inline(always)]
unsafe fn map_2mib_page<M>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut BootInfoFrameAllocator,
) -> Result<(), MapToError<Size2MiB>>
where
    M: Mapper<Size2MiB>,
{
    map_2mib_page_inner(mapper, addr, flags, fa, true)
}

unsafe fn map_2mib_page_inner<M>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut BootInfoFrameAllocator,
    flush: bool,
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
        Ok(map_flush) => {
            if flush {
                map_flush.flush();
            }
        }
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
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    map_range_with_huge_pages(
        &mut mapper,
        addr,
        size,
        &mut frame_allocator,
        flags,
        ignore_already_mapped,
    )
}

pub(crate) unsafe fn map_kernel_2mib_frame(
    addr: VirtAddr,
    phys_addr: PhysAddr,
    flags: PageTableFlags,
    flush: bool,
) -> Result<(), MapToError<Size2MiB>> {
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
    let page = Page::<Size2MiB>::containing_address(addr);
    let frame = PhysFrame::<Size2MiB>::containing_address(phys_addr);
    let effective_flags = if flags.contains(PageTableFlags::HUGE_PAGE) {
        flags
    } else {
        flags | PageTableFlags::HUGE_PAGE
    };

    match unsafe { mapper.map_to(page, frame, effective_flags, &mut frame_allocator) } {
        Ok(map_flush) => {
            if flush {
                map_flush.flush();
            }
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

/// SAFETY: Same as `map_kernel_range`. This skips TLB invalidation and is only
/// valid for fresh virtual ranges that have not been accessed while unmapped.
pub unsafe fn map_fresh_kernel_range_no_flush(
    addr: VirtAddr,
    size: u64,
    flags: PageTableFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    map_fresh_range_with_huge_pages_no_flush(
        &mut mapper,
        addr,
        size,
        &mut frame_allocator,
        flags,
        ignore_already_mapped,
    )
}

extern "win64" fn tlb_flush_ipi() {
    instructions::tlb::flush_all();
    send_eoi(TLB_FLUSH_VECTOR);
}
#[unsafe(naked)]
pub extern "win64" fn tlb_flush_entry() {
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
    unsafe {
        if let Some(a) = APIC.lock().as_ref() {
            a.lapic.send_ipi(
                IpiDest::AllExcludingSelf,
                IpiKind::Fixed {
                    vector: TLB_FLUSH_VECTOR,
                },
            )
        }
    }
    instructions::tlb::flush_all();
}
