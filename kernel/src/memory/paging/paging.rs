use core::sync::atomic::{AtomicUsize, Ordering};

use kernel_types::status::PageMapError;
use spin::Mutex;
use x86_64::{
    instructions::interrupts,
    registers::control::Cr3,
    structures::idt::InterruptStackFrame,
    structures::paging::{
        mapper::{MapToError, MapperFlush},
        FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    cpu::get_cpu_info,
    drivers::{
        interrupt_index::{send_eoi, IpiDest, IpiKind, LocalApic, APIC},
        timer_driver::NUM_CORES,
    },
    memory::paging::{frame_alloc::BootInfoFrameAllocator, tables::init_mapper},
    util::{boot_info, CORE_LOCK},
};

pub const fn num_frames_4k(size: usize) -> usize {
    ((size + 0xFFF) >> 12)
}

pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xF1;

static TLB_SHOOTDOWN_LOCK: Mutex<()> = Mutex::new(());

// TODO: it is possible to remove all this unsafe, not urgent.

#[inline(always)]
fn reload_current_cr3() {
    let (cr3, flags) = Cr3::read();
    unsafe { Cr3::write(cr3, flags) };
}

pub extern "x86-interrupt" fn tlb_shootdown_interrupt(_frame: InterruptStackFrame) {
    reload_current_cr3();
    send_eoi(TLB_SHOOTDOWN_VECTOR);
}

pub fn flush_tlb_global() {
    if NUM_CORES.load(Ordering::Acquire) <= 1 || CORE_LOCK.load(Ordering::Relaxed) != 0 {
        reload_current_cr3();
        return;
    }

    if let Some(_shootdown_guard) = TLB_SHOOTDOWN_LOCK.try_lock() {
        let interrupts_were_enabled = interrupts::are_enabled();
        if interrupts_were_enabled {
            interrupts::disable();
        }

        reload_current_cr3();

        let remote_targets = NUM_CORES.load(Ordering::Acquire).saturating_sub(1);
        if remote_targets != 0 {
            let apic_guard = APIC.lock();
            if let Some(apic) = apic_guard.as_ref() {
                unsafe {
                    apic.lapic.send_ipi(
                        IpiDest::AllExcludingSelf,
                        IpiKind::Fixed {
                            vector: TLB_SHOOTDOWN_VECTOR,
                        },
                    );
                }
                drop(apic_guard);
            }
        }

        if interrupts_were_enabled {
            interrupts::enable();
        }
    } else {
        return;
    }
}

pub fn flush_tlb_shootdown<S: x86_64::structures::paging::page::PageSize>(flush: MapperFlush<S>) {
    flush.ignore();
    flush_tlb_global();
}

/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
pub unsafe fn map_range_with_huge_pages<M>(
    mapper: &mut M,
    addr: VirtAddr,
    size: u64,
    fa: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
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
            match unsafe { map_1gib_page(mapper, cur, flags, fa) } {
                Ok(_) => {
                    cur += gib;
                    remaining -= gib;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => {
                    return Err(PageMapError::Page1GiB(e));
                }
            };
        }

        if remaining >= mib2 && (cur.as_u64() & (mib2 - 1)) == 0 {
            match unsafe { map_2mib_page(mapper, cur, flags, fa) } {
                Ok(_) => {
                    cur += mib2;
                    remaining -= mib2;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => {
                    return Err(PageMapError::Page2MiB(e));
                }
            };
        }

        let page4k = Page::<Size4KiB>::containing_address(cur);
        unsafe { map_page(mapper, page4k, fa, flags) }?;
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
            && unmap_page::<Size1GiB>(&mut mapper, &mut frame_allocator, cur)
        {
            cur += GI_B;
            remaining -= GI_B;
            continue;
        }

        // Try 2 MiB page
        if remaining >= MI_B2
            && (cur.as_u64() & (MI_B2 - 1)) == 0
            && unmap_page::<Size2MiB>(&mut mapper, &mut frame_allocator, cur)
        {
            cur += MI_B2;
            remaining -= MI_B2;
            continue;
        }

        // Fall back to 4 KiB page
        if unmap_page::<Size4KiB>(&mut mapper, &mut frame_allocator, cur) {
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
) -> bool {
    let page = Page::<S>::containing_address(addr);
    match mapper.unmap(page) {
        Ok((frame, flush)) => {
            flush_tlb_shootdown(flush);
            // SAFETY: the frame is no longer mapped
            frame_allocator.deallocate_frame(frame);
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
            let flush = mapper.map_to(
                page,
                frame,
                flags | PageTableFlags::PRESENT,
                &mut frame_allocator,
            )?;
            flush_tlb_shootdown(flush);
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
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    unsafe {
        let flush = mapper.map_to(page, frame, flags, frame_allocator)?;
        flush_tlb_shootdown(flush);
    }
    Ok(())
}
/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
#[inline(always)]
unsafe fn map_1gib_page<M, FA>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut FA,
) -> Result<(), MapToError<Size1GiB>>
where
    M: Mapper<Size1GiB>,
    FA: FrameAllocator<Size1GiB> + FrameAllocator<Size4KiB>,
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

    unsafe {
        let flush = mapper.map_to(page, frame, effective_flags, fa)?;
        flush_tlb_shootdown(flush);
    }
    Ok(())
}
/// SAFETY: Does not check the kernel range allocator before mapping the requested range.
/// The caller must make sure that the range they request is not currently allocated and will not be later allocated by kernel map auto functions
/// The best way to do this is to reserve the range you want to map manually.
#[inline(always)]
unsafe fn map_2mib_page<M, FA>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut FA,
) -> Result<(), MapToError<Size2MiB>>
where
    M: Mapper<Size2MiB>,
    FA: FrameAllocator<Size2MiB> + FrameAllocator<Size4KiB>,
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

    unsafe {
        let flush = mapper.map_to(page, frame, effective_flags, fa)?;
        flush_tlb_shootdown(flush);
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
) -> Result<(), PageMapError> {
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    map_range_with_huge_pages(&mut mapper, addr, size, &mut frame_allocator, flags)
}
