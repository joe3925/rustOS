use core::sync::atomic::AtomicU64;

use kernel_types::status::PageMapError;
use x86_64::{
    structures::paging::{
        mapper::MapToError, Mapper as _, Page, PageTableFlags, PhysFrame, Size1GiB, Size2MiB,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    memory::paging::{
        constants::MMIO_BASE, frame_alloc::BootInfoFrameAllocator, paging::align_up_4k,
        tables::init_mapper, virt_tracker::allocate_auto_kernel_range,
    },
    util::boot_info,
};

static NEXT_MMIO_VADDR: AtomicU64 = AtomicU64::new(MMIO_BASE);
pub extern "win64" fn map_mmio_region(
    mmio_base: PhysAddr,
    mmio_size: u64,
) -> Result<VirtAddr, PageMapError> {
    let phys_addr = mmio_base.as_u64();
    let off = phys_addr & 0xFFF;
    let aligned_base = PhysAddr::new(phys_addr - off);
    let total_size = align_up_4k(mmio_size + off);

    let phys_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(aligned_base);
    let num_pages = total_size / 4096;

    let virtual_addr =
        allocate_auto_kernel_range(total_size).ok_or_else(|| PageMapError::NoMemory())?;

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    for i in 0..num_pages {
        let page = Page::containing_address(virtual_addr + i * 4096);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
        unsafe {
            mapper
                .map_to(page, phys_frame + i, flags, &mut frame_allocator)?
                .flush();
        }
    }
    Ok(VirtAddr::new(virtual_addr.as_u64() + off))
}
pub fn unmap_mmio_region(base: VirtAddr, size: u64) -> Result<(), PageMapError> {
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

    const GIB: u64 = 1 << 30;
    const MIB2: u64 = 2 * 1024 * 1024;
    const KIB4: u64 = 4 * 1024;

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
