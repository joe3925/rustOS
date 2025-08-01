use core::sync::atomic::AtomicU64;

use x86_64::{structures::paging::{mapper::MapToError, Mapper as _, Page, PageTableFlags, PhysFrame, Size4KiB}, PhysAddr, VirtAddr};

use crate::{memory::paging::{constants::MMIO_BASE, frame_alloc::BootInfoFrameAllocator, tables::init_mapper, virt_tracker::allocate_auto_kernel_range}, util::boot_info};


static NEXT_MMIO_VADDR: AtomicU64 = AtomicU64::new(MMIO_BASE);
pub fn map_mmio_region(
    mmio_base: PhysAddr,
    mmio_size: u64,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let phys_frame = PhysFrame::containing_address(mmio_base);
    let num_pages = (mmio_size + 0xFFF) / 4096;

    let virtual_addr =
        allocate_auto_kernel_range(mmio_size).ok_or_else(|| MapToError::FrameAllocationFailed)?;

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
    Ok(virtual_addr)
}
