use buddy_system_allocator::LockedHeap;
use x86_64::structures::paging::{PageSize, PageTableFlags, Size1GiB};
use x86_64::VirtAddr;

use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::paging::map_range_with_huge_pages;
use crate::memory::paging::tables::init_mapper;
use crate::util::boot_info;

pub const HEAP_START: usize = 0xFFFF_8600_0000_0000;
pub const HEAP_SIZE: usize = Size1GiB::SIZE as usize;

#[global_allocator]
pub static ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

/// Initialize the buddy allocator with the heap region.
/// Maps the heap memory with huge pages, then initializes the allocator.
pub fn init() {
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap_or(0));
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_alloc = BootInfoFrameAllocator::init();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    unsafe {
        map_range_with_huge_pages(
            &mut mapper,
            VirtAddr::new(HEAP_START as u64),
            HEAP_SIZE as u64,
            &mut frame_alloc,
            flags,
        )
        .expect("Failed to map heap memory");

        ALLOCATOR.lock().init(HEAP_START, HEAP_SIZE);
    }
}
