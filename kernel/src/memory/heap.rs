use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::paging::{align_up_4k, map_range_with_huge_pages};
use crate::memory::paging::tables::init_mapper;
use crate::util::boot_info;
use x86_64::structures::paging::{PageSize, PageTableFlags, Size1GiB};
use x86_64::VirtAddr;

pub const HEAP_START: usize = 0xFFFF_8600_0000_0000;
pub const HEAP_SIZE: u64 = Size1GiB::SIZE * 4;
pub const BOOTSTRAP_HEAP_SIZE: u64 = Size1GiB::SIZE;
pub const MIMALLOC_HEAP_START: usize = HEAP_START + BOOTSTRAP_HEAP_SIZE as usize;
pub const MIMALLOC_HEAP_SIZE: u64 = HEAP_SIZE - BOOTSTRAP_HEAP_SIZE;
pub const MIMALLOC_META_HEAP_SIZE: u64 = 64 * 1024 * 1024;
pub const MIMALLOC_ARENA_START: usize = MIMALLOC_HEAP_START + MIMALLOC_META_HEAP_SIZE as usize;
pub const MIMALLOC_ARENA_SIZE: u64 = MIMALLOC_HEAP_SIZE - MIMALLOC_META_HEAP_SIZE;
pub(crate) fn init_heap() {
    let heap_start = VirtAddr::new(align_up_4k(HEAP_START as u64));
    let heap_size = align_up_4k(HEAP_SIZE);
    let heap_end = heap_start + heap_size;

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    unsafe {
        map_range_with_huge_pages(
            &mut mapper,
            heap_start,
            heap_size,
            &mut frame_allocator,
            flags,
        )
        .expect("Heap creation failed, can't recover")
    };
}
