pub mod allocator;
pub mod buddylocked;
#[cfg(feature = "allocator-mimalloc")]
pub mod mimalloc;

#[global_allocator]
pub static ALLOCATOR: KernelAllocator = KernelAllocator::new();

pub fn enable_mimalloc() {
    ALLOCATOR.enable_mimalloc();
}

pub fn mimalloc_thread_done() {
    ALLOCATOR.mimalloc_thread_done();
}

use crate::memory::heap::allocator::KernelAllocator;
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::paging::{align_up_4k, map_range_with_huge_pages};
use crate::memory::paging::tables::init_mapper;
use crate::util::boot_info;
use x86_64::structures::paging::{PageSize, PageTableFlags, Size1GiB, Size2MiB};
use x86_64::VirtAddr;

pub const HEAP_START: usize = 0xFFFF_8600_0000_0000;
pub const HEAP_SIZE: u64 = Size1GiB::SIZE * 4;
pub const BOOTSTRAP_HEAP_SIZE: u64 = Size2MiB::SIZE * 5;
pub const MIMALLOC_HEAP_START: usize = HEAP_START + BOOTSTRAP_HEAP_SIZE as usize;
pub const MIMALLOC_HEAP_SIZE: u64 = HEAP_SIZE - BOOTSTRAP_HEAP_SIZE;
// Minimum pre-arena space. The actual mimalloc OS allocator uses the entire
// pre-arena range because mimalloc uses it for normal segments, not just metadata.
pub const MIMALLOC_META_HEAP_SIZE: u64 = 64 * 1024 * 1024;
pub const MIMALLOC_ARENA_START: usize = align_up_usize(
    MIMALLOC_HEAP_START + MIMALLOC_META_HEAP_SIZE as usize,
    Size1GiB::SIZE as usize,
);
pub const MIMALLOC_OS_HEAP_SIZE: u64 = (MIMALLOC_ARENA_START - MIMALLOC_HEAP_START) as u64;
pub const MIMALLOC_ARENA_SIZE: u64 =
    (HEAP_START + HEAP_SIZE as usize - MIMALLOC_ARENA_START) as u64;

const fn align_up_usize(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

pub(crate) fn init_heap() {
    let heap_start = VirtAddr::new(align_up_4k(HEAP_START as u64));

    #[cfg(feature = "allocator-mimalloc")]
    let heap_size = align_up_4k(BOOTSTRAP_HEAP_SIZE + MIMALLOC_OS_HEAP_SIZE);

    #[cfg(feature = "allocator-buddy")]
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
            false,
        )
        .expect("Heap creation failed, can't recover")
    };
}
