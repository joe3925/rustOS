use crate::memory::paging::{
    align_up_4k, init_mapper, map_page, map_range_with_huge_pages, BootInfoFrameAllocator,
};
use crate::println;
use crate::structs::linked_list::ListNode;
use crate::util::boot_info;
use x86_64::structures::paging::FrameAllocator;
use x86_64::structures::paging::{Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

pub const HEAP_START: usize = 0xFFFF_8600_0000_0000;
pub const HEAP_SIZE: usize = 10 * 1024 * 1024;
pub(crate) fn init_heap() {
    let heap_start = VirtAddr::new(align_up_4k(HEAP_START as u64));
    let heap_size = align_up_4k(HEAP_SIZE as u64);
    let heap_end = heap_start + heap_size as u64;

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    map_range_with_huge_pages(
        &mut mapper,
        heap_start,
        heap_size,
        &mut frame_allocator,
        flags,
    )
    .expect("Heap creation failed, can't recover");

    let heap_node = heap_start.as_mut_ptr() as *mut ListNode;
    unsafe {
        heap_node.write(ListNode::new(HEAP_SIZE));
    }
    println!("heap created");
}
