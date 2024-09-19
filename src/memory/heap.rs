use x86_64::structures::paging::{Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;
use crate::memory::paging::map_page;
use crate::structs::linked_list::ListNode;

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 50000 * 1024;
pub(crate) fn init_heap(mapper: &mut impl Mapper<Size4KiB>, frame_allocator: &mut impl FrameAllocator<Size4KiB>){
    let heap_start = VirtAddr::new(HEAP_START as u64);
    let heap_end = heap_start + HEAP_SIZE as u64;
    let end_page = Page::containing_address(heap_end);
    let mut current_page = Page::containing_address(heap_start);

    while (current_page <= end_page){
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        //todo: handle this error better
        map_page(mapper, current_page, frame_allocator, flags).expect("HEAP CREATION FAILED");
        current_page += 1;
    }
    let heapNode = heap_start.as_mut_ptr() as *mut ListNode;
    unsafe{heapNode.write(ListNode::new(HEAP_SIZE));}
}