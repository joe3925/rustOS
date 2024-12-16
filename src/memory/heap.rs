use core::ptr::write_volatile;
use crate::println;
use crate::structs::linked_list::ListNode;
use x86_64::structures::paging::FrameAllocator;
use x86_64::structures::paging::{Mapper, Page, PageSize, PageTableFlags, PhysFrame, Size2MiB, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::paging::map_page;

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 5 * 1024 * 1024;
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
    let heap_node = heap_start.as_mut_ptr() as *mut ListNode;
    unsafe{ heap_node.write(ListNode::new(HEAP_SIZE));}
    println!("heap created");
}
struct DummyAllocator;

unsafe impl FrameAllocator<Size4KiB> for DummyAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        None // No additional frames need to be allocated
    }
}