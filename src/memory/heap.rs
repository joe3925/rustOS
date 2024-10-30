use x86_64::structures::paging::{Mapper, Page, PageSize, PageTableFlags, PhysFrame, Size2MiB, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::FrameAllocator;
use x86_64::structures::paging::mapper::MapToError;
use crate::memory::paging::{map_page, BootInfoFrameAllocator};
use crate::println;
use crate::structs::linked_list::ListNode;

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 20 * 1024 * 1024; // 20 MiB, aligned for 2 MiB pages
pub(crate) fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size2MiB>,
    kib2_frame_alloc: &mut impl FrameAllocator<Size4KiB>,
) {
    // Calculate start and end addresses for the heap
    let heap_start = VirtAddr::new(HEAP_START as u64);
    let heap_end = heap_start + HEAP_SIZE as u64;

    // Define the range using 2 MiB pages
    let start_page_2mb: Page<Size2MiB> = Page::containing_address(heap_start);
    let end_page_2mb: Page<Size2MiB> = Page::containing_address(heap_end - 1u64);
    let page_range_2mb = Page::range_inclusive(start_page_2mb, end_page_2mb);
    for page_2mb in page_range_2mb {
        // Allocate a single 2 MiB frame
        let frame_2mb = frame_allocator
            .allocate_frame()
            .expect("failed to allocate 2 MiB frame");

        // Split the 2 MiB frame into 512 contiguous 4 KiB frames
        let start_frame_4kb = frame_2mb.start_address().as_u64();
        let start_page_4kb: Page<Size4KiB> = Page::containing_address(page_2mb.start_address());

        for i in 0..512 {
            let page_4kb = start_page_4kb + i;
            let frame_address = start_frame_4kb + i * Size4KiB::SIZE as u64;
            let frame_4kb = PhysFrame::containing_address(PhysAddr::new(frame_address));

            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

            unsafe {
                mapper
                    .map_to(page_4kb, frame_4kb, flags, kib2_frame_alloc)
                    .expect("failed to map 4 KiB page")
                    .flush();
            }
        }
    }

    // Initialize the heap allocator’s free list or other setup
    let heap_node = heap_start.as_mut_ptr() as *mut ListNode;
    unsafe { heap_node.write(ListNode::new(HEAP_SIZE)); }

    println!("heap created using 4 KiB pages, but 2 MiB frame allocations");
}
struct DummyAllocator;

unsafe impl FrameAllocator<Size4KiB> for DummyAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        None // No additional frames need to be allocated
    }
}