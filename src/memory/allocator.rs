use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::mem::{align_of, size_of};
use x86_64::{align_up, VirtAddr};
use crate::memory::heap::HEAP_START;
use crate::structs::linked_list::{LinkedList, ListNode};
#[global_allocator]
pub static mut ALLOCATOR: Locked<Allocator> =
    Locked::new(Allocator::new());
pub struct Locked<A> {
    inner: spin::Mutex<A>,
}

impl<A> Locked<A> {
    pub const fn new(inner: A) -> Self {
        Locked {
            inner: spin::Mutex::new(inner),
        }
    }

    pub fn lock(&self) -> spin::MutexGuard<A> {
        self.inner.lock()
    }
}
pub struct Allocator {
    pub(crate) freeList: LinkedList,
    pub(crate) allocationsMade: u128,
}
impl Allocator{
    pub const fn new() -> Self {
        Allocator {
            freeList: LinkedList::new(),
            allocationsMade: 0,
        }


    }
    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        // ensure that the freed region is capable of holding ListNode
        assert!(size >= size_of::<ListNode>());

        // create a new list node and append it at the start of the list
        let mut node = ListNode::new(size);
        node.next = self.freeList.head.next.take();
        let node_ptr = addr as *mut ListNode;
        node_ptr.write(node);
        self.freeList.head.next = Some(&mut *node_ptr);
    }

    fn find_region(&mut self, size: usize, align: usize) -> Option<(&'static mut ListNode, usize)> {
        let mut best_fit_size = usize::MAX;
        let mut best_fit_prev: *mut ListNode = ptr::null_mut();
        let mut best_fit_alloc_start = 0usize;

        // Start from the head of the free list
        let mut current = &mut self.freeList.head as *mut ListNode;

        unsafe {
            // Traverse the free list
            while let Some(ref mut region) = (*current).next {
                // Try to allocate from the current region
                if let Ok(alloc_start) = Self::alloc_from_region(region, size, align) {
                    let region_size = region.size;
                    // Check if this region is a better fit
                    if region_size < best_fit_size {
                        best_fit_size = region_size;
                        best_fit_prev = current;
                        best_fit_alloc_start = alloc_start;
                    }
                }
                // Move to the next region
                current = &mut **region as *mut ListNode;
            }

            // If a best-fit region was found
            if !best_fit_prev.is_null() {
                // Remove the best-fit region from the free list
                let best_fit_prev_ref = &mut *best_fit_prev;
                let best_fit_region = best_fit_prev_ref.next.take().unwrap();
                let next = best_fit_region.next.take();
                best_fit_prev_ref.next = next;

                // Return the best-fit region and allocation start address
                return Some((best_fit_region, best_fit_alloc_start));
            }
        }

        // No suitable region found
        None
    }
    fn alloc_from_region(region: &mut ListNode, size: usize, align: usize)
                         -> Result<usize, ()>
    {
        let alloc_start = align_up(region.start_addr() as u64, align as u64);
        let alloc_end = alloc_start.checked_add(size as u64).ok_or(())?;

        if alloc_end > region.end_addr() as u64 {
            // region too small
            return Err(());
        }

        let excess_size = region.end_addr() as u64 - alloc_end;
        if excess_size > 0 && excess_size < size_of::<ListNode>() as u64 {
            // rest of region too small to hold a ListNode (required because the
            // allocation splits the region in a used and a free part)
            return Err(());
        }

        // region suitable for allocation
        Ok(alloc_start as usize)
    }
    fn size_align(layout: Layout) -> (usize, usize) {
        let layout = layout
            .align_to(align_of::<ListNode>())
            .expect("adjusting alignment failed")
            .pad_to_align();
        let size = layout.size().max(size_of::<ListNode>());
        (size, layout.align())
    }
    pub(crate) fn free_memory(&self) -> usize {
        let mut current = &self.freeList.head;
        let mut total_free = 0;

        while let Some(ref region) = current.next {
            total_free += region.size;
            current = region;
        }

        total_free
    }

    pub fn merge_free_list(&mut self) {
        unsafe {
            // We need to loop until no merges are made in an iteration
            let mut merges_made = true;
            while merges_made {
                merges_made = false;
                let mut current = &mut self.freeList.head as *mut ListNode;

                while let Some(ref mut current_node) = (*current).next {
                    let mut other = &mut self.freeList.head as *mut ListNode;

                    while let Some(ref mut other_node) = (*other).next {
                        if other_node.start_addr() == current_node.start_addr() {
                            other = &mut **other_node as *mut ListNode;
                            continue;
                        }

                        // Check if current_node and other_node are adjacent in memory
                        if current_node.end_addr() == other_node.start_addr() {
                            // Merge other_node into current_node
                            current_node.size += other_node.size;
                            // Remove other_node from the free list
                            (*other).next = other_node.next.take();
                            merges_made = true;
                            break;
                        } else if other_node.end_addr() == current_node.start_addr() {
                            // Merge current_node into other_node
                            other_node.size += current_node.size;
                            // Remove current_node from the free list
                            (*current).next = current_node.next.take();
                            merges_made = true;
                            // Restart outer loop since current_node has changed
                            break;
                        } else {
                            // Move to the next node in the inner loop
                            other = &mut **other_node as *mut ListNode;
                        }
                    }

                    // If a merge was made, restart the outer loop
                    if merges_made {
                        break;
                    } else {
                        // Move to the next node in the outer loop
                        current = &mut **current_node as *mut ListNode;
                    }
                }
            }
        }
    }
}

unsafe impl GlobalAlloc for Locked<Allocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // perform layout adjustments
        static mut INIT:bool = false;
        let (size, align) = Allocator::size_align(layout);
        let mut allocator = self.lock();
       // println!("free mem:{}, alloc size: {}", allocator.free_memory(), layout.size());

        if(INIT == false){
            let heap_start = VirtAddr::new(HEAP_START as u64);
            let heap_node_ptr = heap_start.as_mut_ptr() as *mut ListNode;

            allocator.freeList.head.next = heap_node_ptr.as_mut();
            INIT = true;
        }
        if let Some((region, alloc_start)) = allocator.find_region(size, align) {
            let alloc_end = alloc_start.checked_add(size).expect("overflow");
            let excess_size = region.end_addr() - alloc_end;
            if excess_size > 0 {
                allocator.add_free_region(alloc_end, excess_size);
            }
            allocator.allocationsMade += 1;
            alloc_start as *mut u8
        } else {
            ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // perform layout adjustments
        let mut allocator = self.lock();
        let (size, _) = Allocator::size_align(layout);
        allocator.allocationsMade -= 1;
        allocator.add_free_region(ptr as usize, size);
        allocator.merge_free_list();
    }
}


