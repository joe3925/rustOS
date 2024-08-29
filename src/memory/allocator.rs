use core::alloc::{GlobalAlloc, Layout};
use core::{mem, ptr};
use linked_list_allocator::LockedHeap;
use x86_64::{align_up, VirtAddr};
use crate::{print, println};
use crate::memory::heap::HEAP_START;
use crate::structs::linked_list::{LinkedList, ListNode};
#[global_allocator]
static mut ALLOCATOR: Locked<Allocator> =
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
struct Allocator {
    freeList: LinkedList,
}
impl Allocator{
    pub const fn new() -> Self {
        Allocator {
            freeList: LinkedList::new(),
        }


    }
    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        // ensure that the freed region is capable of holding ListNode
        assert!(size >= mem::size_of::<ListNode>());

        // create a new list node and append it at the start of the list
        let mut node = ListNode::new(size);
        node.next = self.freeList.head.next.take();
        let node_ptr = addr as *mut ListNode;
        node_ptr.write(node);
        self.freeList.head.next = Some(&mut *node_ptr)
    }

    fn find_region(&mut self, size: usize, align: usize)
                   -> Option<(&'static mut ListNode, usize)>
    {
        //self.freeList.printList();
        let mut current = &mut self.freeList.head;
        while let Some(ref mut region) = current.next {
            if let Ok(alloc_start) = Self::alloc_from_region(&region, size, align) {
                let next = region.next.take();
                let ret = Some((current.next.take().unwrap(), alloc_start));
                current.next = next;
                return ret;

            } else {
                current = current.next.as_mut().unwrap();
            }
        }
        //println!("here1");
        None
    }
    fn alloc_from_region(region: &ListNode, size: usize, align: usize)
                         -> Result<usize, ()>
    {
        let alloc_start = align_up(region.start_addr() as u64, align as u64);
        let alloc_end = alloc_start.checked_add(size as u64).ok_or(())?;

        if alloc_end > region.end_addr() as u64 {
            // region too small
            return Err(());
        }

        let excess_size = region.end_addr() as u64 - alloc_end;
        if excess_size > 0 && excess_size < mem::size_of::<ListNode>() as u64 {
            // rest of region too small to hold a ListNode (required because the
            // allocation splits the region in a used and a free part)
            return Err(());
        }

        // region suitable for allocation
        Ok(alloc_start as usize)
    }
    fn size_align(layout: Layout) -> (usize, usize) {
        let layout = layout
            .align_to(mem::align_of::<ListNode>())
            .expect("adjusting alignment failed")
            .pad_to_align();
        let size = layout.size().max(mem::size_of::<ListNode>());
        (size, layout.align())
    }
}

unsafe impl GlobalAlloc for Locked<Allocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // perform layout adjustments
        static mut INIT:bool = false;

        let (size, align) = Allocator::size_align(layout);
        let mut allocator = self.lock();
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
            alloc_start as *mut u8
        } else {
            ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // perform layout adjustments

        let (size, _) = Allocator::size_align(layout);

        self.lock().add_free_region(ptr as usize, size)
    }
}


