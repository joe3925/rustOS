use crate::memory::heap::{HEAP_SIZE, HEAP_START};
use crate::structs::linked_list::{LinkedList, ListNode};
use buddy_system_allocator::LockedHeap;
use core::alloc::{GlobalAlloc, Layout};
use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::{align_up, VirtAddr};

// #[global_allocator]
// pub static mut ALLOCATOR: Locked<Allocator> = Locked::new(Allocator::new());
// TODO: write my own buddy alloc when I have time
#[global_allocator]
pub static ALLOCATOR: BuddyLocked = BuddyLocked::new();
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
    pub(crate) free_list: LinkedList,
    pub(crate) allocations_made: u128,
}
impl Allocator {
    pub const fn new() -> Self {
        Allocator {
            free_list: LinkedList::new(),
            allocations_made: 0,
        }
    }
    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        assert!(size >= size_of::<ListNode>());

        // create a new list node and append it at the start of the list
        let mut node = ListNode::new(size);
        node.next = self.free_list.head.next.take();
        let node_ptr = addr as *mut ListNode;
        node_ptr.write(node);
        self.free_list.head.next = Some(&mut *node_ptr);
    }

    fn find_region(&mut self, size: usize, align: usize) -> Option<(&'static mut ListNode, usize)> {
        let mut best_fit_size = usize::MAX;
        let mut best_fit_prev: *mut ListNode = ptr::null_mut();
        let mut best_fit_alloc_start = 0usize;

        let mut current = &mut self.free_list.head as *mut ListNode;

        unsafe {
            // Traverse the free list
            while let Some(ref mut region) = (*current).next {
                if let Ok(alloc_start) = Self::alloc_from_region(region, size, align) {
                    let region_size = region.size;
                    if region_size < best_fit_size {
                        best_fit_size = region_size;
                        best_fit_prev = current;
                        best_fit_alloc_start = alloc_start;
                    }
                }
                // Move to the next region
                current = &mut **region as *mut ListNode;
            }

            if !best_fit_prev.is_null() {
                let best_fit_prev_ref = &mut *best_fit_prev;
                let best_fit_region = best_fit_prev_ref.next.take().unwrap();
                let next = best_fit_region.next.take();
                best_fit_prev_ref.next = next;

                return Some((best_fit_region, best_fit_alloc_start));
            }
        }

        None
    }
    fn alloc_from_region(region: &mut ListNode, size: usize, align: usize) -> Result<usize, ()> {
        let alloc_start = align_up(region.start_addr() as u64, align as u64);
        let alloc_end = alloc_start.checked_add(size as u64).ok_or(())?;

        if alloc_end > region.end_addr() as u64 {
            return Err(());
        }

        let excess_size = region.end_addr() as u64 - alloc_end;
        if excess_size > 0 && excess_size < size_of::<ListNode>() as u64 {
            // rest of region too small to hold a ListNode (required because the
            // allocation splits the region in a used and a free part)
            return Err(());
        }

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
        let mut current = &self.free_list.head;
        let mut total_free = 0;

        while let Some(ref region) = current.next {
            total_free += region.size;
            current = region;
        }

        total_free
    }

    pub fn merge_free_list(&mut self) {
        unsafe {
            let mut current = self.free_list.head.start_addr() as *mut ListNode;

            while !current.is_null() {
                let current_node = &mut *current;

                if let Some(ref mut next_ref) = current_node.next {
                    let next_ptr = &mut **next_ref as *mut ListNode;
                    let next_node = &mut *next_ptr;

                    if current_node.end_addr() == next_node.start_addr() {
                        current_node.size += next_node.size;

                        current_node.next = next_node.next.take();
                    } else {
                        current = next_ptr;
                    }
                } else {
                    break;
                }
            }
        }
    }
}
//TODO: make this atomic or mutex lock
// static mut INIT: bool = false;
// unsafe impl GlobalAlloc for Locked<Allocator> {
//     unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
//         // perform layout adjustments
//         x86_64::instructions::interrupts::without_interrupts(|| {
//             let (size, align) = Allocator::size_align(layout);
//             let mut allocator = self.lock();

//             if (INIT == false) {
//                 let heap_start = VirtAddr::new(HEAP_START as u64);
//                 let heap_node_ptr = heap_start.as_mut_ptr() as *mut ListNode;

//                 allocator.free_list.head.next = heap_node_ptr.as_mut();
//                 INIT = true;
//             }
//             if let Some((region, alloc_start)) = allocator.find_region(size, align) {
//                 let alloc_end = alloc_start.checked_add(size).expect("overflow");
//                 let excess_size = region.end_addr() - alloc_end;
//                 if excess_size > 0 {
//                     allocator.add_free_region(alloc_end, excess_size);
//                 }
//                 allocator.allocations_made += 1;
//                 alloc_start as *mut u8
//             } else {
//                 ptr::null_mut()
//             }
//         })
//     }

//     unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
//         // perform layout adjustments
//         x86_64::instructions::interrupts::without_interrupts(|| {
//             let mut allocator = self.lock();
//             let (size, _) = Allocator::size_align(layout);
//             allocator.allocations_made -= 1;
//             allocator.add_free_region(ptr as usize, size);
//             allocator.merge_free_list();
//         });
//     }
// }
pub struct BuddyLocked {
    inner: LockedHeap<32>,
    init: AtomicBool,
}

impl BuddyLocked {
    pub const fn new() -> Self {
        Self {
            inner: LockedHeap::<32>::empty(),
            init: AtomicBool::new(false),
        }
    }
    #[inline(always)]
    unsafe fn ensure_init(&self) {
        if !self.init.load(Ordering::Acquire) {
            without_interrupts(|| {
                if !self.init.load(Ordering::Acquire) {
                    let heap_start = HEAP_START as usize;
                    let heap_size = HEAP_SIZE as usize;
                    self.inner.lock().init(heap_start, heap_size);
                    self.init.store(true, Ordering::Release);
                }
            });
        }
    }
    pub fn free_memory(&self) -> usize {
        without_interrupts(|| {
            let inner = self.inner.lock();
            inner.stats_total_bytes() - inner.stats_alloc_actual()
        })
    }
}

unsafe impl GlobalAlloc for BuddyLocked {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.ensure_init();
        without_interrupts(|| self.inner.lock().alloc(layout))
            .expect("kernel heap overflow")
            .as_ptr()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.ensure_init();
        without_interrupts(|| {
            self.inner.lock().dealloc(
                NonNull::new(ptr).expect("Null ptr passed to kernel heap dealloc"),
                layout,
            )
        })
    }
}
