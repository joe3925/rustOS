use crate::memory::{
    heap::{HEAP_SIZE, HEAP_START},
    paging::{
        frame_alloc::BootInfoFrameAllocator,
        paging::{map_range_with_huge_pages, unmap_range_impl},
        tables::init_mapper,
    },
};
use crate::structs::linked_list::{LinkedList, ListNode};
use crate::util::boot_info;
use crate::static_handlers::task_yield;
use baby_mimalloc::Mimalloc;
use buddy_system_allocator::LockedHeap;
use core::alloc::{GlobalAlloc, Layout};
use core::mem::{align_of, size_of};
use core::ptr::{self, null_mut, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::structures::paging::{mapper::MapToError, Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::{align_up, VirtAddr};
use x86_64::{
    instructions::interrupts::{self, without_interrupts},
    structures::paging::FrameAllocator,
};

// #[global_allocator]
// pub static mut ALLOCATOR: Locked<Allocator> = Locked::new(Allocator::new());
// #[global_allocator]
// pub static ALLOCATOR: BuddyLocked = BuddyLocked::new();
#[global_allocator]
pub static ALLOCATOR: YieldingMimalloc = YieldingMimalloc::new();

/// Global allocator wrapper that yields if another CPU is holding the lock
/// instead of spinning with interrupts off.
pub struct YieldingMimalloc {
    inner: spin::Mutex<Mimalloc<KernelSegAlloc>>,
}

impl YieldingMimalloc {
    pub const fn new() -> Self {
        Self {
            inner: spin::Mutex::new(Mimalloc::with_os_allocator(KernelSegAlloc)),
        }
    }

    #[inline(always)]
    fn lock(&self) -> spin::MutexGuard<'_, Mimalloc<KernelSegAlloc>> {
        loop {
            if let Some(g) = self.inner.try_lock() {
                return g;
            }

            if interrupts::are_enabled() {
                unsafe { task_yield() };
            } else {
                core::hint::spin_loop();
            }
        }
    }
}

unsafe impl GlobalAlloc for YieldingMimalloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.lock().alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.lock().dealloc(ptr, layout)
    }
}

pub struct KernelSegAlloc;

const PAGE_SIZE: usize = 4096;

// Simple VA range allocator that backs allocations with freshly mapped frames.
// All metadata lives inside the heap VA itself so no heap allocations occur.
static SEG_ALLOC: Locked<SegAllocator> = Locked::new(SegAllocator::new());
unsafe impl GlobalAlloc for KernelSegAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = x86_64::align_up(layout.size() as u64, PAGE_SIZE as u64) as usize;
        if size == 0 {
            return core::ptr::null_mut();
        }
        let align = layout.align().max(PAGE_SIZE);
        vm_alloc_aligned(size, align)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        if ptr.is_null() {
            return;
        }
        let size = x86_64::align_up(layout.size() as u64, PAGE_SIZE as u64) as usize;
        if size == 0 {
            return;
        }
        vm_free(ptr, size);
    }
}
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

struct SegAllocator {
    free_list: LinkedList,
    initialized: bool,
}

impl SegAllocator {
    pub const fn new() -> Self {
        Self {
            free_list: LinkedList::new(),
            initialized: false,
        }
    }

    fn ensure_init(&mut self) {
        if self.initialized {
            return;
        }

        unsafe {
            if !ensure_header_mapped(HEAP_START as usize) {
                return;
            }

            let heap_node_ptr = HEAP_START as *mut ListNode;
            heap_node_ptr.write(ListNode::new(HEAP_SIZE as usize));
            self.free_list.head.next = heap_node_ptr.as_mut();
            self.initialized = true;
        }
    }

    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        if size < core::mem::size_of::<ListNode>() || size < PAGE_SIZE {
            return;
        }

        if !ensure_header_mapped(addr) {
            return;
        }

        let node_ptr = addr as *mut ListNode;
        node_ptr.write(ListNode::new(size));

        let mut prev: *mut ListNode = &mut self.free_list.head as *mut ListNode;
        while let Some(next_ref) = (*prev).next.as_mut() {
            let next_ptr = &mut **next_ref as *mut ListNode;
            if (*next_ptr).start_addr() < addr {
                prev = next_ptr;
            } else {
                break;
            }
        }

        let prev_ref = &mut *prev;
        let old_next = prev_ref.next.take();

        (*node_ptr).next = old_next;
        prev_ref.next = Some(&mut *node_ptr);

        let mut cur_ptr: *mut ListNode = node_ptr;

        if let Some(next_ref) = (*cur_ptr).next.as_mut() {
            let next_ptr = &mut **next_ref as *mut ListNode;
            if (*cur_ptr).end_addr() == (*next_ptr).start_addr() {
                let next_next = (*next_ptr).next.take();
                (*cur_ptr).size += (*next_ptr).size;
                (*cur_ptr).next = next_next;
            }
        }

        let head_ptr = &mut self.free_list.head as *mut ListNode;
        if prev != head_ptr {
            let prev_ref = &mut *prev;
            if prev_ref.end_addr() == (*cur_ptr).start_addr() {
                let cur_next = (*cur_ptr).next.take();
                prev_ref.size += (*cur_ptr).size;
                prev_ref.next = cur_next;
            }
        }
    }
    fn find_region(&mut self, size: usize, align: usize) -> Option<(&'static mut ListNode, usize)> {
        let mut best_fit_size = usize::MAX;
        let mut best_fit_prev: *mut ListNode = core::ptr::null_mut();
        let mut best_fit_alloc_start = 0usize;

        let mut prev: *mut ListNode = &mut self.free_list.head as *mut ListNode;

        unsafe {
            while let Some(next_ref) = (*prev).next.as_mut() {
                let region_ptr = &mut **next_ref as *mut ListNode;

                if let Ok(alloc_start) = Self::alloc_from_region(&mut *region_ptr, size, align) {
                    let region_size = (*region_ptr).size;
                    if region_size < best_fit_size {
                        best_fit_size = region_size;
                        best_fit_prev = prev;
                        best_fit_alloc_start = alloc_start;
                    }
                }

                prev = region_ptr;
            }

            if best_fit_prev.is_null() {
                return None;
            }

            let prev_ref = &mut *best_fit_prev;
            let region = prev_ref.next.take().unwrap();
            let next = region.next.take();
            prev_ref.next = next;

            Some((region, best_fit_alloc_start))
        }
    }

    fn alloc_from_region(region: &mut ListNode, size: usize, align: usize) -> Result<usize, ()> {
        let region_start = region.start_addr();
        let region_end = region.end_addr();

        let alloc_start = x86_64::align_up(region_start as u64, align as u64) as usize;
        let alloc_end = alloc_start.checked_add(size).ok_or(())?;

        if alloc_end > region_end {
            return Err(());
        }

        let min = core::mem::size_of::<ListNode>();

        let lead = alloc_start - region_start;
        if lead > 0 && lead < min {
            return Err(());
        }

        let tail = region_end - alloc_end;
        if tail > 0 && tail < min {
            return Err(());
        }

        Ok(alloc_start)
    }
}

unsafe fn ensure_header_mapped(addr: usize) -> bool {
    let boot = boot_info();
    let phys_off = VirtAddr::new(
        boot.physical_memory_offset
            .into_option()
            .expect("missing phys mem offset"),
    );

    let mut mapper = init_mapper(phys_off);
    let mut fa = BootInfoFrameAllocator::init(&boot.memory_regions);

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr as u64));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let new_frame = match fa.allocate_frame() {
        Some(f) => f,
        None => return false,
    };

    match mapper.map_to(page, new_frame, flags, &mut fa) {
        Ok(flush) => {
            flush.flush();
            true
        }
        Err(MapToError::PageAlreadyMapped(_)) => {
            fa.deallocate_frame(new_frame);
            true
        }
        Err(_) => {
            fa.deallocate_frame(new_frame);
            false
        }
    }
}

unsafe fn map_range_4k_rollback(start: VirtAddr, size: usize) -> Result<(), ()> {
    let boot = boot_info();
    let phys_off = VirtAddr::new(
        boot.physical_memory_offset
            .into_option()
            .expect("missing phys mem offset"),
    );

    let mut mapper = init_mapper(phys_off);
    let mut fa = BootInfoFrameAllocator::init(&boot.memory_regions);

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let mut cur = start;
    let mut remaining = align_up(size as u64, PAGE_SIZE as u64) as usize;

    while remaining > 0 {
        let page = Page::<Size4KiB>::containing_address(cur);

        let new_frame = match fa.allocate_frame() {
            Some(f) => f,
            None => {
                unmap_range_impl(start, (cur.as_u64() - start.as_u64()));
                return Err(());
            }
        };

        match mapper.map_to(page, new_frame, flags, &mut fa) {
            Ok(flush) => {
                flush.flush();
            }
            Err(MapToError::PageAlreadyMapped(_)) => {
                fa.deallocate_frame(new_frame);
            }
            Err(_) => {
                fa.deallocate_frame(new_frame);
                unmap_range_impl(start, (cur.as_u64() - start.as_u64()));
                return Err(());
            }
        }

        cur += PAGE_SIZE as u64;
        remaining -= PAGE_SIZE;
    }

    Ok(())
}

/// Allocate a VA range from the heap window, back it with frames, and map it RW.
unsafe fn vm_alloc_aligned(size: usize, align: usize) -> *mut u8 {
    let request_size = align_up(size as u64, PAGE_SIZE as u64) as usize;
    if request_size == 0 {
        return null_mut();
    }
    let align = align.max(PAGE_SIZE);

    let (alloc_start, alloc_size) = match without_interrupts(|| {
        let mut alloc = SEG_ALLOC.lock();
        alloc.ensure_init();
        if !alloc.initialized {
            return None;
        }

        alloc
            .find_region(request_size, align)
            .map(|(region, alloc_start)| {
                let region_start = region.start_addr();
                let region_end = region.end_addr();
                let alloc_end = alloc_start + request_size;

                if alloc_start > region_start {
                    unsafe { alloc.add_free_region(region_start, alloc_start - region_start) };
                }
                if alloc_end < region_end {
                    unsafe { alloc.add_free_region(alloc_end, region_end - alloc_end) };
                }

                (alloc_start, request_size)
            })
    }) {
        Some(v) => v,
        None => return null_mut(),
    };

    if map_range_4k_rollback(VirtAddr::new(alloc_start as u64), alloc_size).is_err() {
        without_interrupts(|| {
            let mut alloc = SEG_ALLOC.lock();
            alloc.ensure_init();
            if alloc.initialized {
                unsafe { alloc.add_free_region(alloc_start, alloc_size) };
            }
        });
        return null_mut();
    }

    core::ptr::write_bytes(alloc_start as *mut u8, 0, alloc_size);
    alloc_start as *mut u8
}

/// Unmap and free the VA range previously returned by `vm_alloc_aligned`.
unsafe fn vm_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }

    let size = align_up(size as u64, PAGE_SIZE as u64) as usize;

    unmap_range_impl(VirtAddr::new(ptr as u64), size as u64);

    if !ensure_header_mapped(ptr as usize) {
        return;
    }

    without_interrupts(|| {
        let mut alloc = SEG_ALLOC.lock();
        alloc.ensure_init();
        if alloc.initialized {
            unsafe { alloc.add_free_region(ptr as usize, size) };
        }
    });
}
// pub struct Allocator {
//     pub(crate) free_list: LinkedList,
//     pub(crate) allocations_made: u128,
// }
// impl Allocator {
//     pub const fn new() -> Self {
//         Allocator {
//             free_list: LinkedList::new(),
//             allocations_made: 0,
//         }
//     }
//     unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
//         assert!(size >= size_of::<ListNode>());

//         // create a new list node and append it at the start of the list
//         let mut node = ListNode::new(size);
//         node.next = self.free_list.head.next.take();
//         let node_ptr = addr as *mut ListNode;
//         node_ptr.write(node);
//         self.free_list.head.next = Some(&mut *node_ptr);
//     }

//     fn find_region(&mut self, size: usize, align: usize) -> Option<(&'static mut ListNode, usize)> {
//         let mut best_fit_size = usize::MAX;
//         let mut best_fit_prev: *mut ListNode = ptr::null_mut();
//         let mut best_fit_alloc_start = 0usize;

//         let mut current = &mut self.free_list.head as *mut ListNode;

//         unsafe {
//             // Traverse the free list
//             while let Some(ref mut region) = (*current).next {
//                 if let Ok(alloc_start) = Self::alloc_from_region(region, size, align) {
//                     let region_size = region.size;
//                     if region_size < best_fit_size {
//                         best_fit_size = region_size;
//                         best_fit_prev = current;
//                         best_fit_alloc_start = alloc_start;
//                     }
//                 }
//                 // Move to the next region
//                 current = &mut **region as *mut ListNode;
//             }

//             if !best_fit_prev.is_null() {
//                 let best_fit_prev_ref = &mut *best_fit_prev;
//                 let best_fit_region = best_fit_prev_ref.next.take().unwrap();
//                 let next = best_fit_region.next.take();
//                 best_fit_prev_ref.next = next;

//                 return Some((best_fit_region, best_fit_alloc_start));
//             }
//         }

//         None
//     }
//     fn alloc_from_region(region: &mut ListNode, size: usize, align: usize) -> Result<usize, ()> {
//         let alloc_start = align_up(region.start_addr() as u64, align as u64);
//         let alloc_end = alloc_start.checked_add(size as u64).ok_or(())?;

//         if alloc_end > region.end_addr() as u64 {
//             return Err(());
//         }

//         let excess_size = region.end_addr() as u64 - alloc_end;
//         if excess_size > 0 && excess_size < size_of::<ListNode>() as u64 {
//             // rest of region too small to hold a ListNode (required because the
//             // allocation splits the region in a used and a free part)
//             return Err(());
//         }

//         Ok(alloc_start as usize)
//     }
//     fn size_align(layout: Layout) -> (usize, usize) {
//         let layout = layout
//             .align_to(align_of::<ListNode>())
//             .expect("adjusting alignment failed")
//             .pad_to_align();
//         let size = layout.size().max(size_of::<ListNode>());
//         (size, layout.align())
//     }
//     pub(crate) fn free_memory(&self) -> usize {
//         let mut current = &self.free_list.head;
//         let mut total_free = 0;

//         while let Some(ref region) = current.next {
//             total_free += region.size;
//             current = region;
//         }

//         total_free
//     }

//     pub fn merge_free_list(&mut self) {
//         unsafe {
//             let mut current = self.free_list.head.start_addr() as *mut ListNode;

//             while !current.is_null() {
//                 let current_node = &mut *current;

//                 if let Some(ref mut next_ref) = current_node.next {
//                     let next_ptr = &mut **next_ref as *mut ListNode;
//                     let next_node = &mut *next_ptr;

//                     if current_node.end_addr() == next_node.start_addr() {
//                         current_node.size += next_node.size;

//                         current_node.next = next_node.next.take();
//                     } else {
//                         current = next_ptr;
//                     }
//                 } else {
//                     break;
//                 }
//             }
//         }
//     }
// }
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
