use buddy_system_allocator::LockedHeap;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::instructions::interrupts::without_interrupts;

use crate::memory::heap::HEAP_START;

#[cfg(feature = "allocator-buddy")]
use crate::memory::heap::HEAP_SIZE;

#[cfg(feature = "allocator-mimalloc")]
use crate::memory::heap::BOOTSTRAP_HEAP_SIZE;

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
                    #[cfg(feature = "allocator-mimalloc")]
                    let size = BOOTSTRAP_HEAP_SIZE as usize;
                    #[cfg(feature = "allocator-buddy")]
                    let size = HEAP_SIZE as usize;

                    self.inner.lock().init(HEAP_START, size);
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

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            core::ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.ensure_init();
        without_interrupts(|| {
            self.inner.lock().dealloc(
                NonNull::new(ptr).expect("null ptr passed to kernel heap dealloc"),
                layout,
            )
        })
    }
}
