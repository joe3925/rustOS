use crate::memory::heap::buddylocked::BuddyLocked;
use core::alloc::{GlobalAlloc, Layout};

cfg_if::cfg_if! {
    if #[cfg(feature = "allocator-mimalloc")] {
        use crate::memory::heap::mimalloc as mi;
        use core::sync::atomic::{AtomicBool, Ordering};

        pub struct KernelAllocator {
            bootstrap: BuddyLocked,
            mimalloc_enabled: AtomicBool,
            enable_lock: spin::Mutex<()>,
        }

        impl KernelAllocator {
            pub const fn new() -> Self {
                Self {
                    bootstrap: BuddyLocked::new(),
                    mimalloc_enabled: AtomicBool::new(false),
                    enable_lock: spin::Mutex::new(()),
                }
            }

            pub fn enable_mimalloc(&self) {
                if self.mimalloc_enabled.load(Ordering::Acquire) {
                    return;
                }

                let _guard = self.enable_lock.lock();
                if !self.mimalloc_enabled.load(Ordering::Acquire) {
                    unsafe { mi::enable_mimalloc_impl(); }
                    self.mimalloc_enabled.store(true, Ordering::Release);
                }
            }

            #[inline(always)]
            pub fn mimalloc_enabled(&self) -> bool {
                self.mimalloc_enabled.load(Ordering::Acquire)
            }

            pub fn mimalloc_thread_done(&self) {
                if self.mimalloc_enabled() {
                    unsafe { mi::mimalloc_thread_done_impl(); }
                }
            }

            pub fn free_memory(&self) -> usize {
                self.bootstrap.free_memory() + mi::get_mimalloc_free_memory()
            }
        }

        unsafe impl GlobalAlloc for KernelAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                if self.mimalloc_enabled() {
                    mi::mimalloc_alloc(layout)
                } else {
                    self.bootstrap.alloc(layout)
                }
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                if self.mimalloc_enabled() {
                    mi::mimalloc_alloc_zeroed(layout)
                } else {
                    let ptr = self.bootstrap.alloc(layout);
                    if !ptr.is_null() {
                        core::ptr::write_bytes(ptr, 0, layout.size());
                    }
                    ptr
                }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                if ptr.is_null() {
                    return;
                }

                if mi::ptr_is_mimalloc(ptr) {
                    mi::mimalloc_dealloc(ptr, layout)
                } else {
                    self.bootstrap.dealloc(ptr, layout)
                }
            }

            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                if ptr.is_null() {
                    return self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
                }

                if mi::ptr_is_mimalloc(ptr) {
                    mi::mimalloc_realloc(ptr, layout, new_size)
                } else {
                    let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
                    let new_ptr = self.alloc(new_layout);
                    if !new_ptr.is_null() {
                        core::ptr::copy_nonoverlapping(
                            ptr,
                            new_ptr,
                            core::cmp::min(layout.size(), new_size),
                        );
                        self.bootstrap.dealloc(ptr, layout);
                    }
                    new_ptr
                }
            }
        }

    } else if #[cfg(feature = "allocator-buddy")] {
        pub struct KernelAllocator {
            inner: BuddyLocked,
        }

        impl KernelAllocator {
            pub const fn new() -> Self {
                Self {
                    inner: BuddyLocked::new(),
                }
            }

            pub fn enable_mimalloc(&self) {
                // No-op for buddy allocator
            }

            pub fn mimalloc_thread_done(&self) {
                // No-op
            }

            pub fn free_memory(&self) -> usize {
                self.inner.free_memory()
            }
        }

        unsafe impl GlobalAlloc for KernelAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                self.inner.alloc(layout)
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                self.inner.alloc_zeroed(layout)
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                self.inner.dealloc(ptr, layout)
            }
        }
    } else {
        compile_error!("Must enable either 'allocator-mimalloc' or 'allocator-buddy' feature.");
    }
}
