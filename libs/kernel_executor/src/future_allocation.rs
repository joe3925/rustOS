use alloc::alloc::{Layout, alloc, dealloc};
use core::ptr::NonNull;

#[derive(Debug)]
pub struct FutureAllocation {
    pub ptr: NonNull<u8>,
    pub layout: Layout,
}

unsafe impl Send for FutureAllocation {}

impl FutureAllocation {
    #[inline]
    pub(crate) fn allocate(size: usize, align: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size.max(1), align.max(1)).ok()?;
        let ptr = NonNull::new(unsafe { alloc(layout) })?;
        Some(Self { ptr, layout })
    }

    #[inline]
    pub(crate) unsafe fn release(self) {
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}
