pub(super) struct CachePadded<T>(T);

impl<T> CachePadded<T> {
    pub(super) const fn new(v: T) -> Self {
        Self(v)
    }
}

impl<T> core::ops::Deref for CachePadded<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::DerefMut for CachePadded<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

pub(super) unsafe fn drop_inline<F>(ptr: *mut u8) {
    core::ptr::drop_in_place(ptr as *mut F);
}
