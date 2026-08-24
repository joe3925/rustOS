pub(super) unsafe fn drop_inline<F>(ptr: *mut u8) { unsafe {
    core::ptr::drop_in_place(ptr as *mut F);
}}
