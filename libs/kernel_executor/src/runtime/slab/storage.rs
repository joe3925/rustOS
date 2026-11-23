#[cfg_attr(irq_check, irq::forbidden)]
pub(super) unsafe fn drop_future<F>(ptr: *mut u8) { unsafe {
    core::ptr::drop_in_place(ptr as *mut F);
}}
