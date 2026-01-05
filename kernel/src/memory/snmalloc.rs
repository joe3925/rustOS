// snmalloc.rs
#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

extern "C" {
    fn sn_rust_alloc(alignment: usize, size: usize) -> *mut u8;
    fn sn_rust_alloc_zeroed(alignment: usize, size: usize) -> *mut u8;
    fn sn_rust_dealloc(ptr: *mut u8, alignment: usize, size: usize);
    fn sn_rust_realloc(ptr: *mut u8, alignment: usize, old_size: usize, new_size: usize)
        -> *mut u8;
    fn sn_rust_statistics(current: *mut usize, peak: *mut usize);
    fn sn_rust_usable_size(ptr: *const u8) -> usize;
}

pub struct SnMalloc;

unsafe impl GlobalAlloc for SnMalloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        sn_rust_alloc(layout.align(), layout.size())
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        sn_rust_alloc_zeroed(layout.align(), layout.size())
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        sn_rust_dealloc(p, layout.align(), layout.size())
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        sn_rust_realloc(p, layout.align(), layout.size(), new_size)
    }
}

pub fn usable_size(p: *const u8) -> usize {
    unsafe { sn_rust_usable_size(p) }
}

pub fn statistics() -> (usize, usize) {
    let mut current = 0usize;
    let mut peak = 0usize;
    unsafe { sn_rust_statistics(&mut current, &mut peak) };
    (current, peak)
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_reserve(size: usize) -> *mut u8 {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_reserve_aligned(size: usize, alignment: usize) -> *mut u8 {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_release(base: *mut u8, size: usize) {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_commit(base: *mut u8, size: usize, zero: bool) -> bool {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_decommit(base: *mut u8, size: usize) {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_message_cstr(s: *const u8) {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_error_cstr(s: *const u8) -> ! {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_entropy64() -> u64 {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_time_ms() -> u64 {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_wait_on_u8(addr: *const u8, expected: u8) {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_wake_one_u8(addr: *const u8) {
    todo!();
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_wake_all_u8(addr: *const u8) {
    todo!();
}

// C runtime stubs required by snmalloc in freestanding environment

/// Thread-local destructor registration - not supported in kernel, just ignore
#[no_mangle]
pub unsafe extern "C" fn __cxa_thread_atexit(
    _dtor: extern "C" fn(*mut core::ffi::c_void),
    _obj: *mut core::ffi::c_void,
    _dso_symbol: *mut core::ffi::c_void,
) -> i32 {
    // In a kernel without thread-local storage cleanup, we just return success
    // and don't actually register anything. The destructor won't be called.
    0
}

/// errno location for newlib - returns pointer to a static errno variable
static mut ERRNO_VALUE: i32 = 0;

#[no_mangle]
pub unsafe extern "C" fn __errno() -> *mut i32 {
    core::ptr::addr_of_mut!(ERRNO_VALUE)
}
