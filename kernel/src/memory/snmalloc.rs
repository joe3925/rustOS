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

// freestanding libc-ish exports that C++ may pull in
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    ptr::copy_nonoverlapping(src, dst, n);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    ptr::copy(src, dst, n);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    ptr::write_bytes(dst, c as u8, n);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    while i < n {
        let av = *a.add(i);
        let bv = *b.add(i);
        if av != bv {
            return av as i32 - bv as i32;
        }
        i += 1;
    }
    0
}
