// snmalloc.rs
#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

use crate::cpu;
use crate::drivers::interrupt_index::current_cpu_id;
use crate::memory::heap::{HEAP_SIZE, HEAP_START};
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::paging::{map_page, map_range_with_huge_pages, unmap_range_unchecked};
use crate::memory::paging::tables::init_mapper;
use crate::scheduling::scheduler::{TaskHandle, SCHEDULER};
use crate::static_handlers::task_yield;
use crate::util::TOTAL_TIME;
use core::alloc::{GlobalAlloc, Layout};
use core::array;
use core::ffi::CStr;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use x86_64::structures::paging::{mapper::MapToError, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

/// Simple bump allocator for snmalloc's backend memory requests.
/// This hands out memory from the pre-mapped heap region.
/// Memory is never actually freed back (bump allocator), but snmalloc
/// manages its own free lists on top of this.
static HEAP_BUMP: AtomicUsize = AtomicUsize::new(HEAP_START);
const MAX_WAITERS: usize = 512;
unsafe impl Send for Waiter {}
unsafe impl Sync for Waiter {}
struct Waiter {
    addr: *const u8,
    task: TaskHandle,
}

lazy_static! {
    static ref WAITERS: Mutex<[Option<Waiter>; MAX_WAITERS]> = {
        let arr = array::from_fn(|_| None);
        Mutex::new(arr)
    };
}
extern "C" {
    fn sn_rust_init(base: *mut u8, length: usize);
    fn sn_rust_alloc(alignment: usize, size: usize) -> *mut u8;
    fn sn_rust_alloc_zeroed(alignment: usize, size: usize) -> *mut u8;
    fn sn_rust_dealloc(ptr: *mut u8, alignment: usize, size: usize);
    fn sn_rust_realloc(ptr: *mut u8, alignment: usize, old_size: usize, new_size: usize)
        -> *mut u8;
    fn sn_rust_statistics(current: *mut usize, peak: *mut usize);
    fn sn_rust_usable_size(ptr: *const u8) -> usize;
}

/// Initialize snmalloc with the heap region.
/// Must be called before any allocations.
pub fn init() {
    unsafe {
        sn_rust_init(HEAP_START as *mut u8, HEAP_SIZE);
    }
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

const HEAP_END: usize = HEAP_START + HEAP_SIZE;

/// Aligns `addr` up to `alignment`. Alignment must be a power of two.
#[inline]
const fn align_up(addr: usize, alignment: usize) -> usize {
    (addr + alignment - 1) & !(alignment - 1)
}

#[inline]
const fn align_down(addr: usize, alignment: usize) -> usize {
    addr & !(alignment - 1)
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_reserve(size: usize) -> *mut u8 {
    krnl_snmalloc_reserve_aligned(size, 0x1000)
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_reserve_aligned(size: usize, alignment: usize) -> *mut u8 {
    let alignment = alignment.max(0x1000);
    let size = align_up(size, 0x1000);

    loop {
        let current = HEAP_BUMP.load(Ordering::Relaxed);
        let aligned_start = align_up(current, alignment);
        let new_end = match aligned_start.checked_add(size) {
            Some(end) => end,
            None => return ptr::null_mut(),
        };

        if new_end > HEAP_END {
            return ptr::null_mut();
        }

        match HEAP_BUMP.compare_exchange_weak(current, new_end, Ordering::AcqRel, Ordering::Relaxed)
        {
            Ok(_) => return aligned_start as *mut u8,
            Err(_) => continue,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_release(_base: *mut u8, _size: usize) {
    if !_base.is_null() && _size != 0 {
        let start = align_down(_base as usize, 0x1000);
        let end = align_up(start + _size, 0x1000);
        unmap_range_unchecked(VirtAddr::new(start as u64), (end - start) as u64);
    }
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_commit(base: *mut u8, size: usize, zero: bool) -> bool {
    if base.is_null() || size == 0 {
        return true;
    }

    let boot_info = crate::util::boot_info();
    let phys_mem_offset =
        VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap_or(0));
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_alloc = BootInfoFrameAllocator::init();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    map_range_with_huge_pages(
        &mut mapper,
        VirtAddr::new(base as u64),
        size.try_into().unwrap(),
        &mut frame_alloc,
        flags,
    )
    .expect("Failed to commit memory for snmalloc ");
    if zero {
        ptr::write_bytes(base, 0, size);
    }

    true
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_decommit(_base: *mut u8, _size: usize) {
    if _base.is_null() || _size == 0 {
        return;
    }
    let start = align_down(_base as usize, 0x1000);
    let end = align_up(start + _size, 0x1000);
    unmap_range_unchecked(VirtAddr::new(start as u64), (end - start) as u64);
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_message_cstr(s: *const u8) {
    if s.is_null() {
        return;
    }
    // match CStr::from_ptr(s as *const i8).to_str() {
    //     Ok(msg) => println!("[snmalloc] {}", msg),
    //     Err(_) => println!("[snmalloc] <invalid utf8>"),
    // }
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_error_cstr(s: *const u8) -> ! {
    if !s.is_null() {
        if let Ok(msg) = CStr::from_ptr(s as *const i8).to_str() {
            //println!("[snmalloc error] {}", msg);
        }
    }

    panic!("snmalloc fatal error");
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_entropy64() -> u64 {
    cpu::get_cycles()
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_time_ms() -> u64 {
    match TOTAL_TIME.get() {
        Some(sw) => sw.elapsed_millis(),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_wait_on_u8(addr: *const u8, expected: u8) {
    // short spin first
    for _ in 0..64 {
        if ptr::read_volatile(addr) != expected {
            return;
        }
        core::hint::spin_loop();
    }

    loop {
        if ptr::read_volatile(addr) != expected {
            return;
        }

        let parked = without_interrupts(|| {
            if ptr::read_volatile(addr) != expected {
                return false;
            }
            let Some(task) = SCHEDULER.get_current_task(current_cpu_id() as usize) else {
                return false;
            };

            let mut waiters = WAITERS.lock();
            if let Some(slot) = waiters.iter_mut().find(|w| w.is_none()) {
                *slot = Some(Waiter {
                    addr,
                    task: task.clone(),
                });
                return task.read().park_begin();
            }
            false
        });

        if !parked {
            return;
        }

        task_yield(); // scheduler parks us; woken via wake_* below

        // clean up stale registrations for this task/address
        if let Some(me) = SCHEDULER.get_current_task(current_cpu_id() as usize) {
            let mut waiters = WAITERS.lock();
            for slot in waiters.iter_mut() {
                if let Some(w) = slot {
                    if w.addr == addr && Arc::ptr_eq(&w.task, &me) {
                        *slot = None;
                    }
                }
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_wake_one_u8(addr: *const u8) {
    let mut waiters = WAITERS.lock();
    if let Some((idx, waiter)) = waiters
        .iter_mut()
        .enumerate()
        .find_map(|(i, w)| w.take().map(|v| (i, v)).filter(|(_, v)| v.addr == addr))
    {
        waiters[idx] = None;
        SCHEDULER.wake_task(&waiter.task);
    }
}

#[no_mangle]
pub unsafe extern "C" fn krnl_snmalloc_wake_all_u8(addr: *const u8) {
    let mut waiters = WAITERS.lock();
    for slot in waiters.iter_mut() {
        if let Some(w) = slot.take() {
            if w.addr == addr {
                SCHEDULER.wake_task(&w.task);
            } else {
                *slot = Some(w);
            }
        }
    }
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
