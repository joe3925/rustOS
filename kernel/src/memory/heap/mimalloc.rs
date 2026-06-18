use crate::memory::heap::{
    mimalloc_arena_size, mimalloc_heap_end, MIMALLOC_ARENA_START, MIMALLOC_HEAP_START,
    MIMALLOC_OS_HEAP_SIZE,
};
use crate::memory::paging::{
    align_up_to_base_page, base_page_size, map_fresh_kernel_range_no_flush, unmap_range_unchecked,
};
use crate::platform;
use crate::structs::linked_list::{LinkedList, ListNode};
use crate::util::boot_info;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_abi::MemoryRegionKind;

use crate::arch::interrupts::without_interrupts;
use crate::arch::{align_up, interrupts, VirtAddr};
use kernel_types::arch::PageFlags;

const MIMALLOC_STATS_ENABLED: bool = false;
const MIMALLOC_OS_ALLOC_ZEROES: bool = false;
const MIMALLOC_COMMIT_GRANULARITY: usize = 2 * 1024 * 1024;
const MIMALLOC_COMMIT_BITMAP_BITS: usize = usize::BITS as usize;

pub static MIMALLOC_ARENA_COMMITTED: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_COMMIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_COMMIT_MAP_CALLS: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_COMMIT_REQUESTED: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_COMMIT_MAPPED: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_COMMIT_CYCLES: AtomicU64 = AtomicU64::new(0);
static MIMALLOC_ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_ALLOC_CYCLES: AtomicU64 = AtomicU64::new(0);
static MIMALLOC_REALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_REALLOC_OLD_BYTES: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_REALLOC_NEW_BYTES: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_REALLOC_CYCLES: AtomicU64 = AtomicU64::new(0);
static MIMALLOC_DEALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_DEALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_DEALLOC_CYCLES: AtomicU64 = AtomicU64::new(0);

struct MimallocCommitTracker {
    track_start: usize,
    track_end: usize,
    bitmap: Vec<usize>,
}

impl MimallocCommitTracker {
    const fn new() -> Self {
        Self {
            track_start: 0,
            track_end: 0,
            bitmap: Vec::new(),
        }
    }

    fn init(&mut self, arena_start: usize, arena_size: usize) {
        let arena_end = arena_start
            .checked_add(arena_size)
            .expect("mimalloc arena end overflow");
        let track_start = align_down_const(arena_start, MIMALLOC_COMMIT_GRANULARITY);
        let track_end = align_up_const(arena_end, MIMALLOC_COMMIT_GRANULARITY);
        let chunks = (track_end - track_start) / MIMALLOC_COMMIT_GRANULARITY;
        let words = (chunks + MIMALLOC_COMMIT_BITMAP_BITS - 1) / MIMALLOC_COMMIT_BITMAP_BITS;

        let mut bitmap = Vec::new();
        bitmap
            .try_reserve_exact(words)
            .expect("failed to reserve mimalloc commit bitmap");
        bitmap.resize(words, 0);

        self.track_start = track_start;
        self.track_end = track_end;
        self.bitmap = bitmap;
    }

    fn chunk_range(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        if self.bitmap.is_empty() || start < self.track_start || end > self.track_end {
            return None;
        }

        Some((
            (start - self.track_start) / MIMALLOC_COMMIT_GRANULARITY,
            (end - self.track_start) / MIMALLOC_COMMIT_GRANULARITY,
        ))
    }

    #[inline(always)]
    fn chunk_is_set(&self, chunk: usize) -> bool {
        let word = chunk / MIMALLOC_COMMIT_BITMAP_BITS;
        let bit = chunk % MIMALLOC_COMMIT_BITMAP_BITS;
        self.bitmap
            .get(word)
            .is_some_and(|value| (value & (1usize << bit)) != 0)
    }

    #[inline(always)]
    fn mark_range(&mut self, start: usize, end: usize) {
        for chunk in start..end {
            let word = chunk / MIMALLOC_COMMIT_BITMAP_BITS;
            let bit = chunk % MIMALLOC_COMMIT_BITMAP_BITS;
            self.bitmap[word] |= 1usize << bit;
        }
    }

    #[inline(always)]
    fn clear_range(&mut self, start: usize, end: usize) {
        for chunk in start..end {
            let word = chunk / MIMALLOC_COMMIT_BITMAP_BITS;
            let bit = chunk % MIMALLOC_COMMIT_BITMAP_BITS;
            self.bitmap[word] &= !(1usize << bit);
        }
    }
}

static MIMALLOC_COMMIT_TRACKER: spin::Mutex<MimallocCommitTracker> =
    spin::Mutex::new(MimallocCommitTracker::new());

pub struct MimallocCommitStats {
    pub calls: usize,
    pub map_calls: usize,
    pub requested: usize,
    pub mapped: usize,
    pub cycles: u64,
}

pub struct MimallocAllocStats {
    pub alloc_calls: usize,
    pub alloc_bytes: usize,
    pub alloc_cycles: u64,
    pub realloc_calls: usize,
    pub realloc_old_bytes: usize,
    pub realloc_new_bytes: usize,
    pub realloc_cycles: u64,
    pub dealloc_calls: usize,
    pub dealloc_bytes: usize,
    pub dealloc_cycles: u64,
}

unsafe extern "C" {
    fn mi_process_init();
    fn mi_thread_done();
    fn mi_collect(force: bool);
    fn mi_malloc(size: usize) -> *mut c_void;
    fn mi_zalloc(size: usize) -> *mut c_void;
    fn mi_realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void;
    fn mi_malloc_aligned(size: usize, alignment: usize) -> *mut c_void;
    fn mi_zalloc_aligned(size: usize, alignment: usize) -> *mut c_void;
    fn mi_realloc_aligned(ptr: *mut c_void, new_size: usize, alignment: usize) -> *mut c_void;
    fn mi_free(ptr: *mut c_void);
    fn rustos_mi_configure_options();
    fn rustos_mi_manage_arena(start: *mut c_void, size: usize) -> bool;
}

static MIMALLOC_OS_ALLOCATOR: Locked<RangeAllocator> = Locked::new(RangeAllocator::new(
    MIMALLOC_HEAP_START,
    MIMALLOC_OS_HEAP_SIZE as usize,
));

pub unsafe fn enable_mimalloc_impl() {
    let arena_size = mimalloc_arena_size();
    if arena_size < MIMALLOC_COMMIT_GRANULARITY {
        panic!(
            "mimalloc arena too small: start={:#x}, size={}",
            MIMALLOC_ARENA_START, arena_size
        );
    }

    MIMALLOC_COMMIT_TRACKER
        .lock()
        .init(MIMALLOC_ARENA_START, arena_size);
    MIMALLOC_ARENA_COMMITTED.store(0, Ordering::Release);

    mi_process_init();
    rustos_mi_configure_options();
    init_mimalloc_diagnostics();
    if !rustos_mi_manage_arena(MIMALLOC_ARENA_START as *mut c_void, arena_size) {
        panic!("failed to register rustOS mimalloc arena");
    }
}

pub unsafe fn mimalloc_thread_done_impl() {
    mi_thread_done();
}

pub fn mimalloc_collect(force: bool) {
    unsafe {
        mi_collect(force);
    }
}

pub fn mimalloc_commit_stats_reset() {
    MIMALLOC_COMMIT_CALLS.store(0, Ordering::Relaxed);
    MIMALLOC_COMMIT_MAP_CALLS.store(0, Ordering::Relaxed);
    MIMALLOC_COMMIT_REQUESTED.store(0, Ordering::Relaxed);
    MIMALLOC_COMMIT_MAPPED.store(0, Ordering::Relaxed);
    MIMALLOC_COMMIT_CYCLES.store(0, Ordering::Relaxed);
}

pub fn mimalloc_alloc_stats_reset() {
    MIMALLOC_ALLOC_CALLS.store(0, Ordering::Relaxed);
    MIMALLOC_ALLOC_BYTES.store(0, Ordering::Relaxed);
    MIMALLOC_ALLOC_CYCLES.store(0, Ordering::Relaxed);
    MIMALLOC_REALLOC_CALLS.store(0, Ordering::Relaxed);
    MIMALLOC_REALLOC_OLD_BYTES.store(0, Ordering::Relaxed);
    MIMALLOC_REALLOC_NEW_BYTES.store(0, Ordering::Relaxed);
    MIMALLOC_REALLOC_CYCLES.store(0, Ordering::Relaxed);
    MIMALLOC_DEALLOC_CALLS.store(0, Ordering::Relaxed);
    MIMALLOC_DEALLOC_BYTES.store(0, Ordering::Relaxed);
    MIMALLOC_DEALLOC_CYCLES.store(0, Ordering::Relaxed);
}

pub fn mimalloc_commit_stats() -> MimallocCommitStats {
    MimallocCommitStats {
        calls: MIMALLOC_COMMIT_CALLS.load(Ordering::Relaxed),
        map_calls: MIMALLOC_COMMIT_MAP_CALLS.load(Ordering::Relaxed),
        requested: MIMALLOC_COMMIT_REQUESTED.load(Ordering::Relaxed),
        mapped: MIMALLOC_COMMIT_MAPPED.load(Ordering::Relaxed),
        cycles: MIMALLOC_COMMIT_CYCLES.load(Ordering::Relaxed),
    }
}

pub fn mimalloc_alloc_stats() -> MimallocAllocStats {
    MimallocAllocStats {
        alloc_calls: MIMALLOC_ALLOC_CALLS.load(Ordering::Relaxed),
        alloc_bytes: MIMALLOC_ALLOC_BYTES.load(Ordering::Relaxed),
        alloc_cycles: MIMALLOC_ALLOC_CYCLES.load(Ordering::Relaxed),
        realloc_calls: MIMALLOC_REALLOC_CALLS.load(Ordering::Relaxed),
        realloc_old_bytes: MIMALLOC_REALLOC_OLD_BYTES.load(Ordering::Relaxed),
        realloc_new_bytes: MIMALLOC_REALLOC_NEW_BYTES.load(Ordering::Relaxed),
        realloc_cycles: MIMALLOC_REALLOC_CYCLES.load(Ordering::Relaxed),
        dealloc_calls: MIMALLOC_DEALLOC_CALLS.load(Ordering::Relaxed),
        dealloc_bytes: MIMALLOC_DEALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_cycles: MIMALLOC_DEALLOC_CYCLES.load(Ordering::Relaxed),
    }
}

#[inline(always)]
pub fn ptr_is_mimalloc(ptr: *mut u8) -> bool {
    let addr = ptr as usize;
    addr >= MIMALLOC_HEAP_START && addr < mimalloc_heap_end()
}

pub fn get_mimalloc_free_memory() -> usize {
    MIMALLOC_OS_ALLOCATOR.lock().free_memory()
}

pub unsafe fn mimalloc_alloc(layout: Layout) -> *mut u8 {
    let start = mimalloc_stats_start();
    let size = layout.size().max(1);
    let ptr = if layout.align() <= core::mem::align_of::<usize>() {
        mi_malloc(size)
    } else {
        mi_malloc_aligned(size, layout.align())
    } as *mut u8;
    mimalloc_record_alloc(layout.size(), start);
    ptr
}

pub unsafe fn mimalloc_alloc_zeroed(layout: Layout) -> *mut u8 {
    let start = mimalloc_stats_start();
    let size = layout.size().max(1);
    let ptr = if layout.align() <= core::mem::align_of::<usize>() {
        mi_zalloc(size)
    } else {
        mi_zalloc_aligned(size, layout.align())
    } as *mut u8;
    mimalloc_record_alloc(layout.size(), start);
    ptr
}

pub unsafe fn mimalloc_dealloc(ptr: *mut u8, layout: Layout) {
    let start = mimalloc_stats_start();
    mi_free(ptr.cast::<c_void>());
    mimalloc_record_dealloc(layout.size(), start);
}

pub unsafe fn mimalloc_realloc(ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let start = mimalloc_stats_start();
    let size = new_size.max(1);
    let new_ptr = if layout.align() <= core::mem::align_of::<usize>() {
        mi_realloc(ptr.cast::<c_void>(), size)
    } else {
        mi_realloc_aligned(ptr.cast::<c_void>(), size, layout.align())
    } as *mut u8;
    mimalloc_record_realloc(layout.size(), new_size, start);
    new_ptr
}

#[inline(always)]
fn mimalloc_stats_start() -> u64 {
    if MIMALLOC_STATS_ENABLED {
        platform::cycle_counter()
    } else {
        0
    }
}

#[inline(always)]
fn mimalloc_record_alloc(size: usize, start: u64) {
    if !MIMALLOC_STATS_ENABLED {
        return;
    }

    let elapsed = platform::cycle_counter().wrapping_sub(start);
    MIMALLOC_ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_ALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
    MIMALLOC_ALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline(always)]
fn mimalloc_record_dealloc(size: usize, start: u64) {
    if !MIMALLOC_STATS_ENABLED {
        return;
    }

    let elapsed = platform::cycle_counter().wrapping_sub(start);
    MIMALLOC_DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_DEALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
    MIMALLOC_DEALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline(always)]
fn mimalloc_record_realloc(old_size: usize, new_size: usize, start: u64) {
    if !MIMALLOC_STATS_ENABLED {
        return;
    }

    let elapsed = platform::cycle_counter().wrapping_sub(start);
    MIMALLOC_REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_REALLOC_OLD_BYTES.fetch_add(old_size, Ordering::Relaxed);
    MIMALLOC_REALLOC_NEW_BYTES.fetch_add(new_size, Ordering::Relaxed);
    MIMALLOC_REALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
}

pub struct Locked<A> {
    inner: spin::Mutex<A>,
}

impl<A> Locked<A> {
    pub const fn new(inner: A) -> Self {
        Self {
            inner: spin::Mutex::new(inner),
        }
    }

    pub fn lock(&self) -> spin::MutexGuard<'_, A> {
        self.inner.lock()
    }
}

struct RangeAllocator {
    free_list: LinkedList,
    initialized: bool,
    start: usize,
    size: usize,
    free_bytes: usize,
}

impl RangeAllocator {
    pub const fn new(start: usize, size: usize) -> Self {
        Self {
            free_list: LinkedList::new(),
            initialized: false,
            start,
            size,
            free_bytes: 0,
        }
    }

    fn ensure_init(&mut self) {
        if self.initialized {
            return;
        }

        unsafe {
            let node_ptr = self.start as *mut ListNode;
            node_ptr.write(ListNode::new(self.size));
            self.free_list.head.next = node_ptr.as_mut();
        }

        self.free_bytes = self.size;
        self.initialized = true;
    }

    fn free_memory(&self) -> usize {
        self.free_bytes
    }

    unsafe fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        self.ensure_init();

        let size = align_up_to_base_page(size as u64).unwrap_or(0) as usize;
        if size == 0 {
            return null_mut();
        }
        let align = align.max(base_page_size() as usize);

        let Some((region, alloc_start)) = self.find_region(size, align) else {
            return null_mut();
        };

        let region_start = region.start_addr();
        let region_end = region.end_addr();
        let alloc_end = alloc_start + size;

        if alloc_start > region_start {
            self.add_free_region(region_start, alloc_start - region_start);
        }
        if alloc_end < region_end {
            self.add_free_region(alloc_end, region_end - alloc_end);
        }

        self.free_bytes = self.free_bytes.saturating_sub(size);
        if MIMALLOC_OS_ALLOC_ZEROES {
            core::ptr::write_bytes(alloc_start as *mut u8, 0, size);
        }
        alloc_start as *mut u8
    }

    unsafe fn free(&mut self, ptr: *mut u8, size: usize) {
        if ptr.is_null() || size == 0 {
            return;
        }

        self.ensure_init();

        let addr = ptr as usize;
        if addr < self.start || addr >= self.start + self.size {
            return;
        }

        let size = align_up_to_base_page(size as u64).unwrap_or(0) as usize;
        self.add_free_region(addr, size);
        self.free_bytes = self.free_bytes.saturating_add(size).min(self.size);
    }

    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        if size < core::mem::size_of::<ListNode>() || size < base_page_size() as usize {
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

        let cur_ptr: *mut ListNode = node_ptr;

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
        let mut prev: *mut ListNode = &mut self.free_list.head as *mut ListNode;

        unsafe {
            while let Some(next_ref) = (*prev).next.as_mut() {
                let region_ptr = &mut **next_ref as *mut ListNode;

                if let Ok(alloc_start) = Self::alloc_from_region(&mut *region_ptr, size, align) {
                    let prev_ref = &mut *prev;
                    let region = prev_ref.next.take().unwrap();
                    let next = region.next.take();
                    prev_ref.next = next;
                    return Some((region, alloc_start));
                }

                prev = region_ptr;
            }
        }

        None
    }

    fn alloc_from_region(region: &mut ListNode, size: usize, align: usize) -> Result<usize, ()> {
        let region_start = region.start_addr();
        let region_end = region.end_addr();

        let alloc_start = align_up(region_start as u64, align as u64) as usize;
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

unsafe extern "C" {
    fn mi_register_output(
        cb: extern "C" fn(msg: *const core::ffi::c_char, arg: *mut c_void),
        arg: *mut c_void,
    );
    fn mi_register_error(cb: extern "C" fn(err: i32, arg: *mut c_void), arg: *mut c_void);
}

extern "C" fn mimalloc_output_cb(msg: *const core::ffi::c_char, _arg: *mut c_void) {
    if msg.is_null() {
        return;
    }
    let mut len = 0;
    while unsafe { *msg.add(len) } != 0 {
        len += 1;
    }
    let s = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(msg as *const u8, len))
    };
    crate::println!("MIMALLOC: {}", s.trim_end());
}

extern "C" fn mimalloc_error_cb(err: i32, _arg: *mut c_void) {
    match err {
        11 => crate::println!("MIMALLOC ERROR: EAGAIN (double free)"),
        12 => crate::println!("MIMALLOC ERROR: ENOMEM (out of memory)"),
        14 => crate::println!("MIMALLOC ERROR: EFAULT (corrupted free list/metadata)"),
        22 => crate::println!("MIMALLOC ERROR: EINVAL (invalid pointer)"),
        75 => crate::println!("MIMALLOC ERROR: EOVERFLOW (allocation size overflow)"),
        _ => crate::println!("MIMALLOC ERROR: {}", err),
    }
}

static MIMALLOC_DIAGNOSTICS_INIT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn init_mimalloc_diagnostics() {
    if !MIMALLOC_DIAGNOSTICS_INIT.swap(true, core::sync::atomic::Ordering::SeqCst) {
        unsafe {
            mi_register_output(mimalloc_output_cb, null_mut());
            mi_register_error(mimalloc_error_cb, null_mut());
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rustos_mi_os_commit(addr: *mut c_void, size: usize) -> bool {
    let start_cycles = mimalloc_stats_start();

    if MIMALLOC_STATS_ENABLED {
        MIMALLOC_COMMIT_CALLS.fetch_add(1, Ordering::Relaxed);
        MIMALLOC_COMMIT_REQUESTED.fetch_add(size, Ordering::Relaxed);
    }

    let addr_usize = addr as usize;
    let Some(end_usize) = addr_usize.checked_add(size) else {
        crate::println!(
            "MIMALLOC COMMIT FAILED: address={:p}, size={}, reason=Address overflow",
            addr,
            size
        );
        mimalloc_record_commit_cycles(start_cycles);
        return false;
    };

    let Some(arena_end) = MIMALLOC_ARENA_START.checked_add(mimalloc_arena_size()) else {
        crate::println!(
            "MIMALLOC COMMIT FAILED: address={:p}, size={}, reason=Arena bounds overflow",
            addr,
            size
        );
        mimalloc_record_commit_cycles(start_cycles);
        return false;
    };

    if addr_usize < MIMALLOC_ARENA_START || end_usize > arena_end {
        crate::println!(
            "MIMALLOC COMMIT FAILED: address={:p}, size={}, reason=Address out of arena bounds",
            addr,
            size
        );
        mimalloc_record_commit_cycles(start_cycles);
        return false;
    }

    let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE;

    let mut tracker = MIMALLOC_COMMIT_TRACKER.lock();
    let commit_start =
        align_down_const(addr_usize, MIMALLOC_COMMIT_GRANULARITY).max(tracker.track_start);
    let commit_end = align_up_const(end_usize, MIMALLOC_COMMIT_GRANULARITY).min(tracker.track_end);

    let Some((first_chunk, last_chunk)) = tracker.chunk_range(commit_start, commit_end) else {
        crate::println!(
            "MIMALLOC COMMIT FAILED: address={:p}, size={}, reason=Commit tracker not initialized",
            addr,
            size
        );
        mimalloc_record_commit_cycles(start_cycles);
        return false;
    };

    let mut chunk = first_chunk;
    while chunk < last_chunk {
        if tracker.chunk_is_set(chunk) {
            chunk += 1;
            continue;
        }

        let run_start = chunk;
        chunk += 1;
        while chunk < last_chunk && !tracker.chunk_is_set(chunk) {
            chunk += 1;
        }

        let run_addr = tracker.track_start + run_start * MIMALLOC_COMMIT_GRANULARITY;
        let run_size = (chunk - run_start) * MIMALLOC_COMMIT_GRANULARITY;
        let start_addr = VirtAddr::new(run_addr as u64);

        let res = without_interrupts(|| {
            map_fresh_kernel_range_no_flush(start_addr.into(), run_size as u64, flags, true)
        });

        if let Err(e) = res {
            crate::println!(
                "MIMALLOC COMMIT FAILED: address={:p}, size={}, commit_start={:#x}, commit_size={}, flags={:?}, reason=Page mapping failed ({:?})",
                addr,
                size,
                run_addr,
                run_size,
                flags,
                e
            );
            mimalloc_record_commit_cycles(start_cycles);
            return false;
        }

        tracker.mark_range(run_start, chunk);
        MIMALLOC_ARENA_COMMITTED.fetch_add(run_size, Ordering::Relaxed);
        if MIMALLOC_STATS_ENABLED {
            MIMALLOC_COMMIT_MAP_CALLS.fetch_add(1, Ordering::Relaxed);
            MIMALLOC_COMMIT_MAPPED.fetch_add(run_size, Ordering::Relaxed);
        }
    }

    mimalloc_record_commit_cycles(start_cycles);
    true
}

#[no_mangle]
pub unsafe extern "C" fn rustos_mi_os_decommit(addr: *mut c_void, size: usize) -> bool {
    if addr.is_null() || size == 0 {
        return true;
    }

    let addr_usize = addr as usize;
    let Some(end_usize) = addr_usize.checked_add(size) else {
        crate::println!(
            "MIMALLOC DECOMMIT FAILED: address={:p}, size={}, reason=Address overflow",
            addr,
            size
        );
        return false;
    };

    let Some(arena_end) = MIMALLOC_ARENA_START.checked_add(mimalloc_arena_size()) else {
        crate::println!(
            "MIMALLOC DECOMMIT FAILED: address={:p}, size={}, reason=Arena bounds overflow",
            addr,
            size
        );
        return false;
    };

    if addr_usize < MIMALLOC_ARENA_START || end_usize > arena_end {
        crate::println!(
            "MIMALLOC DECOMMIT FAILED: address={:p}, size={}, reason=Address out of arena bounds",
            addr,
            size
        );
        return false;
    }

    let decommit_start =
        align_up_const(addr_usize, MIMALLOC_COMMIT_GRANULARITY).max(MIMALLOC_ARENA_START);
    let decommit_end = align_down_const(end_usize, MIMALLOC_COMMIT_GRANULARITY).min(arena_end);
    if decommit_end <= decommit_start {
        return true;
    }

    let mut tracker = MIMALLOC_COMMIT_TRACKER.lock();
    let Some((first_chunk, last_chunk)) = tracker.chunk_range(decommit_start, decommit_end) else {
        crate::println!(
            "MIMALLOC DECOMMIT FAILED: address={:p}, size={}, reason=Commit tracker not initialized",
            addr,
            size
        );
        return false;
    };

    let mut chunk = first_chunk;
    while chunk < last_chunk {
        if !tracker.chunk_is_set(chunk) {
            chunk += 1;
            continue;
        }

        let run_start = chunk;
        chunk += 1;
        while chunk < last_chunk && tracker.chunk_is_set(chunk) {
            chunk += 1;
        }

        let run_addr = tracker.track_start + run_start * MIMALLOC_COMMIT_GRANULARITY;
        let run_size = (chunk - run_start) * MIMALLOC_COMMIT_GRANULARITY;

        without_interrupts(|| unsafe {
            unmap_range_unchecked(VirtAddr::new(run_addr as u64).into(), run_size as u64);
        });

        tracker.clear_range(run_start, chunk);
        MIMALLOC_ARENA_COMMITTED.fetch_sub(run_size, Ordering::Relaxed);
    }

    true
}

#[inline(always)]
fn mimalloc_record_commit_cycles(start: u64) {
    if MIMALLOC_STATS_ENABLED {
        MIMALLOC_COMMIT_CYCLES.fetch_add(
            platform::cycle_counter().wrapping_sub(start),
            Ordering::Relaxed,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn rustos_mi_os_alloc(size: usize, alignment: usize) -> *mut c_void {
    let ptr = without_interrupts(|| {
        MIMALLOC_OS_ALLOCATOR
            .lock()
            .alloc(size, alignment)
            .cast::<c_void>()
    });

    if ptr.is_null() {
        crate::println!(
            "MIMALLOC ALLOC FAILED: size={}, alignment={}, reason=Out of OS allocator memory",
            size,
            alignment
        );
    }

    ptr
}

#[no_mangle]
pub unsafe extern "C" fn rustos_mi_os_free(addr: *mut c_void, size: usize) {
    if !addr.is_null() {
        without_interrupts(|| MIMALLOC_OS_ALLOCATOR.lock().free(addr.cast::<u8>(), size));
    }
}

#[no_mangle]
pub extern "C" fn rustos_mi_physical_memory_kib() -> usize {
    let bytes = boot_info()
        .memory_regions
        .iter()
        .filter(|region| region.kind == MemoryRegionKind::Usable)
        .fold(0u128, |sum, region| {
            sum + (region.end - region.start) as u128
        });

    (bytes / 1024).min(usize::MAX as u128) as usize
}

#[no_mangle]
pub extern "C" fn rustos_mi_clock_now() -> u64 {
    let cycles = platform::cycle_counter();
    let hz = platform::cycle_counter_frequency_hz();
    if hz == 0 {
        cycles
    } else {
        ((cycles as u128 * 1000) / hz as u128) as u64
    }
}

#[no_mangle]
pub unsafe extern "C" fn rustos_mi_random_buf(buf: *mut c_void, len: usize) -> bool {
    if buf.is_null() {
        return false;
    }

    let mut state = platform::cycle_counter()
        ^ (buf as u64).rotate_left(17)
        ^ (len as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let bytes = core::slice::from_raw_parts_mut(buf.cast::<u8>(), len);
    for byte in bytes {
        state = splitmix64(state);
        *byte = (state >> 56) as u8;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn rustos_mi_out_stderr(_msg: *const i8) {}

#[no_mangle]
pub extern "C" fn rustos_mi_thread_yield() {
    if interrupts::are_enabled() {
        interrupts::hlt();
    } else {
        core::hint::spin_loop();
    }
}

#[inline(always)]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

const fn align_down_const(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

const fn align_up_const(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
