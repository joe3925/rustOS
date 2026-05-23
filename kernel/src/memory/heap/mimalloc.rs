use crate::cpu;
use crate::memory::heap::{
    HEAP_SIZE, HEAP_START, MIMALLOC_ARENA_SIZE, MIMALLOC_ARENA_START, MIMALLOC_HEAP_SIZE,
    MIMALLOC_HEAP_START, MIMALLOC_OS_HEAP_SIZE,
};
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::paging::{map_kernel_2mib_frame, unmap_range_keep_frames_unchecked};
use crate::memory::paging::tables::init_mapper;
use crate::structs::linked_list::{LinkedList, ListNode};
use crate::util::boot_info;
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_abi::MemoryRegionKind;
use x86_64::align_up;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageSize, PageTableFlags, PhysFrame, Size2MiB,
};
use x86_64::{PhysAddr, VirtAddr};

const PAGE_SIZE: usize = 4096;
const MIMALLOC_COMMIT_GRANULARITY: usize = 1024 * 1024 * 1024;
const MIMALLOC_HEAP_END: usize = MIMALLOC_HEAP_START + MIMALLOC_HEAP_SIZE as usize;
const MIMALLOC_COMMIT_TRACK_START: usize =
    align_down_const(MIMALLOC_ARENA_START, MIMALLOC_COMMIT_GRANULARITY);
const MIMALLOC_COMMIT_TRACK_END: usize = align_up_const(
    MIMALLOC_ARENA_START + MIMALLOC_ARENA_SIZE as usize,
    MIMALLOC_COMMIT_GRANULARITY,
);
const MIMALLOC_COMMIT_CHUNKS: usize =
    (MIMALLOC_COMMIT_TRACK_END - MIMALLOC_COMMIT_TRACK_START) / MIMALLOC_COMMIT_GRANULARITY;
const MIMALLOC_COMMIT_BITMAP_BITS: usize = usize::BITS as usize;
const MIMALLOC_COMMIT_BITMAP_WORDS: usize =
    (MIMALLOC_COMMIT_CHUNKS + MIMALLOC_COMMIT_BITMAP_BITS - 1) / MIMALLOC_COMMIT_BITMAP_BITS;

pub static MIMALLOC_ARENA_COMMITTED: AtomicUsize = AtomicUsize::new(0);
static MIMALLOC_COMMIT_LOCK: spin::Mutex<()> = spin::Mutex::new(());
static MIMALLOC_COMMIT_BITMAP: [AtomicUsize; MIMALLOC_COMMIT_BITMAP_WORDS] =
    [const { AtomicUsize::new(0) }; MIMALLOC_COMMIT_BITMAP_WORDS];
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
    mi_process_init();
    rustos_mi_configure_options();
    init_mimalloc_diagnostics();
    if !rustos_mi_manage_arena(
        MIMALLOC_ARENA_START as *mut c_void,
        MIMALLOC_ARENA_SIZE as usize,
    ) {
        panic!("failed to register rustOS mimalloc arena");
    }
}

pub unsafe fn mimalloc_thread_done_impl() {
    mi_thread_done();
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
    (addr >= MIMALLOC_HEAP_START && addr < MIMALLOC_HEAP_END) || ptr_is_raw_large(ptr)
}

pub fn get_mimalloc_free_memory() -> usize {
    MIMALLOC_OS_ALLOCATOR.lock().free_memory()
}

pub unsafe fn mimalloc_alloc(layout: Layout) -> *mut u8 {
    let start = cpu::get_cycles();
    let mut ptr = null_mut();
    if raw_large_alloc_enabled(layout.size(), layout.align()) {
        ptr = RAW_LARGE_ALLOCATOR
            .lock()
            .alloc(layout.size(), layout.align());
    }
    if ptr.is_null() {
        ptr = mi_malloc_aligned(layout.size().max(1), layout.align()) as *mut u8;
    }
    let elapsed = cpu::get_cycles().wrapping_sub(start);
    MIMALLOC_ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
    MIMALLOC_ALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
    ptr
}

pub unsafe fn mimalloc_alloc_zeroed(layout: Layout) -> *mut u8 {
    let start = cpu::get_cycles();
    let mut ptr = null_mut();
    if raw_large_alloc_enabled(layout.size(), layout.align()) {
        ptr = RAW_LARGE_ALLOCATOR
            .lock()
            .alloc(layout.size(), layout.align());
        if !ptr.is_null() {
            core::ptr::write_bytes(ptr, 0, layout.size());
        }
    }
    if ptr.is_null() {
        ptr = mi_zalloc_aligned(layout.size().max(1), layout.align()) as *mut u8;
    }
    let elapsed = cpu::get_cycles().wrapping_sub(start);
    MIMALLOC_ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
    MIMALLOC_ALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
    ptr
}

pub unsafe fn mimalloc_dealloc(ptr: *mut u8, layout: Layout) {
    let start = cpu::get_cycles();
    if ptr_is_raw_large(ptr) {
        if RAW_LARGE_ALLOCATOR.lock().dealloc(ptr) {
            let elapsed = cpu::get_cycles().wrapping_sub(start);
            MIMALLOC_DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            MIMALLOC_DEALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            MIMALLOC_DEALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
            return;
        }
    }
    mi_free(ptr.cast::<c_void>());
    let elapsed = cpu::get_cycles().wrapping_sub(start);
    MIMALLOC_DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_DEALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
    MIMALLOC_DEALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
}

pub unsafe fn mimalloc_realloc(ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let start = cpu::get_cycles();
    let new_ptr = if ptr_is_raw_large(ptr) {
        RAW_LARGE_ALLOCATOR
            .lock()
            .realloc(ptr, layout.size(), new_size, layout.align())
    } else if raw_large_alloc_enabled(new_size, layout.align()) {
        let raw_ptr = RAW_LARGE_ALLOCATOR.lock().alloc(new_size, layout.align());
        if !raw_ptr.is_null() {
            core::ptr::copy_nonoverlapping(ptr, raw_ptr, core::cmp::min(layout.size(), new_size));
            mi_free(ptr.cast::<c_void>());
            raw_ptr
        } else {
            mi_realloc_aligned(ptr.cast::<c_void>(), new_size.max(1), layout.align()) as *mut u8
        }
    } else {
        mi_realloc_aligned(ptr.cast::<c_void>(), new_size.max(1), layout.align()) as *mut u8
    };
    let elapsed = cpu::get_cycles().wrapping_sub(start);
    MIMALLOC_REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_REALLOC_OLD_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
    MIMALLOC_REALLOC_NEW_BYTES.fetch_add(new_size, Ordering::Relaxed);
    MIMALLOC_REALLOC_CYCLES.fetch_add(elapsed, Ordering::Relaxed);
    new_ptr
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

        let size = align_up(size as u64, PAGE_SIZE as u64) as usize;
        if size == 0 {
            return null_mut();
        }
        let align = align.max(PAGE_SIZE);

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
        core::ptr::write_bytes(alloc_start as *mut u8, 0, size);
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

        let size = align_up(size as u64, PAGE_SIZE as u64) as usize;
        self.add_free_region(addr, size);
        self.free_bytes = self.free_bytes.saturating_add(size).min(self.size);
    }

    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        if size < core::mem::size_of::<ListNode>() || size < PAGE_SIZE {
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
        let mut best_fit_size = usize::MAX;
        let mut best_fit_prev: *mut ListNode = core::ptr::null_mut();
        let mut best_fit_alloc_start = 0usize;

        let mut prev: *mut ListNode = &mut self.free_list.head as *mut ListNode;

        unsafe {
            while let Some(next_ref) = (*prev).next.as_mut() {
                let region_ptr = &mut **next_ref as *mut ListNode;

                if let Ok(alloc_start) = Self::alloc_from_region(&mut *region_ptr, size, align) {
                    let region_size = (*region_ptr).size;
                    if region_size < best_fit_size {
                        best_fit_size = region_size;
                        best_fit_prev = prev;
                        best_fit_alloc_start = alloc_start;
                    }
                }

                prev = region_ptr;
            }

            if best_fit_prev.is_null() {
                return None;
            }

            let prev_ref = &mut *best_fit_prev;
            let region = prev_ref.next.take().unwrap();
            let next = region.next.take();
            prev_ref.next = next;

            Some((region, best_fit_alloc_start))
        }
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

const RAW_LARGE_THRESHOLD: usize = 2 * 1024 * 1024;
const RAW_LARGE_UNIT_SIZE: usize = Size2MiB::SIZE as usize;
const RAW_LARGE_HEAP_START: usize = HEAP_START + HEAP_SIZE as usize;
const RAW_LARGE_HEAP_SIZE: usize = 8 * 1024 * 1024 * 1024;
const RAW_LARGE_SLOT_SIZE: usize = 512 * 1024 * 1024;
const RAW_LARGE_SLOT_UNITS: usize = RAW_LARGE_SLOT_SIZE / RAW_LARGE_UNIT_SIZE;
const RAW_LARGE_FULL_SLOT_ACTIVE_COUNT: usize = 4;
const RAW_LARGE_RESERVATION_WORKING_SET_UNITS: usize =
    ((HEAP_SIZE as usize / 4) + RAW_LARGE_UNIT_SIZE - 1) / RAW_LARGE_UNIT_SIZE;
const RAW_LARGE_UNITS: usize = RAW_LARGE_HEAP_SIZE / RAW_LARGE_UNIT_SIZE;
const RAW_LARGE_BITMAP_WORD_BITS: usize = usize::BITS as usize;
const RAW_LARGE_BITMAP_WORDS: usize =
    (RAW_LARGE_UNITS + RAW_LARGE_BITMAP_WORD_BITS - 1) / RAW_LARGE_BITMAP_WORD_BITS;
const RAW_LARGE_MAX_ALLOCS: usize = 256;

#[derive(Clone, Copy)]
struct RawLargeMeta {
    base_unit: usize,
    reserved_units: usize,
    committed_units: usize,
    active: bool,
}

impl RawLargeMeta {
    const EMPTY: Self = Self {
        base_unit: 0,
        reserved_units: 0,
        committed_units: 0,
        active: false,
    };
}

struct RawLargeAllocator {
    used: [usize; RAW_LARGE_BITMAP_WORDS],
    frames: [usize; RAW_LARGE_UNITS],
    metas: [RawLargeMeta; RAW_LARGE_MAX_ALLOCS],
}

static RAW_LARGE_ALLOCATOR: spin::Mutex<RawLargeAllocator> =
    spin::Mutex::new(RawLargeAllocator::new());

impl RawLargeAllocator {
    const fn new() -> Self {
        Self {
            used: [0; RAW_LARGE_BITMAP_WORDS],
            frames: [0; RAW_LARGE_UNITS],
            metas: [RawLargeMeta::EMPTY; RAW_LARGE_MAX_ALLOCS],
        }
    }

    #[inline(always)]
    fn contains_addr(addr: usize) -> bool {
        addr >= RAW_LARGE_HEAP_START && addr < RAW_LARGE_HEAP_START + RAW_LARGE_HEAP_SIZE
    }

    #[inline(always)]
    fn unit_addr(unit: usize) -> usize {
        RAW_LARGE_HEAP_START + unit * RAW_LARGE_UNIT_SIZE
    }

    #[inline(always)]
    fn units_for_size(size: usize) -> Option<usize> {
        if size == 0 {
            return Some(1);
        }
        let rounded = size.checked_add(RAW_LARGE_UNIT_SIZE - 1)? & !(RAW_LARGE_UNIT_SIZE - 1);
        Some(rounded / RAW_LARGE_UNIT_SIZE)
    }

    #[inline(always)]
    fn align_units(align: usize) -> usize {
        let align = align.max(RAW_LARGE_UNIT_SIZE);
        (align + RAW_LARGE_UNIT_SIZE - 1) / RAW_LARGE_UNIT_SIZE
    }

    #[inline(always)]
    fn bit_is_set(&self, unit: usize) -> bool {
        let word = unit / RAW_LARGE_BITMAP_WORD_BITS;
        let bit = unit & (RAW_LARGE_BITMAP_WORD_BITS - 1);
        (self.used[word] & (1usize << bit)) != 0
    }

    #[inline(always)]
    fn set_bit(&mut self, unit: usize) {
        let word = unit / RAW_LARGE_BITMAP_WORD_BITS;
        let bit = unit & (RAW_LARGE_BITMAP_WORD_BITS - 1);
        self.used[word] |= 1usize << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, unit: usize) {
        let word = unit / RAW_LARGE_BITMAP_WORD_BITS;
        let bit = unit & (RAW_LARGE_BITMAP_WORD_BITS - 1);
        self.used[word] &= !(1usize << bit);
    }

    fn run_is_free(&self, start: usize, units: usize) -> bool {
        if units == 0
            || start
                .checked_add(units)
                .is_none_or(|end| end > RAW_LARGE_UNITS)
        {
            return false;
        }
        for unit in start..start + units {
            if self.bit_is_set(unit) {
                return false;
            }
        }
        true
    }

    fn set_run(&mut self, start: usize, units: usize) {
        for unit in start..start + units {
            self.set_bit(unit);
        }
    }

    fn clear_run(&mut self, start: usize, units: usize) {
        for unit in start..start + units {
            self.clear_bit(unit);
        }
    }

    fn find_free_run(&self, units: usize, align_units: usize) -> Option<usize> {
        if units == 0 || units > RAW_LARGE_UNITS {
            return None;
        }

        let align_units = align_units.max(1);
        let mut start = 0usize;
        while start + units <= RAW_LARGE_UNITS {
            let rem = start % align_units;
            if rem != 0 {
                start += align_units - rem;
                continue;
            }

            if self.run_is_free(start, units) {
                return Some(start);
            }
            start += 1;
        }
        None
    }

    fn find_meta_by_base(&self, base_unit: usize) -> Option<usize> {
        self.metas
            .iter()
            .position(|meta| meta.active && meta.base_unit == base_unit)
    }

    fn find_free_meta(&self) -> Option<usize> {
        self.metas.iter().position(|meta| !meta.active)
    }

    fn active_alloc_count(&self) -> usize {
        self.metas.iter().filter(|meta| meta.active).count()
    }

    fn reservation_units(active_count: usize, committed_units: usize) -> usize {
        let active_count = active_count.max(1);
        let fair_units =
            (RAW_LARGE_RESERVATION_WORKING_SET_UNITS + active_count - 1) / active_count;
        committed_units.max(fair_units.min(RAW_LARGE_SLOT_UNITS))
    }

    fn shrink_active_reservations(&mut self, target_units: usize) {
        for idx in 0..self.metas.len() {
            let meta = self.metas[idx];
            if !meta.active {
                continue;
            }

            let new_reserved_units = meta.committed_units.max(target_units);
            if meta.reserved_units <= new_reserved_units {
                continue;
            }

            let free_start = meta.base_unit + new_reserved_units;
            let free_units = meta.reserved_units - new_reserved_units;
            self.clear_run(free_start, free_units);
            self.metas[idx].reserved_units = new_reserved_units;
        }
    }

    unsafe fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        let Some(committed_units) = Self::units_for_size(size) else {
            return null_mut();
        };

        let active_count_after_alloc = self.active_alloc_count().saturating_add(1);
        let reserved_units = if active_count_after_alloc <= RAW_LARGE_FULL_SLOT_ACTIVE_COUNT {
            committed_units.max(RAW_LARGE_SLOT_UNITS)
        } else {
            Self::reservation_units(active_count_after_alloc, committed_units)
        };
        if active_count_after_alloc > RAW_LARGE_FULL_SLOT_ACTIVE_COUNT {
            self.shrink_active_reservations(reserved_units);
        }

        let align_units = Self::align_units(align);
        let Some(meta_idx) = self.find_free_meta() else {
            return null_mut();
        };
        let Some(base_unit) = self.find_free_run(reserved_units, align_units) else {
            return null_mut();
        };

        self.set_run(base_unit, reserved_units);
        if !unsafe { self.ensure_units_mapped(base_unit, committed_units) } {
            self.clear_run(base_unit, reserved_units);
            return null_mut();
        }

        self.metas[meta_idx] = RawLargeMeta {
            base_unit,
            reserved_units,
            committed_units,
            active: true,
        };

        Self::unit_addr(base_unit) as *mut u8
    }

    unsafe fn dealloc(&mut self, ptr: *mut u8) -> bool {
        let addr = ptr as usize;
        if !Self::contains_addr(addr) || (addr - RAW_LARGE_HEAP_START) % RAW_LARGE_UNIT_SIZE != 0 {
            return false;
        }

        let base_unit = (addr - RAW_LARGE_HEAP_START) / RAW_LARGE_UNIT_SIZE;
        let Some(meta_idx) = self.find_meta_by_base(base_unit) else {
            return false;
        };

        let meta = self.metas[meta_idx];
        self.clear_run(meta.base_unit, meta.reserved_units);
        self.metas[meta_idx] = RawLargeMeta::EMPTY;
        true
    }

    unsafe fn realloc(
        &mut self,
        ptr: *mut u8,
        _old_size: usize,
        new_size: usize,
        align: usize,
    ) -> *mut u8 {
        let addr = ptr as usize;
        if !Self::contains_addr(addr) || (addr - RAW_LARGE_HEAP_START) % RAW_LARGE_UNIT_SIZE != 0 {
            return null_mut();
        }

        let old_base_unit = (addr - RAW_LARGE_HEAP_START) / RAW_LARGE_UNIT_SIZE;
        let Some(meta_idx) = self.find_meta_by_base(old_base_unit) else {
            return null_mut();
        };
        let Some(new_units) = Self::units_for_size(new_size) else {
            return null_mut();
        };

        let meta = self.metas[meta_idx];
        if new_units <= meta.reserved_units {
            if new_units > meta.committed_units
                && !unsafe {
                    self.ensure_units_mapped(
                        meta.base_unit + meta.committed_units,
                        new_units - meta.committed_units,
                    )
                }
            {
                return null_mut();
            }
            self.metas[meta_idx].committed_units =
                self.metas[meta_idx].committed_units.max(new_units);
            return ptr;
        }

        let align_units = Self::align_units(align);
        let Some(new_base_unit) = self.find_free_run(new_units, align_units) else {
            return null_mut();
        };

        self.set_run(new_base_unit, new_units);

        for offset in 0..meta.committed_units {
            let old_unit = meta.base_unit + offset;
            let new_unit = new_base_unit + offset;
            let phys = self.frames[old_unit];
            if phys == 0
                || !unsafe { self.replace_unit_mapping(new_unit, PhysAddr::new(phys as u64)) }
            {
                self.clear_run(new_base_unit, new_units);
                return null_mut();
            }
        }

        if !unsafe {
            self.ensure_units_mapped(
                new_base_unit + meta.committed_units,
                new_units - meta.committed_units,
            )
        } {
            self.clear_run(new_base_unit, new_units);
            return null_mut();
        }

        unsafe {
            unmap_range_keep_frames_unchecked(
                VirtAddr::new(Self::unit_addr(meta.base_unit) as u64),
                (meta.committed_units * RAW_LARGE_UNIT_SIZE) as u64,
            );
        }
        for unit in meta.base_unit..meta.base_unit + meta.committed_units {
            self.frames[unit] = 0;
        }
        self.clear_run(meta.base_unit, meta.reserved_units);

        self.metas[meta_idx] = RawLargeMeta {
            base_unit: new_base_unit,
            reserved_units: new_units,
            committed_units: new_units,
            active: true,
        };

        Self::unit_addr(new_base_unit) as *mut u8
    }

    unsafe fn ensure_units_mapped(&mut self, start: usize, units: usize) -> bool {
        if units == 0 {
            return true;
        }

        let boot_info = boot_info();
        let phys_mem_offset =
            VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut mapper = init_mapper(phys_mem_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE;

        let end = start + units;
        let mut unit = start;
        while unit < end {
            if self.frames[unit] != 0 {
                unit += 1;
                continue;
            }

            let run_start = unit;
            while unit < end && self.frames[unit] == 0 {
                unit += 1;
            }
            let run_units = unit - run_start;

            match unsafe {
                self.ensure_units_mapped_contiguous(
                    run_start,
                    run_units,
                    &mut mapper,
                    &mut frame_allocator,
                    flags,
                )
            } {
                Ok(true) => continue,
                Ok(false) => {}
                Err(()) => return false,
            }

            for offset in 0..run_units {
                let cur_unit = run_start + offset;
                if !unsafe {
                    self.ensure_unit_mapped_single(
                        cur_unit,
                        &mut mapper,
                        &mut frame_allocator,
                        flags,
                    )
                } {
                    return false;
                }
            }
        }

        true
    }

    unsafe fn ensure_units_mapped_contiguous(
        &mut self,
        start: usize,
        units: usize,
        mapper: &mut impl Mapper<Size2MiB>,
        frame_allocator: &mut BootInfoFrameAllocator,
        flags: PageTableFlags,
    ) -> Result<bool, ()> {
        let Some(phys_base) = BootInfoFrameAllocator::allocate_contiguous_2mib_frames(units) else {
            return Ok(false);
        };

        for offset in 0..units {
            let unit = start + offset;
            let phys = PhysAddr::new(phys_base.as_u64() + (offset * RAW_LARGE_UNIT_SIZE) as u64);
            let frame = PhysFrame::<Size2MiB>::containing_address(phys);
            let page =
                Page::<Size2MiB>::containing_address(VirtAddr::new(Self::unit_addr(unit) as u64));
            let mapped = unsafe { mapper.map_to(page, frame, flags, frame_allocator) };

            if mapped.is_err() {
                for rollback_offset in offset..units {
                    let rollback_phys = PhysAddr::new(
                        phys_base.as_u64() + (rollback_offset * RAW_LARGE_UNIT_SIZE) as u64,
                    );
                    frame_allocator
                        .deallocate_frame(PhysFrame::<Size2MiB>::containing_address(rollback_phys));
                }
                return Err(());
            }

            self.frames[unit] = phys.as_u64() as usize;
        }

        Ok(true)
    }

    unsafe fn ensure_unit_mapped_single(
        &mut self,
        unit: usize,
        mapper: &mut impl Mapper<Size2MiB>,
        frame_allocator: &mut BootInfoFrameAllocator,
        flags: PageTableFlags,
    ) -> bool {
        let Some(frame) =
            <BootInfoFrameAllocator as FrameAllocator<Size2MiB>>::allocate_frame(frame_allocator)
        else {
            return false;
        };

        let phys = frame.start_address();
        let page =
            Page::<Size2MiB>::containing_address(VirtAddr::new(Self::unit_addr(unit) as u64));
        let mapped = unsafe { mapper.map_to(page, frame, flags, frame_allocator) };

        if mapped.is_err() {
            frame_allocator.deallocate_frame(frame);
            return false;
        }

        self.frames[unit] = phys.as_u64() as usize;
        true
    }

    unsafe fn replace_unit_mapping(&mut self, unit: usize, phys: PhysAddr) -> bool {
        if self.frames[unit] != 0 {
            unsafe {
                unmap_range_keep_frames_unchecked(
                    VirtAddr::new(Self::unit_addr(unit) as u64),
                    RAW_LARGE_UNIT_SIZE as u64,
                );
            }

            let boot_info = boot_info();
            let frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
            frame_allocator.deallocate_frame(PhysFrame::<Size2MiB>::containing_address(
                PhysAddr::new(self.frames[unit] as u64),
            ));
            self.frames[unit] = 0;
        }

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        if unsafe {
            map_kernel_2mib_frame(
                VirtAddr::new(Self::unit_addr(unit) as u64),
                phys,
                flags,
                false,
            )
        }
        .is_err()
        {
            return false;
        }

        self.frames[unit] = phys.as_u64() as usize;
        true
    }
}

fn raw_large_alloc_enabled(size: usize, align: usize) -> bool {
    size >= RAW_LARGE_THRESHOLD && align <= RAW_LARGE_UNIT_SIZE
}

fn ptr_is_raw_large(ptr: *mut u8) -> bool {
    RawLargeAllocator::contains_addr(ptr as usize)
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
    let start_cycles = crate::cpu::get_cycles();
    MIMALLOC_COMMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    MIMALLOC_COMMIT_REQUESTED.fetch_add(size, Ordering::Relaxed);

    let addr_usize = addr as usize;
    let Some(end_usize) = addr_usize.checked_add(size) else {
        crate::println!(
            "MIMALLOC COMMIT FAILED: address={:p}, size={}, reason=Address overflow",
            addr,
            size
        );
        MIMALLOC_COMMIT_CYCLES.fetch_add(
            crate::cpu::get_cycles().wrapping_sub(start_cycles),
            Ordering::Relaxed,
        );
        return false;
    };

    if addr_usize < MIMALLOC_ARENA_START
        || end_usize > MIMALLOC_ARENA_START + (MIMALLOC_ARENA_SIZE as usize)
    {
        crate::println!(
            "MIMALLOC COMMIT FAILED: address={:p}, size={}, reason=Address out of arena bounds",
            addr,
            size
        );
        MIMALLOC_COMMIT_CYCLES.fetch_add(
            crate::cpu::get_cycles().wrapping_sub(start_cycles),
            Ordering::Relaxed,
        );
        return false;
    }

    let flags = x86_64::structures::paging::PageTableFlags::PRESENT
        | x86_64::structures::paging::PageTableFlags::WRITABLE;

    let commit_start =
        align_down_const(addr_usize, MIMALLOC_COMMIT_GRANULARITY).max(MIMALLOC_COMMIT_TRACK_START);
    let commit_end =
        align_up_const(end_usize, MIMALLOC_COMMIT_GRANULARITY).min(MIMALLOC_COMMIT_TRACK_END);

    let first_chunk = (commit_start - MIMALLOC_COMMIT_TRACK_START) / MIMALLOC_COMMIT_GRANULARITY;
    let last_chunk = (commit_end - MIMALLOC_COMMIT_TRACK_START) / MIMALLOC_COMMIT_GRANULARITY;

    let _commit_guard = MIMALLOC_COMMIT_LOCK.lock();
    let mut chunk = first_chunk;
    while chunk < last_chunk {
        if mimalloc_commit_chunk_is_set(chunk) {
            chunk += 1;
            continue;
        }

        let run_start = chunk;
        chunk += 1;
        while chunk < last_chunk && !mimalloc_commit_chunk_is_set(chunk) {
            chunk += 1;
        }

        let run_addr = MIMALLOC_COMMIT_TRACK_START + run_start * MIMALLOC_COMMIT_GRANULARITY;
        let run_size = (chunk - run_start) * MIMALLOC_COMMIT_GRANULARITY;
        let start_addr = x86_64::VirtAddr::new(run_addr as u64);

        let res = without_interrupts(|| {
            crate::memory::paging::paging::map_fresh_kernel_range_no_flush(
                start_addr,
                run_size as u64,
                flags,
                true,
            )
        });

        if let Err(e) = res {
            crate::println!("MIMALLOC COMMIT FAILED: address={:p}, size={}, commit_start={:#x}, commit_size={}, flags={:?}, reason=Page mapping failed ({:?})", addr, size, run_addr, run_size, flags, e);
            MIMALLOC_COMMIT_CYCLES.fetch_add(
                crate::cpu::get_cycles().wrapping_sub(start_cycles),
                Ordering::Relaxed,
            );
            return false;
        }

        mimalloc_commit_mark_range(run_start, chunk);
        MIMALLOC_COMMIT_MAP_CALLS.fetch_add(1, Ordering::Relaxed);
        MIMALLOC_COMMIT_MAPPED.fetch_add(run_size, Ordering::Relaxed);
        MIMALLOC_ARENA_COMMITTED.fetch_add(run_size, Ordering::Relaxed);
    }

    MIMALLOC_COMMIT_CYCLES.fetch_add(
        crate::cpu::get_cycles().wrapping_sub(start_cycles),
        Ordering::Relaxed,
    );
    true
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
    if addr.is_null() {
        return;
    }
    without_interrupts(|| MIMALLOC_OS_ALLOCATOR.lock().free(addr.cast::<u8>(), size));
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
    let cycles = crate::cpu::get_cycles();
    let hz = crate::drivers::interrupt_index::TSC_HZ.load(Ordering::Relaxed);
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

    let mut state = crate::cpu::get_cycles()
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
    core::hint::spin_loop();
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

#[inline(always)]
fn mimalloc_commit_chunk_is_set(chunk: usize) -> bool {
    let word = chunk / MIMALLOC_COMMIT_BITMAP_BITS;
    let bit = chunk % MIMALLOC_COMMIT_BITMAP_BITS;
    (MIMALLOC_COMMIT_BITMAP[word].load(Ordering::Relaxed) & (1usize << bit)) != 0
}

#[inline(always)]
fn mimalloc_commit_mark_range(start: usize, end: usize) {
    for chunk in start..end {
        let word = chunk / MIMALLOC_COMMIT_BITMAP_BITS;
        let bit = chunk % MIMALLOC_COMMIT_BITMAP_BITS;
        MIMALLOC_COMMIT_BITMAP[word].fetch_or(1usize << bit, Ordering::Relaxed);
    }
}
