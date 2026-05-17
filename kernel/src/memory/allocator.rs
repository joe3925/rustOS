use crate::memory::heap::{
    BOOTSTRAP_HEAP_SIZE, HEAP_START, MIMALLOC_ARENA_SIZE, MIMALLOC_ARENA_START, MIMALLOC_HEAP_SIZE,
    MIMALLOC_HEAP_START, MIMALLOC_META_HEAP_SIZE,
};
use crate::structs::linked_list::{LinkedList, ListNode};
use crate::util::boot_info;
use buddy_system_allocator::LockedHeap;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use x86_64::align_up;
use x86_64::instructions::interrupts::without_interrupts;

const PAGE_SIZE: usize = 4096;
const MIMALLOC_HEAP_END: usize = MIMALLOC_HEAP_START + MIMALLOC_HEAP_SIZE as usize;

pub static MIMALLOC_ARENA_COMMITTED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn mi_process_init();
    fn mi_thread_done();
    fn mi_malloc_aligned(size: usize, alignment: usize) -> *mut c_void;
    fn mi_zalloc_aligned(size: usize, alignment: usize) -> *mut c_void;
    fn mi_realloc_aligned(ptr: *mut c_void, new_size: usize, alignment: usize) -> *mut c_void;
    fn mi_free(ptr: *mut c_void);
    fn rustos_mi_manage_arena(start: *mut c_void, size: usize) -> bool;
}

#[global_allocator]
pub static ALLOCATOR: KernelAllocator = KernelAllocator::new();

static MIMALLOC_OS_ALLOCATOR: Locked<RangeAllocator> = Locked::new(RangeAllocator::new(
    MIMALLOC_HEAP_START,
    MIMALLOC_META_HEAP_SIZE as usize,
));

pub fn enable_mimalloc() {
    ALLOCATOR.enable_mimalloc();
}

pub fn mimalloc_thread_done() {
    ALLOCATOR.mimalloc_thread_done();
}

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
            unsafe {
                mi_process_init();
                init_mimalloc_diagnostics();
                if !rustos_mi_manage_arena(
                    MIMALLOC_ARENA_START as *mut c_void,
                    MIMALLOC_ARENA_SIZE as usize,
                ) {
                    panic!("failed to register rustOS mimalloc arena");
                }
            }
            self.mimalloc_enabled.store(true, Ordering::Release);
        }
    }

    #[inline(always)]
    pub fn mimalloc_enabled(&self) -> bool {
        self.mimalloc_enabled.load(Ordering::Acquire)
    }

    pub fn mimalloc_thread_done(&self) {
        if self.mimalloc_enabled() {
            unsafe {
                mi_thread_done();
            }
        }
    }

    pub fn free_memory(&self) -> usize {
        self.bootstrap.free_memory() + MIMALLOC_OS_ALLOCATOR.lock().free_memory()
    }

    #[inline(always)]
    fn ptr_is_mimalloc(ptr: *mut u8) -> bool {
        let addr = ptr as usize;
        addr >= MIMALLOC_HEAP_START && addr < MIMALLOC_HEAP_END
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.mimalloc_enabled() {
            mi_malloc_aligned(layout.size().max(1), layout.align()) as *mut u8
        } else {
            self.bootstrap.alloc(layout)
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if self.mimalloc_enabled() {
            mi_zalloc_aligned(layout.size().max(1), layout.align()) as *mut u8
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

        if Self::ptr_is_mimalloc(ptr) {
            mi_free(ptr.cast::<c_void>());
        } else {
            self.bootstrap.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
        }

        if Self::ptr_is_mimalloc(ptr) {
            mi_realloc_aligned(ptr.cast::<c_void>(), new_size.max(1), layout.align()) as *mut u8
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

pub struct BuddyLocked {
    inner: LockedHeap<32>,
    init: AtomicBool,
}

impl BuddyLocked {
    pub const fn new() -> Self {
        Self {
            inner: LockedHeap::<32>::empty(),
            init: AtomicBool::new(false),
        }
    }

    #[inline(always)]
    unsafe fn ensure_init(&self) {
        if !self.init.load(Ordering::Acquire) {
            without_interrupts(|| {
                if !self.init.load(Ordering::Acquire) {
                    self.inner
                        .lock()
                        .init(HEAP_START, BOOTSTRAP_HEAP_SIZE as usize);
                    self.init.store(true, Ordering::Release);
                }
            });
        }
    }

    pub fn free_memory(&self) -> usize {
        without_interrupts(|| {
            let inner = self.inner.lock();
            inner.stats_total_bytes() - inner.stats_alloc_actual()
        })
    }
}

unsafe impl GlobalAlloc for BuddyLocked {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.ensure_init();
        without_interrupts(|| self.inner.lock().alloc(layout))
            .expect("kernel bootstrap heap overflow")
            .as_ptr()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.ensure_init();
        without_interrupts(|| {
            self.inner.lock().dealloc(
                NonNull::new(ptr).expect("null ptr passed to kernel heap dealloc"),
                layout,
            )
        })
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
    let start_addr = x86_64::VirtAddr::new(addr as u64);
    let addr_usize = addr as usize;
    if addr_usize < MIMALLOC_ARENA_START
        || addr_usize + size > MIMALLOC_ARENA_START + (MIMALLOC_ARENA_SIZE as usize)
    {
        crate::println!(
            "MIMALLOC COMMIT FAILED: address={:p}, size={}, reason=Address out of arena bounds",
            addr,
            size
        );
        return false;
    }

    let flags = x86_64::structures::paging::PageTableFlags::PRESENT
        | x86_64::structures::paging::PageTableFlags::WRITABLE;

    let res = without_interrupts(|| {
        crate::memory::paging::paging::map_kernel_range(start_addr, size as u64, flags, true)
    });

    match res {
        Ok(_) => {
            MIMALLOC_ARENA_COMMITTED.fetch_add(size, Ordering::Relaxed);
            true
        }
        Err(e) => {
            crate::println!("MIMALLOC COMMIT FAILED: address={:p}, size={}, flags={:?}, reason=Page mapping failed ({:?})", addr, size, flags, e);
            false
        }
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
        .filter(|region| region.kind == bootloader_api::info::MemoryRegionKind::Usable)
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
