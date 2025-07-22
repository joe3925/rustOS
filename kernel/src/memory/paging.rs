use alloc::collections::LinkedList;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::{MapToError, MapperFlush};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, PageTable, PageTableFlags, PageTableIndex, PhysFrame, Size1GiB, Size2MiB, Size4KiB
};
use x86_64::{PhysAddr, VirtAddr};

use crate::cpu::get_cpu_info;
use crate::println;
use crate::util::boot_info;

pub static KERNEL_CR3_U64: AtomicU64 = AtomicU64::new(0);

pub fn init_kernel_cr3() {
    let (frame, _) = Cr3::read();
    KERNEL_CR3_U64.store(frame.start_address().as_u64(), Ordering::SeqCst);
}

pub fn kernel_cr3() -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(x86_64::PhysAddr::new(KERNEL_CR3_U64.load(Ordering::SeqCst)))
}

// Memory constants and structures
pub const KERNEL_STACK_SIZE: u64 = 1024 * 1024 * 5;
pub static KERNEL_STACK_ALLOCATOR: Mutex<StackAllocator> = Mutex::new(StackAllocator::new(
    VirtAddr::new(0xFFFF_FFFF_8000_0000), // Kernel stacks start here
));

lazy_static! {
    pub static ref KERNEL_RANGE_TRACKER: Arc<RangeTracker> = Arc::new(RangeTracker::new(
        MANAGED_KERNEL_RANGE_START,
        MANAGED_KERNEL_RANGE_END,
    ));
}

pub const BOOT_MEMORY_SIZE: usize = 1024 * 1024 * 1024 * 128;
pub static MEMORY_BITMAP: Mutex<[u64; num_frames_4k(BOOT_MEMORY_SIZE) / 64]> =
    Mutex::new([0; num_frames_4k(BOOT_MEMORY_SIZE) / 64]);

pub static USED_MEMORY: AtomicUsize = AtomicUsize::new(0);

const FRAMES_PER_2M: usize = 512; // 2 MiB / 4 KiB
const FRAMES_PER_1G: usize = 1 << 18; // 1 GiB / 4 KiB
const WORDS_PER_2M: usize = FRAMES_PER_2M / 64; // 8
const WORDS_PER_1G: usize = FRAMES_PER_1G / 64; // 4096

pub const MMIO_BASE: u64 = 0xFFFF_9000_0000_0000;
const MAX_PENDING_FREES: usize = 64;

const MANAGED_KERNEL_RANGE_START: u64 = MMIO_BASE;
const MANAGED_KERNEL_RANGE_END: u64 = 0xFFFF_FFFF_8000_0000;

static mut PENDING_FREES: [Option<(u64, u64)>; MAX_PENDING_FREES] = [None; MAX_PENDING_FREES];
static PENDING_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);

static NEXT_MMIO_VADDR: AtomicU64 = AtomicU64::new(MMIO_BASE);

//TODO: Switch to this instead of the x86_64 crate version
#[derive(Debug)]
pub enum PageMapError {
    Page4KiB(MapToError<Size4KiB>),
    Page2MiB(MapToError<Size2MiB>),
    Page1GiB(MapToError<Size1GiB>),
    NoMemory(),
    NoMemoryMap(),
}

impl From<MapToError<Size4KiB>> for PageMapError {
    fn from(e: MapToError<Size4KiB>) -> Self {
        PageMapError::Page4KiB(e)
    }
}
impl From<MapToError<Size2MiB>> for PageMapError {
    fn from(e: MapToError<Size2MiB>) -> Self {
        PageMapError::Page2MiB(e)
    }
}
impl From<MapToError<Size1GiB>> for PageMapError {
    fn from(e: MapToError<Size1GiB>) -> Self {
        PageMapError::Page1GiB(e)
    }
}

pub const fn num_frames_4k(size: usize) -> usize {
    ((size + 0xFFF) >> 12)
}

pub fn total_usable_bytes() -> u64 {
    boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end - r.start)
        .sum()
}
#[derive(Clone)]

// This struct doesnt do anything anymore but remains so old code still works
pub struct BootInfoFrameAllocator {}

impl BootInfoFrameAllocator {
    pub fn init_start(memory_regions: &'static [MemoryRegion]) {
        let mut memory_map = (MEMORY_BITMAP.lock());
        for region in memory_regions {
            if region.kind != MemoryRegionKind::Usable {
                let start_frame = (region.start >> 12) as usize;
                let end_frame = ((region.end + 0xFFF) >> 12) as usize - 1;

                if start_frame / 64 >= memory_map.len() {
                    continue;
                }

                let first_word = start_frame / 64;
                let last_word = end_frame / 64;

                let first_mask = !0u64 << (start_frame & 63);
                let last_mask = (!0u64) >> (63 - (end_frame & 63));

                if first_word == last_word {
                    memory_map[first_word] |= first_mask & last_mask;
                    continue;
                }

                memory_map[first_word] |= first_mask;

                for w in (first_word + 1)..last_word {
                    memory_map[w] = !0u64;
                }

                memory_map[last_word] |= last_mask;
            }
        }
        return;
    }
    pub fn init(memory_regions: &'static [MemoryRegion]) -> Self {
        BootInfoFrameAllocator {}
    }
        pub fn deallocate_frame<S: PageSize>(&self, frame: PhysFrame<S>) {
        let base_idx = (frame.start_address().as_u64() >> 12) as usize;
        let (len, bytes) = match S::SIZE {
            Size4KiB::SIZE => (1, 0x1000),
            Size2MiB::SIZE => (FRAMES_PER_2M, 0x20_0000),
            Size1GiB::SIZE => (FRAMES_PER_1G, 0x4000_0000),
            _ => return, 
        };

        let mut bm = MEMORY_BITMAP.lock();
        clear_range(bm.as_mut_slice(), base_idx, len);
        USED_MEMORY.fetch_sub(bytes, Ordering::SeqCst);
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    #[inline]
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut bm =MEMORY_BITMAP.lock();

        for (word_idx, word) in bm.iter_mut().enumerate() {
            if *word == u64::MAX {
                continue; // fully allocated
            }

            // first zero bit in this word
            let free_bit = (!*word).trailing_zeros() as usize;
            *word |= 1u64 << free_bit; // mark allocated

            let frame_idx = word_idx * 64 + free_bit;
            let phys = (frame_idx as u64) << 12; // * 4096
            USED_MEMORY.fetch_add(1024, Ordering::SeqCst);
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

unsafe impl FrameAllocator<Size2MiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let mut bm = MEMORY_BITMAP.lock();
        let words = bm.len();

        for (word_idx, word) in bm.iter().enumerate() {
            if *word == u64::MAX {
                continue; // no free bit here
            }

            // any zero‑bit in this word gives us a candidate index
            let bit = (!*word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit; // frame index
            let base = idx & !(FRAMES_PER_2M - 1); // align down to 512

            // check whole 2 MiB block
            let start_w = base / 64;
            if start_w + WORDS_PER_2M > words {
                break; // out of bitmap
            }
            let all_free = bm[start_w..start_w + WORDS_PER_2M].iter().all(|w| *w == 0);
            if !all_free {
                continue;
            }

            // mark 512 bits allocated
            for w in &mut bm[start_w..start_w + WORDS_PER_2M] {
                *w = u64::MAX;
            }

            let phys = (base as u64) << 12;
            USED_MEMORY.fetch_add(FRAMES_PER_2M * 4 * 1024, Ordering::SeqCst);
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

unsafe impl FrameAllocator<Size1GiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let mut bm = MEMORY_BITMAP.lock();
        let words = bm.len();

        for (word_idx, word) in bm.iter().enumerate() {
            if *word == u64::MAX {
                continue;
            }

            let bit = (!*word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit;
            let base = idx & !(FRAMES_PER_1G - 1); // align 1 GiB

            let start_w = base / 64;
            if start_w + WORDS_PER_1G > words {
                break;
            }
            let all_free = bm[start_w..start_w + WORDS_PER_1G].iter().all(|w| *w == 0);
            if !all_free {
                continue;
            }

            for w in &mut bm[start_w..start_w + WORDS_PER_1G] {
                *w = u64::MAX;
            }

            let phys = (base as u64) << 12;
            USED_MEMORY.fetch_add(FRAMES_PER_1G * 4 * 1024, Ordering::SeqCst);
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}
fn clear_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 { return; }

    let end = start + len - 1;
    let words = bitmap.len();
    if start / 64 >= words { return; }

    let end = core::cmp::min(end, words * 64 - 1);

    let first_word = start / 64;
    let last_word  = end   / 64;

    if first_word == last_word {
        let mask = ((!0u64) << (start & 63)) & ((!0u64) >> (63 - (end & 63)));
        bitmap[first_word] &= !mask;
        return;
    }

    bitmap[first_word] &= !(!0u64 << (start & 63));

    for w in (first_word + 1)..last_word {
        bitmap[w] = 0;
    }

    bitmap[last_word] &= !(!0u64 >> (63 - (end & 63)));
}
pub fn map_page(
    mapper: &mut impl Mapper<Size4KiB>,
    page: Page<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    unsafe {
        mapper.map_to(page, frame, flags, frame_allocator)?.flush();
    }
    Ok(())
}
#[inline(always)]
fn map_1gib_page<M, FA>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut FA,
) -> Result<(), MapToError<Size1GiB>>
where
    M: Mapper<Size1GiB>,
    FA: FrameAllocator<Size1GiB> + FrameAllocator<Size4KiB>,
{
    let page = Page::<Size1GiB>::containing_address(addr);
    let frame = fa
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;

    // ── ensure HUGE_PAGE flag ─────────────────────────────────────────────
    let effective_flags = if flags.contains(PageTableFlags::HUGE_PAGE) {
        flags
    } else {
        flags | PageTableFlags::HUGE_PAGE
    };

    unsafe {
        mapper.map_to(page, frame, effective_flags, fa)?.flush();
    }
    Ok(())
}

#[inline(always)]
fn map_2mib_page<M, FA>(
    mapper: &mut M,
    addr: VirtAddr,
    flags: PageTableFlags,
    fa: &mut FA,
) -> Result<(), MapToError<Size2MiB>>
where
    M: Mapper<Size2MiB>,
    FA: FrameAllocator<Size2MiB> + FrameAllocator<Size4KiB>,
{
    let page = Page::<Size2MiB>::containing_address(addr);
    let frame = fa
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;

    // ── ensure HUGE_PAGE flag ─────────────────────────────────────────────
    let effective_flags = if flags.contains(PageTableFlags::HUGE_PAGE) {
        flags
    } else {
        flags | PageTableFlags::HUGE_PAGE
    };

    unsafe {
        mapper.map_to(page, frame, effective_flags, fa)?.flush();
    }
    Ok(())
}

fn get_level4_page_table(mem_offset: VirtAddr) -> &'static mut PageTable {
    let (table_frame, _) = Cr3::read();
    let virt_addr = mem_offset + table_frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level3_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l4_table = get_level4_page_table(mem_offset);
    let l3_table_addr = l4_table[to_phys.p4_index()].addr().as_u64();
    let virt_addr = mem_offset + l3_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level2_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l3_table = get_level3_page_table(mem_offset, to_phys);
    let l2_table_addr = l3_table[to_phys.p3_index()].addr().as_u64();
    let virt_addr = mem_offset + l2_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level1_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l2_table = get_level2_page_table(mem_offset, to_phys);
    let l1_table_addr = l2_table[to_phys.p2_index()].addr().as_u64();
    let virt_addr = mem_offset + l1_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

pub(crate) fn virtual_to_phys(to_phys: VirtAddr) -> PhysAddr {
    let mem_offset = VirtAddr::new(boot_info().physical_memory_offset.into_option().unwrap());
    let l1_table = get_level1_page_table(mem_offset, to_phys);
    let page_entry = &l1_table[to_phys.p1_index()];
    page_entry.addr()
}
pub fn init_mapper(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = get_level4_page_table(physical_memory_offset);
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
}
unsafe fn write_infinite_loop(page_ptr: *mut u8) {
    // Infinite loop instruction: `0xEB 0xFE` (JMP -2)
    ptr::write(page_ptr, 0xEB); // JMP opcode
    ptr::write(page_ptr.add(1), 0xFE); // -2 offset to jump back to itself
}
pub(crate) unsafe fn write_syscall(page_ptr: *mut u8) {
    // Interrupt instruction: `int 0x80` → opcode: `0xCD 0x80`
    ptr::write(page_ptr.add(0), 0xCD); // First byte of int 0x80
    ptr::write(page_ptr.add(1), 0x80); // Second byte of int 0x80

    // Infinite loop after syscall
    ptr::write(page_ptr.add(2), 0xEB); // `jmp` short opcode
    ptr::write(page_ptr.add(3), 0xFE); // Offset: -2 (infinite loop)
}
pub(crate) struct StackAllocator {
    base_address: VirtAddr,
    free_list: LinkedList<VirtAddr>, // List of free stack starting addresses
}

impl StackAllocator {
    pub const fn new(base_address: VirtAddr) -> Self {
        StackAllocator {
            base_address,
            free_list: LinkedList::new(),
        }
    }

    pub fn allocate(&mut self, size: u64) -> Option<VirtAddr> {
        if let Some(free_stack) = self.free_list.pop_front() {
            return Some(free_stack);
        }

        // Ensure alignment
        let alignment = 0x10000; // 64 KB alignment
        let total_stack_size = size + 0x1000; // Includes guard page

        // Align base address
        self.base_address =
            VirtAddr::new((self.base_address.as_u64() + alignment - 1) & !(alignment - 1));

        let stack_start = self.base_address;
        self.base_address = VirtAddr::new(self.base_address.as_u64() + total_stack_size);

        // Set up the guard page
        Some(stack_start)
    }

    pub fn deallocate(&mut self, stack_start: VirtAddr) {
        // Add the stack back to the free list for reuse
        self.free_list.push_back(stack_start);
    }
}

pub fn allocate_kernel_stack(size: u64) -> Result<VirtAddr, PageMapError> {
    let total_size = align_up_4k(size + 0x1000);

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    {
        // println!(
        //     "bump pointer: {:#X?}",
        //     KERNEL_RANGE_TRACKER.allocations.lock()
        // );
    }
    let stack_start_addr = (allocate_auto_kernel_range_mapped(total_size, flags))?;
    Ok((stack_start_addr + total_size) - 0x1000)
}

pub fn deallocate_kernel_stack(stack_top: VirtAddr, size: u64) {
    let total_size = size + 0x1000; // includes guard page
    let stack_start = stack_top - size;
    let full_range_start = stack_start - 0x1000;
    unmap_range(full_range_start, total_size);
}

pub enum RangeAllocationError {
    Overlap,
    OutOfRange,
    Unaligned,
}
#[derive(Debug)]
pub struct RangeTracker {
    allocations: Mutex<Vec<(u64, u64)>>,

    pub start: u64,
    pub end: u64,
}

impl RangeTracker {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            allocations: Mutex::new(Vec::new()),
            start,
            end,
        }
    }

    pub fn alloc(&self, base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        let mut lock = self.allocations.lock();
        if (base < self.start || base + aligned_size > self.end) {
            return Err(RangeAllocationError::OutOfRange);
        }
        // Ensure no overlap
        if lock.iter().any(|&(a, s)| {
            let end = a + s;
            let req_end = base + aligned_size;
            !(base >= end || req_end <= a)
        }) {
            return Err(RangeAllocationError::Overlap);
        }

        lock.push((base, aligned_size));
        Ok(VirtAddr::new(base))
    }

    pub fn dealloc(&self, base: u64, size: u64) {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        let mut lock = self.allocations.lock();
        if let Some(index) = lock
            .iter()
            .position(|&(a, s)| a == base && s == aligned_size)
        {
            lock.remove(index);
        }
    }

    // Finds a free region of at least `size` bytes and allocates it
    pub fn alloc_auto(&self, size: u64) -> Option<VirtAddr> {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        let mut lock = self.allocations.lock();

        // Sort existing allocations by base address
        lock.sort_unstable_by_key(|&(base, _)| base);

        let mut current = self.start;

        for &(alloc_base, alloc_size) in lock.iter() {
            let alloc_end = alloc_base;

            if current + aligned_size <= alloc_end {
                // Found gap
                lock.push((current, aligned_size));
                return Some(VirtAddr::new(current));
            }

            // Move past this allocation
            current = alloc_base + alloc_size;
            if current > self.end {
                return None;
            }
        }

        // Check space at the end
        if current + aligned_size <= self.end {
            lock.push((current, aligned_size));
            return Some(VirtAddr::new(current));
        }

        None
    }
}

#[inline(always)]
pub const fn align_up_4k(x: u64) -> u64 {
    (x + 0xFFF) & !0xFFF
}
#[inline(always)]
pub const fn align_up_2mib(x: u64) -> u64 {
    const TWO_MIB: u64 = 2 * 1024 * 1024; // 2 MiB
    (x + (TWO_MIB - 1)) & !(TWO_MIB - 1)
}

/// Any‑address allocation, but start and length are both 4 KiB‑aligned.
pub fn allocate_auto_kernel_range(size: u64) -> Option<VirtAddr> {
    let aligned_size = align_up_4k(size); // round length up
    let addr = KERNEL_RANGE_TRACKER.alloc_auto(aligned_size)?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0); // start aligned
    Some(addr)
}

/// Fixed‑address allocation; reject unaligned `base`, round size up to 4 KiB.
pub fn allocate_kernel_range(base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
    if base & 0xFFF != 0 {
        return Err(RangeAllocationError::Unaligned);
    }
    let aligned_size = align_up_4k(size);
    let addr = KERNEL_RANGE_TRACKER.alloc(base, aligned_size)?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);
    Ok(addr)
}
//TODO: Switch to usize
pub fn map_range_with_huge_pages<M>(
    mapper: &mut M,
    addr: VirtAddr,
    size: u64,
    fa: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), PageMapError>
where
    M: Mapper<Size4KiB> + Mapper<Size2MiB> + Mapper<Size1GiB>,
{
    let mut cur = addr;
    debug_assert_eq!(cur.as_u64() & 0xFFF, 0);
    let mut remaining = align_up_4k(size);
    let gib = 1u64 << 30;
    let mib2 = 2u64 * 1024 * 1024;
    let supports_1g = get_cpu_info()
        .get_extended_processor_and_feature_identifiers()
        .expect("CPUID unavailable")
        .has_1gib_pages();

    while remaining > 0 {
        if supports_1g && remaining >= gib && (cur.as_u64() & (gib - 1)) == 0 {
            match map_1gib_page(mapper, cur, flags, fa) {
                Ok(_) => {
                    cur += gib;
                    remaining -= gib;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => {
                    return Err(PageMapError::Page1GiB(e));
                }
            };
        }

        if remaining >= mib2 && (cur.as_u64() & (mib2 - 1)) == 0 {
            match map_2mib_page(mapper, cur, flags, fa) {
                Ok(_) => {
                    cur += mib2;
                    remaining -= mib2;
                    continue;
                }
                Err(MapToError::FrameAllocationFailed) => {}
                Err(e) => {
                    return Err(PageMapError::Page2MiB(e));
                }
            };
        }

        let page4k = Page::<Size4KiB>::containing_address(cur);
        map_page(mapper, page4k, fa, flags)?;
        cur += 0x1000;
        remaining -= 0x1000;
    }

    Ok(())
}

pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    let align_size = align_up_4k(size);
    let addr = allocate_auto_kernel_range(align_size).ok_or(PageMapError::NoMemory())?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    map_range_with_huge_pages(&mut mapper, addr, align_size, &mut frame_allocator, flags)?;
    Ok(addr)
}

pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    let align_size = align_up_4k(size);
    debug_assert_eq!(base & 0xFFF, 0);

    let addr = allocate_kernel_range(base, align_size).map_err(|_| PageMapError::NoMemory())?;
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    map_range_with_huge_pages(&mut mapper, addr, align_size, &mut frame_allocator, flags)?;
    Ok(addr)
}

/// Deallocates a previously allocated kernel range.
pub fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    debug_assert_eq!(addr.as_u64() & 0xFFF, 0);
    let aligned_size = align_up_4k(size); // length rounded‑up
    KERNEL_RANGE_TRACKER.dealloc(addr.as_u64(), aligned_size);
}

/// Un-maps and deallocates a previously allocated kernel range.
pub fn unmap_range(virtual_addr: VirtAddr, size: u64) {
    let boot_info        = boot_info();
    let phys_mem_offset  =
        VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper       = init_mapper(phys_mem_offset);

    deallocate_kernel_range(virtual_addr, size);

    let frame_allocator  =
        BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let mut cur        = virtual_addr;
    let mut remaining  = align_up_4k(size);
    const GiB : u64 = 1 << 30;
    const MiB2: u64 = 2 * 1024 * 1024;

    while remaining > 0 {
        if remaining >= GiB && (cur.as_u64() & (GiB - 1)) == 0 {
            let page = Page::<Size1GiB>::containing_address(cur);
            if let Ok((frame, flush)) = mapper.unmap(page) {
                flush.flush();                       
                frame_allocator.deallocate_frame(frame);
                cur += GiB;
                remaining -= GiB;
                continue;
            }
        }

        if remaining >= MiB2 && (cur.as_u64() & (MiB2 - 1)) == 0 {
            let page = Page::<Size2MiB>::containing_address(cur);
            if let Ok((frame, flush)) = mapper.unmap(page) {
                flush.flush();
                frame_allocator.deallocate_frame(frame);
                cur += MiB2;
                remaining -= MiB2;
                continue;
            }
        }

        let page4k = Page::<Size4KiB>::containing_address(cur);
        if let Ok((frame, flush)) = mapper.unmap(page4k) {
            flush.flush();
            frame_allocator.deallocate_frame(frame);
        }
        cur       += 0x1000;
        remaining -= 0x1000;
    }
}
pub fn identity_map_page(
    phys_addr: PhysAddr,
    range: usize,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .ok_or(MapToError::FrameAllocationFailed)?,
    );
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
    let page_size = 0x1000;

    let num_pages = (range + 0xFFF) / page_size;
    for i in 0..num_pages {
        let addr = PhysAddr::new(phys_addr.as_u64() + (page_size * i) as u64);
        let page = Page::containing_address(VirtAddr::new(addr.as_u64()));
        let frame = PhysFrame::containing_address(addr);

        unsafe {
            mapper
                .map_to(
                    page,
                    frame,
                    flags | PageTableFlags::PRESENT,
                    &mut frame_allocator,
                )?
                .flush();
        }
    }

    Ok(())
}

pub fn map_mmio_region(
    mmio_base: PhysAddr,
    mmio_size: u64,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let phys_frame = PhysFrame::containing_address(mmio_base);
    let num_pages = (mmio_size + 0xFFF) / 4096;

    let virtual_addr =
        allocate_auto_kernel_range(mmio_size).ok_or_else(|| MapToError::FrameAllocationFailed)?;

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    for i in 0..num_pages {
        let page = Page::containing_address(virtual_addr + i * 4096);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
        unsafe {
            mapper
                .map_to(page, phys_frame + i, flags, &mut frame_allocator)?
                .flush();
        }
    }
    Ok(virtual_addr)
}

pub fn new_user_mode_page_table() -> Result<(PhysAddr, VirtAddr), PageMapError> {
    let mem_offset = boot_info()
        .physical_memory_offset
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;

    let table_virt = allocate_auto_kernel_range_mapped(
        size_of::<PageTable>() as u64,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE,
    )?;

    let table_phys_addr = virtual_to_phys(table_virt);
    let kernel_pml4 = get_level4_page_table(VirtAddr::new(mem_offset));

    let new_table: &mut PageTable = unsafe { &mut *(table_virt.as_mut_ptr()) };
    new_table.zero();

    for i in 256..512 {
        new_table[i] = kernel_pml4[i].clone();
    }

    Ok((table_phys_addr, table_virt))
}

// I hate having to do this
pub fn map_page_in_page_table(
    l4_table: &mut PageTable,
    mem_offset: VirtAddr,
    virtual_addr: VirtAddr,
    flags: PageTableFlags,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    let p4_index = virtual_addr.p4_index();
    let p3_index = virtual_addr.p3_index();
    let p2_index = virtual_addr.p2_index();
    let p1_index = virtual_addr.p1_index();
    let l3_table = get_or_create_table(l4_table, p4_index, mem_offset, frame_allocator);

    let l2_table = get_or_create_table(l3_table, p3_index, mem_offset, frame_allocator);

    let l1_table = get_or_create_table(l2_table, p2_index, mem_offset, frame_allocator);

    let entry = &mut l1_table[p1_index];
    entry.set_frame(
        frame_allocator.allocate_frame().unwrap(),
        flags | PageTableFlags::PRESENT,
    );
}

fn get_or_create_table(
    parent: &mut PageTable,
    index: PageTableIndex,
    mem_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> &'static mut PageTable {
    let entry = &mut parent[index];

    if entry.flags().contains(PageTableFlags::PRESENT) {
        let phys = entry.frame().unwrap().start_address();
        let virt = mem_offset + phys.as_u64();
        unsafe { &mut *(virt.as_mut_ptr()) }
    } else {
        let frame = frame_allocator
            .allocate_frame()
            .expect("Frame allocation failed");
        let virt = mem_offset + frame.start_address().as_u64();
        let table = unsafe {
            let ptr: *mut PageTable = virt.as_mut_ptr();
            ptr.write(PageTable::new());
            &mut *ptr
        };
        entry.set_frame(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        table
    }
}
