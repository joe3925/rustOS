use alloc::borrow::ToOwned;
use alloc::collections::LinkedList;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use core::net::Ipv4Addr;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::{Lazy, Mutex};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, PageTable, PageTableFlags,
    PageTableIndex, PhysFrame, Size2MiB, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::util::boot_info;
use crate::BOOT_INFO;

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

// Global NEXT counter (still required)
static NEXT: Mutex<usize> = Mutex::new(0);

const MMIO_BASE: u64 = 0xFFFF_9000_0000_0000;
const MAX_PENDING_FREES: usize = 64;

const MANAGED_KERNEL_RANGE_START: u64 = MMIO_BASE;
const MANAGED_KERNEL_RANGE_END: u64 = 0xFFFF_FFFF_8000_0000;

static mut PENDING_FREES: [Option<(u64, u64)>; MAX_PENDING_FREES] = [None; MAX_PENDING_FREES];
static PENDING_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);

static NEXT_MMIO_VADDR: AtomicU64 = AtomicU64::new(MMIO_BASE);

#[derive(Clone)]

pub struct BootInfoFrameAllocator {
    memory_regions: &'static [MemoryRegion],
}

impl BootInfoFrameAllocator {
    pub fn init(memory_regions: &'static [MemoryRegion]) -> Self {
        BootInfoFrameAllocator { memory_regions }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        let regions = self.memory_regions.iter();
        let usable = regions.filter(|r| r.kind == MemoryRegionKind::Usable);
        let addr_ranges = usable.map(|r| r.start..r.end);
        let frame_addresses = addr_ranges.flat_map(|r| (r.start..r.end).step_by(4096));
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }

    fn usable_2mb_frames(&self) -> impl Iterator<Item = PhysFrame<Size2MiB>> {
        let regions = self.memory_regions.iter();
        let usable = regions.filter(|r| r.kind == MemoryRegionKind::Usable);
        let addr_ranges = usable.map(|r| r.start..r.end);
        let frame_addresses = addr_ranges.flat_map(|r| (r.start..r.end).step_by(2 * 1024 * 1024));
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut next = NEXT.lock();
        let frame = self.usable_frames().nth(*next);
        *next += 1;
        frame
    }
}

unsafe impl FrameAllocator<Size2MiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let mut next = NEXT.lock();

        if *next % 512 != 0 {
            *next += 512 - (*next % 512);
        }

        let base_frame = self.usable_2mb_frames().nth(*next / 512);
        *next += 512;

        base_frame
    }
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

fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
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

pub fn allocate_kernel_stack(size: u64) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let total_size = size + 0x1000; // +1 page for guard
    let stack_start_addr = KERNEL_STACK_ALLOCATOR.lock().allocate(size).unwrap();

    let stack_end = stack_start_addr + total_size;

    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .ok_or(MapToError::FrameAllocationFailed)?,
    );

    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
    let mut mapper = init_mapper(phys_mem_offset);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    // Map all pages except the guard page (last 4KiB)
    for page in Page::range_inclusive(
        Page::containing_address(stack_start_addr),
        Page::containing_address(stack_end - 0x1000),
    ) {
        match map_page(&mut mapper, page, &mut frame_allocator, flags) {
            Ok(_) => {}
            Err(MapToError::PageAlreadyMapped(..)) => {}
            Err(e) => return Err(e),
        }
    }

    let aligned_stack_end = VirtAddr::new((stack_end.as_u64() - 0x1000) & !0xF);
    Ok(aligned_stack_end)
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
}
#[derive(Debug)]
pub struct RangeTracker {
    allocations: Mutex<Vec<(u64, u64)>>,

    //the range that this allocartor manages
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

pub fn allocate_auto_kernel_range(size: u64) -> Option<VirtAddr> {
    let addr = KERNEL_RANGE_TRACKER.alloc_auto(size)?;
    Some(addr)
}

pub fn allocate_kernel_range(base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
    let addr = KERNEL_RANGE_TRACKER.alloc(base, size)?;
    Ok(addr)
}

pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let addr = allocate_auto_kernel_range(size).ok_or(MapToError::FrameAllocationFailed)?;

    if let boot_info = boot_info() {
        let phys_mem_offset =
            VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
        let mut mapper = init_mapper(phys_mem_offset);

        let num_pages = (size + 0xFFF) / 0x1000;
        for i in 0..num_pages {
            let page = Page::containing_address(addr + i * 0x1000);
            map_page(&mut mapper, page, &mut frame_allocator, flags)?;
        }

        Ok(addr)
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}

pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let addr = allocate_kernel_range(base, size).map_err(|_| MapToError::FrameAllocationFailed)?;

    if let boot_info = boot_info() {
        let phys_mem_offset =
            VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
        let mut mapper = init_mapper(phys_mem_offset);

        let num_pages = (size + 0xFFF) / 0x1000;
        for i in 0..num_pages {
            let page = Page::containing_address(addr + i * 0x1000);
            map_page(&mut mapper, page, &mut frame_allocator, flags)?;
        }

        Ok(addr)
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}

/// Deallocates a previously allocated kernel range.
pub fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    KERNEL_RANGE_TRACKER.dealloc(addr.as_u64(), size);
}

/// Unmaps and deallocates a previously allocated kernel range.
pub fn unmap_range(virtual_addr: VirtAddr, size: u64) {
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
    let mut mapper = init_mapper(phys_mem_offset);

    deallocate_kernel_range(virtual_addr, size);
    let num_pages = (size + 0xFFF) / 4096;
    for i in 0..num_pages {
        let page = Page::<Size4KiB>::containing_address(virtual_addr + i * 4096);
        unsafe {
            if let Ok((_, flush)) = mapper.unmap(page) {
                flush.flush();
            }
        }
    }
}
pub fn identity_map_page(
    phys_addr: PhysAddr,
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

    let page = Page::containing_address(VirtAddr::new(phys_addr.as_u64()));
    let frame = PhysFrame::containing_address(phys_addr);

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

    if let boot_info = boot_info() {
        let phys_mem_offset =
            VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut mapper = init_mapper(phys_mem_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

        for i in 0..num_pages {
            let page = Page::containing_address(virtual_addr + i * 4096);
            let flags =
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
            unsafe {
                mapper
                    .map_to(page, phys_frame + i, flags, &mut frame_allocator)?
                    .flush();
            }
        }
    }

    Ok(virtual_addr)
}

pub fn new_user_mode_page_table() -> Result<(PhysAddr, VirtAddr), MapToError<Size4KiB>> {
    let mem_offset = boot_info()
        .physical_memory_offset
        .into_option()
        .ok_or(MapToError::FrameAllocationFailed)?;

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
