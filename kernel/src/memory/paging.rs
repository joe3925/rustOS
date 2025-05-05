use alloc::collections::LinkedList;
use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size2MiB, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

pub const KERNEL_STACK_SIZE: u64 = 0x2800;
pub const USER_STACK_SIZE: u64 = 0x2800;
pub static KERNEL_STACK_ALLOCATOR: Mutex<StackAllocator> = Mutex::new(StackAllocator::new(
    VirtAddr::new(0xFFFF_FFFF_8000_0000), // Kernel stacks start here
    KERNEL_STACK_SIZE,               // Kernel stack size (64 KB)
));

pub static USER_STACK_ALLOCATOR: Mutex<StackAllocator> = Mutex::new(StackAllocator::new(
    VirtAddr::new(0x8000_0000u64), // User stacks start here
    USER_STACK_SIZE,              // User stack size
));
// Global NEXT counter (still required)
static NEXT: Mutex<usize> = Mutex::new(0);
#[derive(Clone)]

pub struct BootInfoFrameAllocator {
    memory_regions: &'static [MemoryRegion],
}

impl BootInfoFrameAllocator {
    pub fn init(memory_regions: &'static [MemoryRegion]) -> Self {
        BootInfoFrameAllocator { memory_regions }
    }

    fn usable_frames(&self) -> impl Iterator<Item=PhysFrame> {
        let regions = self.memory_regions.iter();
        let usable = regions.filter(|r| r.kind == MemoryRegionKind::Usable);
        let addr_ranges = usable.map(|r| r.start..r.end);
        let frame_addresses = addr_ranges.flat_map(|r| (r.start..r.end).step_by(4096));
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }

    fn usable_2mb_frames(&self) -> impl Iterator<Item=PhysFrame<Size2MiB>> {
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
    flags: PageTableFlags) -> Result<(), MapToError<Size4KiB>> {
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
fn get_table4_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 39) & 0x1FF) as usize
}

fn get_table3_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 30) & 0x1FF) as usize
}

fn get_table2_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 21) & 0x1FF) as usize
}

fn get_table1_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 12) & 0x1FF) as usize
}

fn get_level4_page_table(mem_offset: VirtAddr) -> &'static mut PageTable {
    let (table_frame, _) = Cr3::read();
    let virt_addr = mem_offset + table_frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level3_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l4_table = get_level4_page_table(mem_offset);
    let l3_table_addr = l4_table[get_table4_index(to_phys)].addr().as_u64();
    let virt_addr = mem_offset + l3_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level2_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l3_table = get_level3_page_table(mem_offset, to_phys);
    let l2_table_addr = l3_table[get_table3_index(to_phys)].addr().as_u64();
    let virt_addr = mem_offset + l2_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level1_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l2_table = get_level2_page_table(mem_offset, to_phys);
    let l1_table_addr = l2_table[get_table2_index(to_phys)].addr().as_u64();
    let virt_addr = mem_offset + l1_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

pub(crate) fn virtual_to_phys(mem_offset: VirtAddr, to_phys: VirtAddr) -> PhysAddr {
    let l1_table = get_level1_page_table(mem_offset, to_phys);
    let page_entry = &l1_table[get_table1_index(to_phys)];
    page_entry.addr()
}
pub(crate) fn init_mapper(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = get_level4_page_table(physical_memory_offset);
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
}
unsafe fn write_infinite_loop(page_ptr: *mut u8) {
    // Infinite loop instruction: `0xEB 0xFE` (JMP -2)
    ptr::write(page_ptr, 0xEB);       // JMP opcode
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

/// Allocates a page with a syscall instruction at a free virtual address.
pub(crate) unsafe fn allocate_syscall_page() -> Result<VirtAddr, &'static str> {
    let page_addr = alloc_user_page()?; // Allocate the user page
    write_syscall(page_addr.as_mut_ptr()); // Write the syscall instruction
    Ok(page_addr)
}

/// Function to allocate a user-accessible page with write and execute permissions
///Safety: page must be deallocated after
pub(crate) unsafe fn alloc_user_page() -> Result<VirtAddr, &'static str> {
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    if let boot_info = boot_info() {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
        let mut mapper = init_mapper(phys_mem_offset);

        let mut base_addr = 0x4000_0000u64;
        let mut page: Page<Size4KiB>;

        loop {
            page = Page::containing_address(VirtAddr::new(base_addr));
            if mapper.translate_page(page).is_err() {
                break; // Found an unmapped page
            }
            base_addr += 0x1000; // Move to the next page (4 KiB)
        }

        map_page(&mut mapper, page, &mut frame_allocator, flags).expect("Failed to map user idle page");

        Ok(page.start_address())
    } else {
        Err("Boot info not available")
    }
}

/// Allocates a page with an infinite loop instruction at a free virtual address.
pub(crate) fn allocate_infinite_loop_page() -> Result<VirtAddr, &'static str> {
    let page_addr = unsafe { alloc_user_page() }?; // Allocate the user page
    unsafe { write_infinite_loop(page_addr.as_mut_ptr()); } // Write the infinite loop
    Ok(page_addr)
}
use crate::util::boot_info;
use spin::Mutex;
use crate::println;

pub(crate) struct StackAllocator {
    base_address: VirtAddr,
    stack_size: u64,
    free_list: LinkedList<VirtAddr>, // List of free stack starting addresses
}

impl StackAllocator {
    pub const fn new(base_address: VirtAddr, stack_size: u64) -> Self {
        StackAllocator {
            base_address,
            stack_size,
            free_list: LinkedList::new(),
        }
    }

    pub fn allocate(&mut self) -> Option<VirtAddr> {
        if let Some(free_stack) = self.free_list.pop_front() {
            return Some(free_stack);
        }

        // Ensure alignment
        let alignment = 0x10000; // 64 KB alignment
        let total_stack_size = self.stack_size + 0x1000; // Includes guard page


        // Align base address
        self.base_address = VirtAddr::new((self.base_address.as_u64() + alignment - 1) & !(alignment - 1));

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


/// Allocates a stack for a user-mode task with guard pages.
///Safety: stack must be deallocated after use
pub(crate) unsafe fn allocate_user_stack() -> Result<VirtAddr, MapToError<Size4KiB>> {
    let mut allocator = USER_STACK_ALLOCATOR.lock();
    let stack_start = allocator.allocate().expect("kernel stack alloc failed");
    let total_stack_size = USER_STACK_SIZE + 0x1000; //guard page
    let stack_end = stack_start + total_stack_size;

    if let boot_info = boot_info() {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
        let mut mapper = init_mapper(phys_mem_offset);

        //guard page is not mapped
        for page in Page::range_inclusive(
            Page::<Size4KiB>::containing_address(stack_start),
            Page::<Size4KiB>::containing_address(stack_end - 0x1000),
        ) {
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            match map_page(&mut mapper, page, &mut frame_allocator, flags) {
                Ok(_) => {}
                Err(MapToError::PageAlreadyMapped(..)) => {}
                Err(e) => {
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }

        let aligned_stack_end = VirtAddr::new((stack_end.as_u64() - 0x1000) & !0xF);
        Ok(aligned_stack_end)
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}

///Safety: stack must be deallocated after use
pub(crate) unsafe fn allocate_kernel_stack() -> Result<VirtAddr, MapToError<Size4KiB>> {
    println!("here");
    let mut allocator = KERNEL_STACK_ALLOCATOR.lock();
    let stack_start = allocator.allocate().expect("kernel stack alloc failed");
    let total_stack_size = KERNEL_STACK_SIZE + 0x1000;
    let stack_end = stack_start + total_stack_size;

    if let boot_info = boot_info() {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
        let mut mapper = init_mapper(phys_mem_offset);

        for page in Page::range_inclusive(
            Page::<Size4KiB>::containing_address(stack_start),
            Page::<Size4KiB>::containing_address(stack_end - 0x1000),
        ) {
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
            match map_page(&mut mapper, page, &mut frame_allocator, flags) {
                Ok(_) => {}
                Err(MapToError::PageAlreadyMapped(..)) => {}
                Err(e) => {
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }

        let aligned_stack_end = VirtAddr::new((stack_end.as_u64() - 0x1000) & !0xF);
        Ok(aligned_stack_end)
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}
//TODO: very simple bump allocator change if needed
const MMIO_BASE: u64 = 0xFFFF_C000_0000_0000;
const MMIO_LIMIT: u64 = 0xFFFF_FF00_0000_0000;
const MAX_PENDING_FREES: usize = 64;

static mut PENDING_FREES: [Option<(u64, u64)>; MAX_PENDING_FREES] = [None; MAX_PENDING_FREES];
static PENDING_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);

static NEXT_MMIO_VADDR: AtomicU64 = AtomicU64::new(MMIO_BASE);
fn allocate_mmio_virtual_range(size: u64) -> Option<VirtAddr> {
    let aligned_size = (size + 0xFFF) & !0xFFF; // Align to 4KiB
    let current = NEXT_MMIO_VADDR.fetch_add(aligned_size, Ordering::SeqCst);

    if current + aligned_size > MMIO_LIMIT {
        None
    } else {
        Some(VirtAddr::new(current))
    }
}
fn unmap_mmio_region(
    mapper: &mut impl Mapper<Size4KiB>,
    virtual_addr: VirtAddr,
    size: u64,
) {
    let num_pages = (size + 0xFFF) / 4096;

    for i in 0..num_pages {
        let page = Page::containing_address(virtual_addr + i * 4096);
        unsafe {
            if let Ok((_, flush)) = mapper.unmap(page) {
                flush.flush();
            }
        }
    }
}

pub fn deallocate_mmio_virtual_range(
    addr: VirtAddr,
    size: u64,
) {
    let aligned_size = (size + 0xFFF) & !0xFFF;
    let addr_val = addr.as_u64();


    if let boot_info = boot_info() {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut mapper = init_mapper(phys_mem_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

        unmap_mmio_region(&mut mapper, addr, aligned_size);

        // Try to shrink bump pointer
        let expected = addr_val + aligned_size;
        if NEXT_MMIO_VADDR
            .compare_exchange(expected, addr_val, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            process_pending_frees();
        } else {
            // Can't free immediately, queue it
            unsafe {
                let idx = PENDING_FREE_COUNT.fetch_add(1, Ordering::SeqCst);
                if idx < MAX_PENDING_FREES {
                    PENDING_FREES[idx] = Some((addr_val, aligned_size));
                }
            }
        }
    }
}

fn process_pending_frees() {
    unsafe {
        let mut i = 0;
        while i < PENDING_FREE_COUNT.load(Ordering::SeqCst) {
            if let Some((addr, size)) = PENDING_FREES[i] {
                let expected = addr + size;
                if NEXT_MMIO_VADDR
                    .compare_exchange(expected, addr, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    // Already unmapped when added to queue — safe to reclaim now
                    for j in i..(MAX_PENDING_FREES - 1) {
                        PENDING_FREES[j] = PENDING_FREES[j + 1];
                    }
                    PENDING_FREES[MAX_PENDING_FREES - 1] = None;
                    PENDING_FREE_COUNT.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
            }
            i += 1;
        }
    }
}


pub fn map_mmio_region(
    mmio_base: PhysAddr,
    mmio_size: u64,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let phys_frame = PhysFrame::containing_address(mmio_base);
    let num_pages = (mmio_size + 0xFFF) / 4096;

    let virtual_addr = allocate_mmio_virtual_range(mmio_size)
        .ok_or_else(|| MapToError::FrameAllocationFailed)?;

    if let boot_info = boot_info() {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());
        let mut mapper = init_mapper(phys_mem_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

        for i in 0..num_pages {
            let page = Page::containing_address(virtual_addr + i * 4096);
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
            unsafe {
                mapper.map_to(page, phys_frame + i, flags, &mut frame_allocator)?.flush();
            }
        }
    }

    Ok(virtual_addr)
}
