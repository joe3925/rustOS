use crate::BOOT_INFO;
use alloc::collections::LinkedList;
use bootloader::bootinfo::MemoryRegionType;
use bootloader::bootinfo::{MemoryMap, MemoryRegion};
use core::ptr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size2MiB, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

#[derive(Clone)]
pub(crate) struct BootInfoFrameAllocator {
    memory_map: &'static [MemoryRegion], // Provided at boot
}
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
static NEXT: Mutex<usize> = Mutex::new(0);
impl BootInfoFrameAllocator {
    pub fn init(memory_map: &'static MemoryMap) -> Self {
        BootInfoFrameAllocator {
            memory_map,
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut next = NEXT.lock(); // Lock the global NEXT counter
        let frame = self.usable_frames().nth(*next); // Get the nth usable frame
        *next += 1; // Increment the global NEXT counter
        frame
    }
}

unsafe impl FrameAllocator<Size2MiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let mut next = NEXT.lock(); // Lock the global NEXT counter

        // Ensure the NEXT pointer is aligned to 512 (2MiB boundary)
        if *next % 512 != 0 {
            *next += 512 - (*next % 512);
        }
        let base_frame = self.usable_2mb_frames().nth((*next / 512));

        // Mark all 512 frames as allocated by advancing the NEXT pointer
        *next += 512;

        base_frame
    }
}
impl BootInfoFrameAllocator {
    /// Returns an iterator over the usable frames specified in the memory map.
    fn usable_frames(&self) -> impl Iterator<Item=PhysFrame> {
        // get usable regions from memory map
        let regions = self.memory_map.iter();
        let usable_regions = regions
            .filter(|r| r.region_type == MemoryRegionType::Usable);
        // map each region to its address range
        let addr_ranges = usable_regions
            .map(|r| r.range.start_addr()..r.range.end_addr());
        // transform to an iterator of frame start addresses
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
        // create `PhysFrame` types from the start addresses
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
    /// Returns an iterator over usable 2 MiB-aligned frames in the memory map.
    fn usable_2mb_frames(&self) -> impl Iterator<Item=PhysFrame<Size2MiB>> {
        // get usable regions from memory map
        let regions = self.memory_map.iter();
        let usable_regions = regions
            .filter(|r| r.region_type == MemoryRegionType::Usable);
        // map each region to its address range
        let addr_ranges = usable_regions
            .map(|r| r.range.start_addr()..r.range.end_addr());
        // transform to an iterator of frame start addresses
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(2 * 1024 * 1024));
        // create PhysFrame types from the start addresses
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
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
    // Syscall instruction: `0x0F 0x05`
    ptr::write(page_ptr.add(0), 0x0F); // First byte of syscall opcode
    ptr::write(page_ptr.add(1), 0x05); // Second byte of syscall opcode

    ptr::write(page_ptr.add(2), 0xEB); // `jmp` opcode
    ptr::write(page_ptr.add(3), 0xFE); // Offset: -2 (signed byte)
}

/// Allocates a page with a syscall instruction at a free virtual address.
pub(crate) unsafe fn allocate_syscall_page() -> Result<VirtAddr, &'static str> {
    let page_addr = alloc_user_page()?; // Allocate the user page
    write_syscall(page_addr.as_mut_ptr()); // Write the syscall instruction
    Ok(page_addr)
}

// Function to allocate a user-accessible page with write and execute permissions
pub(crate) unsafe fn alloc_user_page() -> Result<VirtAddr, &'static str> {
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    if let Some(boot_info) = BOOT_INFO {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_map);
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
pub(crate) unsafe fn allocate_infinite_loop_page() -> Result<VirtAddr, &'static str> {
    let page_addr = alloc_user_page()?; // Allocate the user page
    write_infinite_loop(page_addr.as_mut_ptr()); // Write the infinite loop
    Ok(page_addr)
}
use spin::Mutex;
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

    pub unsafe fn allocate(&mut self) -> Option<VirtAddr> {
        // Reuse a freed stack if available
        if let Some(free_stack) = self.free_list.pop_front() {
            return Some(free_stack);
        }

        // Otherwise, allocate a new stack
        let total_stack_size = self.stack_size + 0x1000; // Includes guard page
        let alignment = 0x10000; // 64 KB alignment
        self.base_address = VirtAddr::new((self.base_address.as_u64() + alignment - 1) & !(alignment - 1)); // Align base address
        let stack_start = self.base_address;
        self.base_address = VirtAddr::new(self.base_address.as_u64() + total_stack_size); // Move base for the next stack
        Some(stack_start)
    }

    pub unsafe fn deallocate(&mut self, stack_start: VirtAddr) {
        // Add the stack back to the free list for reuse
        self.free_list.push_back(stack_start);
    }
}


/// Allocates a stack for a user-mode task with guard pages.
pub(crate) unsafe fn allocate_user_stack() -> Result<VirtAddr, MapToError<Size4KiB>> {
    let mut allocator = USER_STACK_ALLOCATOR.lock();
    let stack_start = allocator.allocate().expect("kernel stack alloc failed");
    let total_stack_size = USER_STACK_SIZE + 0x1000; //guard page
    let stack_end = stack_start + total_stack_size;

    if let Some(boot_info) = BOOT_INFO {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_map);
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


pub(crate) unsafe fn allocate_kernel_stack() -> Result<VirtAddr, MapToError<Size4KiB>> {
    let mut allocator = KERNEL_STACK_ALLOCATOR.lock();
    let stack_start = allocator.allocate().expect("kernel stack alloc failed");
    let total_stack_size = KERNEL_STACK_SIZE + 0x1000;
    let stack_end = stack_start + total_stack_size;

    if let Some(boot_info) = BOOT_INFO {
        let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_map);
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


pub fn map_mmio_region(
    mapper: &mut OffsetPageTable,
    frame_allocator: &mut BootInfoFrameAllocator,
    mmio_base: PhysAddr,          // The physical address of the MMIO region (from BAR)
    mmio_size: u64,               // The size of the MMIO region
    virtual_addr: VirtAddr,         // The virtual address to map it to
) -> Result<(), MapToError<Size4KiB>> {
    let phys_frame = PhysFrame::containing_address(mmio_base);

    let num_pages = (mmio_size + 0xFFF) / 4096; // 4KiB pages

    for i in 0..num_pages {
        let page = Page::containing_address(virtual_addr + i * 4096);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
        unsafe {
            mapper.map_to(page, phys_frame + i, flags, frame_allocator)?.flush();
        }
    }

    Ok(())
}