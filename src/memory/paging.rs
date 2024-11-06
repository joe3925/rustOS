use crate::BOOT_INFO;
use bootloader::bootinfo::MemoryMap;
use bootloader::bootinfo::MemoryRegionType;
use core::ptr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, PageTable, PageTableFlags, PhysFrame, Size2MiB, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

#[derive(Clone, Copy)]
pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
}

impl BootInfoFrameAllocator {
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        BootInfoFrameAllocator {
            memory_map,
            next: 0,
        }
    }
}
unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}
// Implement `FrameAllocator<Size2MiB>` for `BootInfoFrameAllocator`
unsafe impl FrameAllocator<Size2MiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let frame = self.usable_2mb_frames().nth(self.next);
        self.next += 1;
        frame
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
        // Filter out non-usable regions from the memory map
        self.memory_map
            .iter()
            .filter(|region| region.region_type == MemoryRegionType::Usable)
            .flat_map(|region| {
                // Get the starting address of the region, rounded up to 2 MiB alignment
                let start_addr = PhysAddr::new(region.range.start_addr());
                let start_frame_addr = start_addr.align_up(Size2MiB::SIZE);

                // Get the ending address of the region, rounded down to 2 MiB alignment
                let end_frame_addr = PhysAddr::new(region.range.end_addr()).align_down(Size2MiB::SIZE);

                // Calculate the range of frames in this region
                let num_frames = (end_frame_addr.as_u64() - start_frame_addr.as_u64()) / Size2MiB::SIZE;

                // Create an iterator over all aligned frames within the usable range
                (0..num_frames).map(move |i| {
                    let frame_start = start_frame_addr + i * Size2MiB::SIZE;
                    PhysFrame::containing_address(frame_start)
                })
            })
    }
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
    ptr::write(page_ptr, 0xF4);
    ptr::write(page_ptr.add(1), 0x0F);       // First byte of syscall opcode
    ptr::write(page_ptr.add(2), 0x05); // Second byte of syscall opcode
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
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_map);
        let mut mapper = init_mapper(VirtAddr::new(boot_info.physical_memory_offset));

        let mut base_addr = 0x4000_0000u64;
        let mut page: Page<Size4KiB>;

        loop {
            page = Page::containing_address(VirtAddr::new(base_addr));
            if mapper.translate_page(page).is_err() {
                break; // Found an unmapped page
            }
            base_addr += 0x1000; // Move to the next page (4 KiB)
        }

        let frame = frame_allocator.allocate_frame().ok_or("Failed to allocate frame")?;

        mapper.map_to(page, frame, flags, &mut frame_allocator)
            .expect("failed to map user page")
            .flush();

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
/// Allocates a stack for a user-mode task with guard pages.
pub(crate) unsafe fn allocate_user_stack(
    stack_size: u64,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    // Initial base address to start searching from
    let mut base_addr = 0x8000_0000u64;

    // Calculate the total size needed, including the guard page (4 KiB)
    let total_stack_size = stack_size + 0x1000;
    let mut stack_end;

    if let Some(boot_info) = BOOT_INFO {
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_map);
        let mut mapper = init_mapper(VirtAddr::new(boot_info.physical_memory_offset));

        // Loop to find a free range that fits the total stack size (including guard page)
        loop {
            let stack_start = VirtAddr::new(base_addr);
            stack_end = stack_start + total_stack_size;

            // Check each page in the range to see if it's already mapped
            let mut is_range_free = true;
            for page in Page::<Size4KiB>::range_inclusive(
                Page::containing_address(stack_start),
                Page::containing_address(stack_end - 0x1000), // Exclude guard page
            ) {
                if mapper.translate_page(page).is_ok() {
                    is_range_free = false;
                    break;
                }
            }

            // If the entire range is free, proceed to allocate
            if is_range_free {
                break;
            }
            // Increment the base address by the total size needed (including guard page)
            base_addr += total_stack_size;
        }

        // Map each page in the stack range, leaving the guard page unmapped
        for page in Page::range_inclusive(
            Page::<Size4KiB>::containing_address(VirtAddr::new(base_addr)),
            Page::<Size4KiB>::containing_address(stack_end - 0x1000), // Last page as guard
        ) {
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            let frame = frame_allocator.allocate_frame().ok_or(MapToError::FrameAllocationFailed)?;
            mapper.map_to(page, frame, flags, &mut frame_allocator)?.flush();
        }

        // Ensure the stack pointer is properly aligned to a 16-byte boundary.
        let aligned_stack_end = VirtAddr::new((stack_end.as_u64() - 0x1000) & !0xF);
        Ok(aligned_stack_end)
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}

pub(crate) unsafe fn allocate_kernel_stack(
    stack_size: u64,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    // Initial base address to start searching from
    let stack_start = 0xFFFF_8000_0000_0000; // Example kernel-space stack base (adjust as needed)

    // Calculate the total size needed, including the guard page (4 KiB)
    let total_stack_size = stack_size + 0x1000;
    let mut stack_end;

    if let Some(boot_info) = BOOT_INFO {
        let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_map);
        let mut mapper = init_mapper(VirtAddr::new(boot_info.physical_memory_offset));

        // Loop to find a free range that fits the total stack size (including guard page)
        loop {
            let mut stack_start = VirtAddr::new(stack_start);
            stack_end = stack_start + total_stack_size;

            // Check each page in the range to see if it's already mapped
            let mut is_range_free = true;
            for page in Page::<Size4KiB>::range_inclusive(
                Page::containing_address(stack_start),
                Page::containing_address(stack_end - 0x1000), // Exclude guard page
            ) {
                if mapper.translate_page(page).is_ok() {
                    is_range_free = false;
                    break;
                }
            }

            // If the entire range is free, proceed to allocate
            if is_range_free {
                break;
            }
            // Increment the base address by the total size needed (including guard page)
            stack_start += total_stack_size;
        }

        // Map each page in the stack range, leaving the guard page unmapped
        for page in Page::range_inclusive(
            Page::<Size4KiB>::containing_address(VirtAddr::new(stack_start)),
            Page::<Size4KiB>::containing_address(stack_end - 0x1000), // Last page as guard
        ) {
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
            let frame = frame_allocator.allocate_frame().ok_or(MapToError::FrameAllocationFailed)?;
            mapper.map_to(page, frame, flags, &mut frame_allocator)?.flush();
        }

        // Ensure the stack pointer is properly aligned to a 16-byte boundary.
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
    // Convert the physical address to a frame
    let phys_frame = PhysFrame::containing_address(mmio_base);

    // Calculate the number of pages to map based on the MMIO size
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