use bootloader::bootinfo::MemoryMap;
use x86_64::structures::paging::{FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::registers::control::Cr3;
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::mapper::MapToError;
use bootloader::bootinfo::MemoryRegionType;
use crate::BOOT_INFO;

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
impl BootInfoFrameAllocator {
    /// Returns an iterator over the usable frames specified in the memory map.
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
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
/// Allocates a stack for a user-mode task.
pub(crate) unsafe fn allocate_user_stack(
    stack_size: u64,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let stack_start = VirtAddr::new(0x8000_0000); // Example user-space stack base (adjust as needed)
    let stack_end = stack_start + stack_size;

    if let Some(boot_info) = unsafe { BOOT_INFO } {
        let mut frame_allocator = unsafe {
            BootInfoFrameAllocator::init(&boot_info.memory_map)
        };
        let mut mapper = unsafe {
            init_mapper(VirtAddr::new(boot_info.physical_memory_offset))
        };

        for page in Page::range_inclusive(
            Page::containing_address(stack_start),
            Page::containing_address(stack_end - 1u64),
        ) {
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            let frame = frame_allocator
                .allocate_frame()
                .ok_or(MapToError::FrameAllocationFailed)?;
            unsafe {
                mapper.map_to(page, frame, flags, &mut frame_allocator)?.flush();
            }
        }

        // Ensure the stack pointer is properly aligned to a 16-byte boundary.
        let aligned_stack_end = VirtAddr::new((stack_end.as_u64() & !0xF));
        Ok(aligned_stack_end)
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}
pub(crate) unsafe fn allocate_kernel_stack(
    stack_size: u64,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let stack_start = VirtAddr::new(0xFFFF_8000_0000_0000); // Example kernel-space stack base (adjust as needed)
    let stack_end = stack_start + stack_size;

    if let Some(boot_info) = unsafe { BOOT_INFO } {
        let mut frame_allocator = unsafe {
            BootInfoFrameAllocator::init(&boot_info.memory_map)
        };
        let mut mapper = unsafe {
            init_mapper(VirtAddr::new(boot_info.physical_memory_offset))
        };

        for page in Page::range_inclusive(
            Page::containing_address(stack_start),
            Page::containing_address(stack_end - 1u64),
        ) {
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
            let frame = frame_allocator
                .allocate_frame()
                .ok_or(MapToError::FrameAllocationFailed)?;
            unsafe {
                mapper.map_to(page, frame, flags, &mut frame_allocator)?.flush();
            }
        }

        Ok(stack_end)
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}
    pub fn map_mmio_region(
        mapper: &mut OffsetPageTable,
        frame_allocator: &mut BootInfoFrameAllocator,
        mmio_base: PhysAddr,          // The physical address of the MMIO region (from BAR)
        mmio_size: u64,               // The size of the MMIO region
        virtual_addr: VirtAddr         // The virtual address to map it to
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