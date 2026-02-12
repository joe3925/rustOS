use core::alloc::{GlobalAlloc, Layout};
use kernel_sys::{kernel_alloc, kernel_free};
pub struct KernelAllocator;
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        kernel_alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        kernel_free(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

pub use kernel_types::status::PageMapError;
use kernel_types::PHYSICAL_MEMORY_OFFSET;
pub use x86_64::structures::paging::PageTableFlags;
use x86_64::{registers::control::Cr3, structures::paging::PageTable, PhysAddr, VirtAddr};

pub fn map_mmio_region(base: PhysAddr, size: u64) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::map_mmio_region(base, size) }
}
pub fn unmap_mmio_region(base: VirtAddr, size: u64) -> Result<(), PageMapError> {
    unsafe { kernel_sys::unmap_mmio_region(base, size) }
}

pub unsafe fn unmap_range(addr: VirtAddr, size: u64) {
    unsafe {
        kernel_sys::unmap_range(addr, size);
    }
}

pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::allocate_auto_kernel_range_mapped(size, flags) }
}

pub fn allocate_auto_kernel_range_mapped_contiguous(
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::allocate_auto_kernel_range_mapped_contiguous(size, flags) }
}

pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageTableFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::allocate_kernel_range_mapped(base, size, flags) }
}

pub fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    unsafe { kernel_sys::deallocate_kernel_range(addr, size) }
}
#[inline(always)]
fn get_level4_page_table(mem_offset: VirtAddr) -> &'static mut PageTable {
    let (table_frame, _) = Cr3::read();
    let virt_addr = mem_offset + table_frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}
#[inline(always)]
pub fn virt_to_phys(to_phys: VirtAddr) -> Option<PhysAddr> {
    let mem_offset = PHYSICAL_MEMORY_OFFSET;
    let l4 = get_level4_page_table(mem_offset);
    let l4e = &l4[to_phys.p4_index()];
    if !l4e.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }

    // Level 3
    let l3_virt = mem_offset + l4e.addr().as_u64();
    let l3_table: &PageTable = unsafe { &*(l3_virt.as_ptr()) };
    let l3e = &l3_table[to_phys.p3_index()];
    if !l3e.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }
    if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
        // 1 GiB page
        let base = l3e.addr().as_u64();
        let offset = to_phys.as_u64() & ((1u64 << 30) - 1);
        return Some(PhysAddr::new(base + offset));
    }

    // Level 2
    let l2_virt = mem_offset + l3e.addr().as_u64();
    let l2_table: &PageTable = unsafe { &*(l2_virt.as_ptr()) };
    let l2e = &l2_table[to_phys.p2_index()];
    if !l2e.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }
    if l2e.flags().contains(PageTableFlags::HUGE_PAGE) {
        // 2 MiB page
        let base = l2e.addr().as_u64();
        let offset = to_phys.as_u64() & ((1u64 << 21) - 1);
        return Some(PhysAddr::new(base + offset));
    }

    // Level 1
    let l1_virt = mem_offset + l2e.addr().as_u64();
    let l1_table: &PageTable = unsafe { &*(l1_virt.as_ptr()) };
    let l1e = &l1_table[to_phys.p1_index()];
    if !l1e.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }
    let base = l1e.addr().as_u64();
    let offset = to_phys.as_u64() & 0xFFF;
    Some(PhysAddr::new(base + offset))
}
