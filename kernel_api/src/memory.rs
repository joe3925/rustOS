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
pub use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};

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

pub fn virt_to_phys(addr: VirtAddr) -> Option<PhysAddr> {
    unsafe { kernel_sys::virt_to_phys(addr) }
}
