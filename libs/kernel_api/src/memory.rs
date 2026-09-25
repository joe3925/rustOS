use core::alloc::{GlobalAlloc, Layout};
use kernel_sys::{kernel_alloc, kernel_free};
pub struct KernelAllocator;
unsafe impl GlobalAlloc for KernelAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { kernel_alloc(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { kernel_free(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

pub use kernel_types::arch::{AddressSpaceRoot, PageFlags, PhysAddr, VirtAddr};
pub use kernel_types::memory::{KernelMapping, PhysicalMappingCache};
pub use kernel_types::status::PageMapError;

pub type PageTableFlags = PageFlags;

pub fn map_physical_pages(
    phys: PhysAddr,
    size: u64,
    cache: PhysicalMappingCache,
) -> Result<KernelMapping, PageMapError> {
    unsafe { kernel_sys::map_physical_pages(phys, size, cache) }
}

pub fn map_mmio_region(base: PhysAddr, size: u64) -> Result<KernelMapping, PageMapError> {
    map_physical_pages(base, size, PhysicalMappingCache::Uncached)
}

pub fn allocate_auto_kernel_mapping(
    size: u64,
    flags: PageFlags,
) -> Result<KernelMapping, PageMapError> {
    unsafe { kernel_sys::allocate_auto_kernel_mapping(size, flags) }
}

pub fn allocate_auto_contiguous_kernel_mapping(
    size: u64,
    flags: PageFlags,
) -> Result<KernelMapping, PageMapError> {
    unsafe { kernel_sys::allocate_auto_contiguous_kernel_mapping(size, flags) }
}

#[inline(always)]
pub fn virt_to_phys(to_phys: VirtAddr) -> Option<(u64, PhysAddr)> {
    virt_to_phys_in(kernel_address_space_root(), to_phys)
}

pub fn virt_to_phys_in(root: AddressSpaceRoot, to_phys: VirtAddr) -> Option<(u64, PhysAddr)> {
    unsafe { kernel_sys::virt_to_phys(root, to_phys) }
}

pub fn resolve_virtual_range_frame(
    root: AddressSpaceRoot,
    addr: VirtAddr,
) -> Option<(u64, PhysAddr)> {
    unsafe { kernel_sys::resolve_virtual_range_frame(root, addr) }
}

pub fn kernel_address_space_root() -> AddressSpaceRoot {
    unsafe { kernel_sys::kernel_address_space_root() }
}
