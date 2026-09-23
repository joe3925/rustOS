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
pub use kernel_types::memory::PhysicalMappingCache;
pub use kernel_types::status::PageMapError;

pub type PageTableFlags = PageFlags;

pub fn map_physical_pages(
    phys: PhysAddr,
    size: u64,
    cache: PhysicalMappingCache,
) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::map_physical_pages(phys, size, cache) }
}

/// # Safety
/// The range must be a live physical mapping owned by the caller and no users
/// may retain it after this call.
pub unsafe fn unmap_physical_pages(virt: VirtAddr, size: u64) -> Result<(), PageMapError> {
    unsafe { kernel_sys::unmap_physical_pages(virt, size) }
}

pub fn map_mmio_region(base: PhysAddr, size: u64) -> Result<VirtAddr, PageMapError> {
    map_physical_pages(base, size, PhysicalMappingCache::Uncached)
}

/// # Safety
/// The range must be a live MMIO mapping owned by the caller and no users may
/// retain it after this call.
pub unsafe fn unmap_mmio_region(base: VirtAddr, size: u64) -> Result<(), PageMapError> {
    unsafe { unmap_physical_pages(base, size) }
}

/// # Safety
/// The range must be a live mapping owned by the caller and no references may
/// survive this call.
pub unsafe fn unmap_range(addr: VirtAddr, size: u64) {
    unsafe { unmap_range_in(kernel_address_space_root(), addr, size) }
}

pub unsafe fn unmap_range_in(root: AddressSpaceRoot, addr: VirtAddr, size: u64) {
    unsafe {
        kernel_sys::unmap_range(root, addr, size);
    }
}

pub fn identity_map_page_in(root: AddressSpaceRoot, frame_addr: PhysAddr, flags: PageFlags) {
    unsafe { kernel_sys::identity_map_page(root, frame_addr, flags) }
}

pub fn identity_map_page(frame_addr: PhysAddr, flags: PageFlags) {
    identity_map_page_in(kernel_address_space_root(), frame_addr, flags)
}

pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::allocate_auto_kernel_range_mapped(size, flags) }
}

pub fn allocate_auto_kernel_range_mapped_contiguous(
    size: u64,
    flags: PageFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::allocate_auto_kernel_range_mapped_contiguous(size, flags) }
}

pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageFlags,
) -> Result<VirtAddr, PageMapError> {
    unsafe { kernel_sys::allocate_kernel_range_mapped(base, size, flags) }
}

/// # Safety
/// The range must be owned by the caller, no longer mapped or referenced, and
/// returned exactly once.
pub unsafe fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    unsafe { kernel_sys::deallocate_kernel_range(addr, size) }
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
