use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;

use crate::memory::paging::types::UserVmLayout;
use crate::memory::paging::{
    KernelVirtualLayout, LocalTlbFlush, MappingSize, PagingCapabilities, ResolvedMapping,
    UnmapFrameDisposition,
};
use crate::platform::{PageTableFrameAllocator, PagingPlatform};

use super::super::platform::Aarch64Platform;

impl PagingPlatform for Aarch64Platform {
    fn paging_capabilities() -> PagingCapabilities { todo!() }
    fn kernel_virtual_layout() -> KernelVirtualLayout { todo!() }
    fn user_virtual_layout() -> UserVmLayout { todo!() }
    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        _allocator: &mut A,
        _virt: VirtAddr,
        _phys: PhysAddr,
        _size: MappingSize,
        _flags: PageFlags,
        _cache: Option<PhysicalMappingCache>,
        _flush: LocalTlbFlush,
    ) -> Result<(), PageMapError> { todo!() }
    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        _allocator: &mut A,
        _virt: VirtAddr,
        _size: MappingSize,
        _disposition: UnmapFrameDisposition,
        _flush: LocalTlbFlush,
    ) -> Result<Option<PhysAddr>, PageMapError> { todo!() }
    fn resolve_mapping(_virt: VirtAddr) -> Option<ResolvedMapping> { todo!() }
    fn resolve_mapping_in_root(_root: Self::Root, _virt: VirtAddr) -> Option<ResolvedMapping> { todo!() }
    fn local_flush_tlb_all() { todo!() }
    fn local_flush_tlb_range(_start: VirtAddr, _size: u64, _stride: u64) { todo!() }
    fn broadcast_tlb_shootdown() -> bool { todo!() }
}
