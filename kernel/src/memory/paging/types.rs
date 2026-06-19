use kernel_types::arch::{PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingSize {
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagingCapabilities {
    pub base_page_size: u64,
    pub leaf_mapping_sizes: &'static [MappingSize],
    pub supports_global_mappings: bool,
    pub supports_execute_disable: bool,
    pub supports_cache_attributes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelVirtualLayout {
    pub kernel_space_base: VirtAddr,
    pub managed_kernel_range_start: VirtAddr,
    pub managed_kernel_range_end: VirtAddr,
    pub mmio_base: VirtAddr,
    pub low_physical_reserve_bytes: u64,
}
#[derive(Debug, Clone, Copy)]
pub struct UserVmLayout {
    pub start: u64,
    pub end: u64,
    pub base_page_size: u64,
    pub stack_alignment: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedMapping {
    pub mapping_size: u64,
    pub phys_addr: PhysAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTlbFlush {
    Flush,
    Defer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmapFrameDisposition {
    FreeMappedFrame,
    ReleaseReservedFrame,
    KeepFrame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlbShootdownRange {
    pub start: VirtAddr,
    pub size: u64,
    pub stride: u64,
}

impl TlbShootdownRange {
    pub fn new(start: VirtAddr, size: u64) -> Self {
        Self {
            start,
            size,
            stride: crate::memory::paging::base_page_size(),
        }
    }

    pub const fn with_stride(start: VirtAddr, size: u64, stride: u64) -> Self {
        Self {
            start,
            size,
            stride,
        }
    }
}
