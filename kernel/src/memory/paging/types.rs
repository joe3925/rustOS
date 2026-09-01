use acpi::PhysicalMapping;
use hashbrown::hash_table::Iter;
use kernel_types::arch::{PhysAddr, VirtAddr};
use kernel_types::dma::implementation::PhysicalFrameExtent;

use crate::memory::paging::address_space::AddressSpaceRoot;
use crate::memory::paging::map::map_contiguous_physical_range;

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
    pub heap_range_start: VirtAddr,
    pub heap_range_end: VirtAddr,
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
    pub user_accessible: bool,
    pub writable: bool,
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
            stride: crate::memory::paging::layout::base_page_size(),
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

pub struct PhysicalMemoryIter {
    // In order to identify extents we may end up translating an extra page -> frame. This caches that extra frame
    next_frame: Option<ResolvedMapping>,
    addr_space_root: AddressSpaceRoot,
    cursor: VirtAddr,
    base_address: VirtAddr,
    len: u64,
}
impl PhysicalMemoryIter {
    pub fn len(&self) -> u64 {
        return self.len;
    }
    /// While an iter can be created for any sized virtual range, its returned extents will always be page aligned and at least page sized.
    pub fn new(addr_space_root: AddressSpaceRoot, base_address: VirtAddr, len: u64) -> Self {
        Self {
            next_frame: None,
            addr_space_root,
            cursor: base_address,
            base_address,
            len,
        }
    }
}

impl Iterator for PhysicalMemoryIter {
    type Item = PhysicalFrameExtent;

    fn next(&mut self) -> Option<Self::Item> {
        let mapping = match self.next_frame.take() {
            Some(mapping) => mapping,
            None => {
                let mapping =
                    crate::platform::resolve_mapping_in_root(self.addr_space_root, self.cursor)?;

                self.cursor += mapping.mapping_size;
                mapping
            }
        };

        let phys_base = mapping.phys_addr;
        let mut phys_len = mapping.mapping_size;
        let virt_base = self.cursor.as_u64() - mapping.mapping_size;

        while self.cursor - self.base_address < self.len {
            let Some(mapping) =
                crate::platform::resolve_mapping_in_root(self.addr_space_root, self.cursor)
            else {
                break;
            };

            self.cursor += mapping.mapping_size;

            if phys_base.as_u64() + phys_len != mapping.phys_addr.as_u64() {
                self.next_frame = Some(mapping);
                break;
            }

            phys_len += mapping.mapping_size;
        }

        unsafe {
            Some(PhysicalFrameExtent::new(
                phys_base.as_u64(),
                phys_len,
                VirtAddr::new(virt_base),
            ))
        }
    }
}
