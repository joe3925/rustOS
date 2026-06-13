use crate::platform::{ActivePlatform, PagingPlatform};
use kernel_types::arch::VirtAddr as AbiVirtAddr;

use super::types::{KernelVirtualLayout, MappingSize, PagingCapabilities};

pub fn paging_capabilities() -> PagingCapabilities {
    <ActivePlatform as PagingPlatform>::paging_capabilities()
}

pub fn kernel_virtual_layout() -> KernelVirtualLayout {
    <ActivePlatform as PagingPlatform>::kernel_virtual_layout()
}

pub fn kernel_space_base() -> AbiVirtAddr {
    kernel_virtual_layout().kernel_space_base
}

pub fn managed_kernel_range_start() -> AbiVirtAddr {
    kernel_virtual_layout().managed_kernel_range_start
}

pub fn managed_kernel_range_end() -> AbiVirtAddr {
    kernel_virtual_layout().managed_kernel_range_end
}

pub fn mmio_base() -> AbiVirtAddr {
    kernel_virtual_layout().mmio_base
}

pub fn low_physical_reserve_bytes() -> u64 {
    kernel_virtual_layout().low_physical_reserve_bytes
}

pub fn base_page_size() -> u64 {
    paging_capabilities().base_page_size
}

pub fn supported_mapping_sizes() -> &'static [MappingSize] {
    paging_capabilities().leaf_mapping_sizes
}

pub fn largest_mapping_size_for(total_size: u64, phys_base: Option<u64>) -> u64 {
    for size in supported_mapping_sizes() {
        if total_size < size.bytes {
            continue;
        }

        if let Some(phys) = phys_base {
            if !is_aligned(phys, size.bytes) {
                continue;
            }
        }

        return size.bytes;
    }

    base_page_size()
}

#[inline]
pub fn is_aligned(value: u64, align: u64) -> bool {
    align != 0 && (value % align) == 0
}

#[inline]
pub fn align_down(value: u64, align: u64) -> Option<u64> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }
    Some(value & !(align - 1))
}

#[inline]
pub fn align_up(value: u64, align: u64) -> Option<u64> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }

    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

#[inline]
pub fn align_up_to_base_page(value: u64) -> Option<u64> {
    align_up(value, base_page_size())
}

#[inline]
pub fn bytes_to_base_frames_rounded(bytes: u64) -> Option<usize> {
    let page = base_page_size();
    let aligned = align_up(bytes, page)?;
    usize::try_from(aligned / page).ok()
}
