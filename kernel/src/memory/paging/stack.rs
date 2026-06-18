use kernel_types::arch::{PageFlags, VirtAddr};
use kernel_types::status::PageMapError;

use super::layout::{align_up, base_page_size, supported_mapping_sizes};
use super::map::{map_range, unmap_range};
use super::virt_tracker::allocate_auto_kernel_range_aligned;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StackSize {
    Tiny,
    Small,
    Medium,
    Large,
    #[default]
    Huge,
}

impl StackSize {
    #[inline]
    pub fn as_bytes(self) -> u64 {
        match self {
            Self::Tiny => 4 * 1024,
            Self::Small => 8 * 1024,
            Self::Medium => 16 * 1024,
            Self::Large => 64 * 1024,
            Self::Huge => 16 * 1024 * 1024,
        }
    }

    #[inline]
    pub fn total_size_with_guard(self) -> u64 {
        self.as_bytes() + base_page_size()
    }

    #[inline]
    pub fn required_alignment(self) -> u64 {
        required_alignment_for_bytes(self.as_bytes())
    }
}

fn required_alignment_for_bytes(bytes: u64) -> u64 {
    for size in supported_mapping_sizes() {
        if bytes >= size.bytes {
            return size.bytes;
        }
    }
    base_page_size()
}

pub fn kernel_stack_max_bytes() -> u64 {
    StackSize::Huge.as_bytes()
}

pub fn kernel_stack_reservation_bytes() -> u64 {
    kernel_stack_max_bytes() + base_page_size()
}

pub fn allocate_kernel_stack(size: StackSize) -> Result<VirtAddr, PageMapError> {
    let max_stack = kernel_stack_max_bytes();
    let reserve_total = kernel_stack_reservation_bytes();

    let map_bytes = {
        let bytes = align_up(size.as_bytes(), base_page_size()).ok_or(PageMapError::NoMemory())?;
        if bytes > max_stack {
            max_stack
        } else {
            bytes
        }
    };

    let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE;

    let region_base =
        allocate_auto_kernel_range_aligned(reserve_total, required_alignment_for_bytes(max_stack))
            .ok_or(PageMapError::NoMemory())?;
    let stack_top = VirtAddr::new(region_base.as_u64() + reserve_total);
    let map_start = VirtAddr::new(stack_top.as_u64() - map_bytes);

    if let Err(err) = unsafe { map_range(map_start, map_bytes, flags, false) } {
        unmap_range(region_base, reserve_total);
        return Err(err);
    }

    Ok(stack_top)
}

pub fn deallocate_kernel_stack(stack_top: VirtAddr) {
    let reserve_total = kernel_stack_reservation_bytes();
    let region_base = VirtAddr::new(stack_top.as_u64() - reserve_total);
    unmap_range(region_base, reserve_total);
}
