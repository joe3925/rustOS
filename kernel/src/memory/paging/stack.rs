use alloc::collections::linked_list::LinkedList;
use kernel_types::status::PageMapError;
use spin::Mutex;
use x86_64::{structures::paging::PageTableFlags, VirtAddr};

use crate::memory::paging::{
    paging::align_up_4k,
    virt_tracker::{
        allocate_auto_kernel_range_mapped, allocate_auto_kernel_range_mapped_aligned, unmap_range,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StackSize {
    /// 4 KiB - Single standard page (minimal stack)
    Tiny = 4 * 1024,
    /// 8 KiB - Two standard pages (typical kernel stack)
    Small = 8 * 1024,
    /// 16 KiB - Four standard pages
    Medium = 16 * 1024,
    /// 64 KiB - Sixteen standard pages
    Large = 64 * 1024,
    /// 2 MiB - Single huge page (requires 2MiB alignment)
    Huge2M = 2 * 1024 * 1024,
    /// 1 GiB - Single gigantic page (requires 1GiB alignment)
    Huge1G = 1024 * 1024 * 1024,
}

impl StackSize {
    #[inline]
    pub const fn as_bytes(self) -> u64 {
        self as u64
    }

    /// Total allocation size including 4KiB guard page
    #[inline]
    pub const fn total_size_with_guard(self) -> u64 {
        self.as_bytes() + 0x1000
    }

    /// Required alignment for efficient huge page mapping.
    /// For huge page sizes, alignment must match page size.
    /// For smaller sizes, 4KiB is sufficient.
    #[inline]
    pub const fn required_alignment(self) -> u64 {
        match self {
            StackSize::Tiny | StackSize::Small | StackSize::Medium | StackSize::Large => 0x1000,
            StackSize::Huge2M => 2 * 1024 * 1024,
            StackSize::Huge1G => 1024 * 1024 * 1024,
        }
    }

    /// Whether this size benefits from huge page mapping
    #[inline]
    pub const fn uses_huge_pages(self) -> bool {
        matches!(self, StackSize::Huge2M | StackSize::Huge1G)
    }
}

impl Default for StackSize {
    fn default() -> Self {
        StackSize::Huge2M
    }
}

pub fn allocate_kernel_stack(size: StackSize) -> Result<VirtAddr, PageMapError> {
    let stack_bytes = size.as_bytes();
    let guard_page = 0x1000u64;
    let total_size = stack_bytes + guard_page;
    let alignment = size.required_alignment();

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    let stack_base = if size.uses_huge_pages() {
        allocate_auto_kernel_range_mapped_aligned(total_size, alignment, flags)?
    } else {
        allocate_auto_kernel_range_mapped(total_size, flags)?
    };

    let stack_top = (stack_base + total_size) - guard_page;

    Ok(stack_top)
}

pub fn deallocate_kernel_stack(stack_top: VirtAddr, size: StackSize) {
    let total_size = size.total_size_with_guard();
    let stack_base = stack_top - total_size;
    unmap_range(stack_base, total_size);
}
