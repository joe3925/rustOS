use alloc::collections::linked_list::LinkedList;
use kernel_types::status::PageMapError;
use spin::Mutex;
use x86_64::{structures::paging::PageTableFlags, VirtAddr};

use crate::memory::paging::{
    frame_alloc::BootInfoFrameAllocator,
    paging::{align_up_4k, map_kernel_range},
    tables::init_mapper,
    virt_tracker::{allocate_auto_kernel_range_aligned, unmap_range},
};
use crate::util::boot_info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StackSize {
    Tiny = 4 * 1024,
    Small = 8 * 1024,
    Medium = 16 * 1024,
    Large = 64 * 1024,
    Huge2M = 2 * 1024 * 1024,
    Huge1G = 1024 * 1024 * 1024,
}

impl StackSize {
    #[inline]
    pub const fn as_bytes(self) -> u64 {
        self as u64
    }

    #[inline]
    pub const fn total_size_with_guard(self) -> u64 {
        self.as_bytes() + 0x1000
    }

    #[inline]
    pub const fn required_alignment(self) -> u64 {
        match self {
            StackSize::Tiny | StackSize::Small | StackSize::Medium | StackSize::Large => 0x1000,
            StackSize::Huge2M => 2 * 1024 * 1024,
            StackSize::Huge1G => 1024 * 1024 * 1024,
        }
    }
}

impl Default for StackSize {
    fn default() -> Self {
        StackSize::Huge2M
    }
}

const GUARD_4K: u64 = 0x1000;

pub fn allocate_kernel_stack(size: StackSize) -> Result<VirtAddr, PageMapError> {
    let max_stack = StackSize::Huge2M.as_bytes();
    let reserve_total = max_stack + GUARD_4K;

    let map_bytes = {
        let b = align_up_4k(size.as_bytes());
        if b > max_stack {
            max_stack
        } else {
            b
        }
    };

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    // Reserve a full 2MiB stack window (+4KiB hard guard) but do NOT map it yet.
    let region_base =
        allocate_auto_kernel_range_aligned(reserve_total, StackSize::Huge2M.required_alignment())
            .ok_or(PageMapError::NoMemory())?;
    let stack_top = region_base + reserve_total;

    // Map only the requested initial stack bytes at the *top* of the 2MiB window.
    // Layout (low -> high):
    //   [region_base .. region_base+4K)                 unmapped hard guard
    //   [region_base+4K .. stack_top-map_bytes)         unmapped reserve (for growth)
    //   [stack_top-map_bytes .. stack_top)             mapped initial stack
    let map_start = stack_top - map_bytes;

    unsafe { map_kernel_range(map_start, map_bytes, flags) }?;

    Ok(stack_top)
}

pub fn deallocate_kernel_stack(stack_top: VirtAddr, _size: StackSize) {
    let reserve_total = StackSize::Huge2M.as_bytes() + GUARD_4K;
    let region_base = stack_top - reserve_total;
    unmap_range(region_base, reserve_total);
}
