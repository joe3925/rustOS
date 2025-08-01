use alloc::collections::linked_list::LinkedList;
use spin::Mutex;
use x86_64::{structures::paging::PageTableFlags, VirtAddr};

use crate::memory::paging::{paging::{align_up_4k, PageMapError}, virt_tracker::{allocate_auto_kernel_range_mapped, unmap_range}};

pub static KERNEL_STACK_ALLOCATOR: Mutex<StackAllocator> = Mutex::new(StackAllocator::new(
    VirtAddr::new(0xFFFF_FFFF_8000_0000), // Kernel stacks start here
));

pub(crate) struct StackAllocator {
    base_address: VirtAddr,
    free_list: LinkedList<VirtAddr>, // List of free stack starting addresses
}

impl StackAllocator {
    pub const fn new(base_address: VirtAddr) -> Self {
        StackAllocator {
            base_address,
            free_list: LinkedList::new(),
        }
    }

    pub fn allocate(&mut self, size: u64) -> Option<VirtAddr> {
        if let Some(free_stack) = self.free_list.pop_front() {
            return Some(free_stack);
        }

        // Ensure alignment
        let alignment = 0x10000; // 64 KB alignment
        let total_stack_size = size + 0x1000; // Includes guard page

        // Align base address
        self.base_address =
            VirtAddr::new((self.base_address.as_u64() + alignment - 1) & !(alignment - 1));

        let stack_start = self.base_address;
        self.base_address = VirtAddr::new(self.base_address.as_u64() + total_stack_size);

        // Set up the guard page
        Some(stack_start)
    }

    pub fn deallocate(&mut self, stack_start: VirtAddr) {
        // Add the stack back to the free list for reuse
        self.free_list.push_back(stack_start);
    }
}

pub fn allocate_kernel_stack(size: u64) -> Result<VirtAddr, PageMapError> {
    let total_size = align_up_4k(size + 0x1000);

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    {
        // println!(
        //     "bump pointer: {:#X?}",
        //     KERNEL_RANGE_TRACKER.allocations.lock()
        // );
    }
    let stack_start_addr = (allocate_auto_kernel_range_mapped(total_size, flags))?;
    Ok((stack_start_addr + total_size) - 0x1000)
}

pub fn deallocate_kernel_stack(stack_top: VirtAddr, size: u64) {
    let total_size = size + 0x1000; // includes guard page
    let stack_start = stack_top - size;
    let full_range_start = stack_start - 0x1000;
    unmap_range(full_range_start, total_size);
}
