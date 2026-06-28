use core::mem::size_of;

use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableIndex, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use crate::platform::PageTableFrameAllocator;
use crate::util::boot_info;

use super::tables::{get_level4_page_table, init_kernel_cr3, kernel_cr3};

pub type Root = PhysFrame<Size4KiB>;

pub fn init_kernel_root() {
    init_kernel_cr3();
}

pub fn kernel_root() -> Root {
    kernel_cr3()
}

pub fn current_root() -> Root {
    Cr3::read().0
}

pub unsafe fn switch_root(root: Root) {
    unsafe {
        Cr3::write(root, Cr3::read().1);
    }
}

pub fn root_to_phys(root: Root) -> kernel_types::arch::PhysAddr {
    kernel_types::arch::PhysAddr::new(root.start_address().as_u64())
}

pub fn create_user_root<A: PageTableFrameAllocator>(
    allocator: &mut A,
) -> Result<Root, PageMapError> {
    let root_phys = allocator
        .allocate_page_table_frame()
        .ok_or(PageMapError::NoMemory())?;

    let root_virt = crate::memory::paging::map_physical_pages(
        root_phys,
        size_of::<PageTable>() as u64,
        PhysicalMappingCache::Cached,
    )?;

    let recursive_index = boot_info()
        .arch_info
        .recursive_index
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;
    let kernel_pml4 = unsafe { get_level4_page_table(PageTableIndex::new(recursive_index)) };
    let new_table: &mut PageTable = unsafe { &mut *(root_virt.as_mut_ptr()) };
    new_table.zero();

    for idx in 256..512 {
        new_table[idx] = kernel_pml4[idx].clone();
    }

    let _ = unsafe {
        crate::memory::paging::unmap_physical_pages(root_virt, size_of::<PageTable>() as u64)
    };

    Ok(PhysFrame::containing_address(PhysAddr::new(
        root_phys.as_u64(),
    )))
}

pub unsafe fn destroy_user_root<A: PageTableFrameAllocator>(
    root: Root,
    allocator: &mut A,
) -> Result<(), PageMapError> {
    allocator.free_page_table_frame(root.start_address().into());
    Ok(())
}
