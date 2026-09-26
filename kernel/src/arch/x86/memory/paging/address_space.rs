use core::mem::size_of;

use kernel_types::arch::AddressSpaceRoot;
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;
use x86_64::PhysAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PhysFrame};

use crate::platform::{AddressSpacePlatform, PageTableFrameAllocator};
use crate::util::boot_info;

use super::super::super::platform::X86Platform;
use super::tables::{init_kernel_cr3, kernel_cr3};

impl AddressSpacePlatform for X86Platform {
    fn init_kernel_root() {
        init_kernel_cr3();
    }

    fn kernel_root() -> AddressSpaceRoot {
        unsafe { AddressSpaceRoot::from_raw(kernel_cr3().start_address().as_u64()) }
    }

    fn current_root() -> AddressSpaceRoot {
        unsafe { AddressSpaceRoot::from_raw(Cr3::read().0.start_address().as_u64()) }
    }

    unsafe fn switch_root(root: AddressSpaceRoot) {
        unsafe {
            Cr3::write(
                PhysFrame::containing_address(PhysAddr::new(root.as_u64())),
                Cr3::read().1,
            );
        }
    }

    fn create_user_root<A: PageTableFrameAllocator>(
        allocator: &mut A,
    ) -> Result<AddressSpaceRoot, PageMapError> {
        let root_phys = allocator
            .allocate_page_table_frame()
            .ok_or(PageMapError::NoMemory())?;

        let root_virt = crate::memory::paging::mmio::map_physical_pages(
            root_phys,
            size_of::<PageTable>() as u64,
            PhysicalMappingCache::Cached,
        )?;

        let info = &boot_info().arch_info;
        let kernel_pml4_address = info
            .physical_memory_offset
            .checked_add(Self::kernel_root().as_u64())
            .ok_or(PageMapError::TranslationFailed())?;
        let kernel_pml4 = unsafe { &*(kernel_pml4_address as *const PageTable) };
        let new_table: &mut PageTable = unsafe { &mut *(root_virt.address().as_mut_ptr()) };
        new_table.zero();

        for idx in 256..512 {
            new_table[idx] = kernel_pml4[idx].clone();
        }
        Ok(unsafe { AddressSpaceRoot::from_raw(root_phys.as_u64()) })
    }

    unsafe fn destroy_user_root<A: PageTableFrameAllocator>(
        root: AddressSpaceRoot,
        allocator: &mut A,
    ) -> Result<(), PageMapError> {
        if root == Self::current_root() || root == Self::kernel_root() {
            return Err(PageMapError::TranslationFailed());
        }
        allocator.free_page_table_frame(root.physical_address());
        Ok(())
    }
}
