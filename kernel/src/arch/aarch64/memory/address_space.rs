use aarch64_cpu::asm::barrier::{ISH, ISHST, SY, dsb, isb};
use aarch64_cpu::registers::{Readable, TCR_EL1, TTBR0_EL1, TTBR1_EL1, Writeable};
use kernel_types::arch::PhysAddr;
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;
use spin::Once;

use crate::platform::{AddressSpacePlatform, PageTableFrameAllocator};
use crate::util::boot_info;

use super::super::platform::Aarch64Platform;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Root(u64);

impl Root {
    pub(super) const fn physical_address(self) -> PhysAddr {
        PhysAddr::new(self.0)
    }
}

static KERNEL_ROOT: Once<Root> = Once::new();

impl AddressSpacePlatform for Aarch64Platform {
    type Root = Root;

    fn init_kernel_root() {
        assert_eq!(boot_info().arch_info.granule_shift, 12);
        assert!(boot_info().arch_info.output_addr_bits <= 48);
        let root = Root(boot_info().arch_info.root_table);
        assert_eq!(root_from_ttbr(TTBR1_EL1.get()), root);
        let tcr = super::super::cpu::startup_tcr(TCR_EL1.get());
        let tcr_changed = TCR_EL1.get() != tcr;
        if tcr_changed {
            TCR_EL1.set(tcr);
            isb(SY);
        }
        if tcr_changed || root_from_ttbr(TTBR0_EL1.get()) != root {
            unsafe { Self::switch_root(root) };
        }
        KERNEL_ROOT.call_once(|| root);
    }

    fn kernel_root() -> Self::Root {
        *KERNEL_ROOT
            .get()
            .expect("kernel address-space root is not initialized")
    }

    fn current_root() -> Self::Root {
        root_from_ttbr(TTBR0_EL1.get())
    }

    unsafe fn switch_root(root: Self::Root) {
        assert_eq!(root.0 & (root_table_size() - 1), 0);
        let mask = ((1u64 << 48) - 1) & !(root_table_size() - 1);
        let ttbr0_controls = TTBR0_EL1.get() & !mask;
        let ttbr1_controls = TTBR1_EL1.get() & !mask;
        dsb(ISHST);
        TTBR0_EL1.set(root.0 | ttbr0_controls);
        TTBR1_EL1.set(root.0 | ttbr1_controls);
        isb(SY);
        unsafe {
            core::arch::asm!("tlbi vmalle1is", options(nostack, preserves_flags));
        }
        dsb(ISH);
        isb(SY);
    }

    fn root_to_phys(root: Self::Root) -> PhysAddr {
        root.physical_address()
    }

    fn create_user_root<A: PageTableFrameAllocator>(
        allocator: &mut A,
    ) -> Result<Self::Root, PageMapError> {
        let root_phys = allocator
            .allocate_page_table_frame()
            .ok_or(PageMapError::NoMemory())?;
        let table_size = root_table_size();

        if root_phys.as_u64() & (table_size - 1) != 0 {
            allocator.free_page_table_frame(root_phys);
            return Err(PageMapError::TranslationFailed());
        }

        let root_virt = match crate::memory::paging::mmio::map_physical_pages(
            root_phys,
            table_size,
            PhysicalMappingCache::Cached,
        ) {
            Ok(root_virt) => root_virt,
            Err(error) => {
                allocator.free_page_table_frame(root_phys);
                return Err(error);
            }
        };

        unsafe {
            root_virt
                .as_mut_ptr::<u8>()
                .write_bytes(0, table_size as usize);
        }

        let entries = table_size as usize / core::mem::size_of::<u64>();
        let recursive_index = usize::from(boot_info().arch_info.recursive_index);
        if recursive_index >= entries {
            let _ = unsafe { crate::memory::paging::mmio::unmap_physical_pages(root_virt, table_size) };
            allocator.free_page_table_frame(root_phys);
            return Err(PageMapError::TranslationFailed());
        }
        let kernel_table = boot_info().arch_info.recursive_base as *const u64;
        let new_table = root_virt.as_mut_ptr::<u64>();
        for index in entries / 2..entries {
            unsafe { new_table.add(index).write(kernel_table.add(index).read()) };
        }
        let recursive = unsafe { kernel_table.add(recursive_index).read() };
        let recursive = (recursive & !root_address_mask()) | root_phys.as_u64();
        unsafe { new_table.add(recursive_index).write(recursive) };

        if let Err(error) =
            unsafe { crate::memory::paging::mmio::unmap_physical_pages(root_virt, table_size) }
        {
            return Err(error);
        }

        Ok(Root(root_phys.as_u64()))
    }

    unsafe fn destroy_user_root<A: PageTableFrameAllocator>(
        root: Self::Root,
        allocator: &mut A,
    ) -> Result<(), PageMapError> {
        if root == Self::current_root() || root == Self::kernel_root() {
            return Err(PageMapError::TranslationFailed());
        }
        allocator.free_page_table_frame(PhysAddr::new(root.0));
        Ok(())
    }
}

fn root_from_ttbr(ttbr: u64) -> Root {
    Root(ttbr & root_address_mask())
}

fn root_table_size() -> u64 {
    1u64 << boot_info().arch_info.granule_shift
}

fn root_address_mask() -> u64 {
    let output_bits = boot_info().arch_info.output_addr_bits;
    let address_mask = if output_bits == 64 {
        u64::MAX
    } else {
        (1u64 << output_bits) - 1
    };
    address_mask & !(root_table_size() - 1)
}
