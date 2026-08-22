pub mod address_space;
pub mod flags;
pub mod layout;
pub mod mapper;
pub mod tables;
pub mod tlb;

use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageSize, PageTableFlags, Size1GiB, Size2MiB, Size4KiB};
use x86_64::{PhysAddr as X86PhysAddr, VirtAddr as X86VirtAddr};

use crate::memory::paging::{
    KernelFrameAllocator, KernelPageTableFrameAllocator, KernelVirtualLayout, LocalTlbFlush,
    MappingSize, PagingCapabilities, ResolvedMapping, UnmapFrameDisposition,
};
use crate::platform::{AddressSpacePlatform, PageTableFrameAllocator, PagingPlatform};
use crate::util::boot_info;

use self::flags::page_flags_to_x86;
use self::mapper::{X86PageTableFrameAllocator, map_existing_frame, unmap_leaf_inner};
use self::tables::init_mapper;
use super::super::drivers::interrupt_index::{APIC, IpiDest, IpiKind, LocalApic};
use super::super::platform::X86Platform;

const X86_MAPPING_SIZES_WITH_1G: [MappingSize; 3] = [
    MappingSize {
        bytes: Size1GiB::SIZE,
    },
    MappingSize {
        bytes: Size2MiB::SIZE,
    },
    MappingSize {
        bytes: Size4KiB::SIZE,
    },
];

const X86_MAPPING_SIZES_WITHOUT_1G: [MappingSize; 2] = [
    MappingSize {
        bytes: Size2MiB::SIZE,
    },
    MappingSize {
        bytes: Size4KiB::SIZE,
    },
];

impl PagingPlatform for X86Platform {
    fn paging_capabilities() -> PagingCapabilities {
        let supports_1g = super::super::cpu::get_cpu_info()
            .get_extended_processor_and_feature_identifiers()
            .is_some_and(|features| features.has_1gib_pages());

        PagingCapabilities {
            base_page_size: Size4KiB::SIZE,
            leaf_mapping_sizes: if supports_1g {
                &X86_MAPPING_SIZES_WITH_1G
            } else {
                &X86_MAPPING_SIZES_WITHOUT_1G
            },
            supports_global_mappings: true,
            supports_execute_disable: true,
            supports_cache_attributes: true,
        }
    }

    fn kernel_virtual_layout() -> KernelVirtualLayout {
        KernelVirtualLayout {
            kernel_space_base: VirtAddr::new(layout::KERNEL_SPACE_BASE),
            managed_kernel_range_start: VirtAddr::new(layout::MANAGED_KERNEL_RANGE_START),
            managed_kernel_range_end: VirtAddr::new(layout::MANAGED_KERNEL_RANGE_END),
            heap_range_start: VirtAddr::new(layout::HEAP_RANGE_START),
            heap_range_end: VirtAddr::new(layout::HEAP_RANGE_END),
            mmio_base: VirtAddr::new(layout::MMIO_BASE),
            low_physical_reserve_bytes: layout::LOW_PHYSICAL_RESERVE_BYTES,
        }
    }

    fn user_virtual_layout() -> crate::memory::paging::types::UserVmLayout {
        const USER_VA_START: u64 = 0x0000_0000_0000_0000;
        const USER_VA_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

        crate::memory::paging::types::UserVmLayout {
            start: USER_VA_START + Size4KiB::SIZE,
            end: USER_VA_END_EXCLUSIVE,
            base_page_size: Size4KiB::SIZE,
            stack_alignment: 16,
        }
    }

    unsafe fn prepare_emergency_zero_mapping(
        virtual_address: VirtAddr,
    ) -> Result<(), PageMapError> {
        let mapping_size = MappingSize {
            bytes: Size4KiB::SIZE,
        };
        let physical_address = KernelFrameAllocator::allocate_mapping_frame(mapping_size)
            .ok_or(PageMapError::NoMemory())?;
        let mut allocator = KernelPageTableFrameAllocator;
        let map_result = unsafe {
            Self::map_leaf(
                &mut allocator,
                virtual_address,
                physical_address,
                mapping_size,
                PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE,
                None,
                LocalTlbFlush::Flush,
            )
        };

        if let Err(error) = map_result {
            unsafe {
                KernelFrameAllocator::release_reserved_mapping_frame(physical_address, mapping_size)
            };
            return Err(error);
        }

        let unmap_result = unsafe {
            Self::unmap_leaf(
                &mut allocator,
                virtual_address,
                mapping_size,
                UnmapFrameDisposition::KeepFrame,
                LocalTlbFlush::Flush,
            )
        };
        unsafe {
            KernelFrameAllocator::release_reserved_mapping_frame(physical_address, mapping_size)
        };
        unmap_result.map(|_| ())
    }

    unsafe fn emergency_zero_physical_frame(
        virtual_address: VirtAddr,
        physical_address: PhysAddr,
    ) -> Result<(), PageMapError> {
        if virtual_address.as_u64() % Size4KiB::SIZE != 0
            || physical_address.as_u64() % Size4KiB::SIZE != 0
        {
            return Err(PageMapError::TranslationFailed());
        }

        let recursive_index = boot_info()
            .arch_info
            .recursive_index
            .into_option()
            .ok_or(PageMapError::NoMemoryMap())?;
        let rec = u64::from(recursive_index);
        let raw = virtual_address.as_u64();
        let p4 = (raw >> 39) & 0x1ff;
        let p3 = (raw >> 30) & 0x1ff;
        let p2 = (raw >> 21) & 0x1ff;
        let p1 = (raw >> 12) & 0x1ff;
        let table_address = self::tables::recursive_table_addr(rec, p4, p3, p2);
        let entry = unsafe { &mut *(table_address as *mut PageTableEntry).add(p1 as usize) };

        if !entry.is_unused() {
            return Err(PageMapError::Page4KiB(
                kernel_types::status::PageMapFailure::PageAlreadyMapped,
            ));
        }

        entry.set_addr(
            X86PhysAddr::new(physical_address.as_u64()),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
        );
        x86_64::instructions::tlb::flush(X86VirtAddr::new(virtual_address.as_u64()));
        unsafe {
            core::ptr::write_bytes(
                virtual_address.as_mut_ptr::<u8>(),
                0,
                Size4KiB::SIZE as usize,
            );
        }
        entry.set_unused();
        x86_64::instructions::tlb::flush(X86VirtAddr::new(virtual_address.as_u64()));
        Ok(())
    }

    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: VirtAddr,
        phys: PhysAddr,
        size: MappingSize,
        flags: PageFlags,
        cache: Option<PhysicalMappingCache>,
        flush: LocalTlbFlush,
    ) -> Result<(), PageMapError> {
        let recursive_index = boot_info()
            .arch_info
            .recursive_index
            .into_option()
            .ok_or(PageMapError::NoMemoryMap())?;
        let mut mapper = unsafe { init_mapper(recursive_index) };
        let mut table_allocator = X86PageTableFrameAllocator { inner: allocator };
        let flags = page_flags_to_x86(flags, cache) | PageTableFlags::PRESENT;
        let virt = X86VirtAddr::new(virt.as_u64());
        let phys = X86PhysAddr::new(phys.as_u64());

        match size.bytes {
            Size4KiB::SIZE => unsafe {
                map_existing_frame::<Size4KiB, A>(
                    &mut mapper,
                    &mut table_allocator,
                    virt,
                    phys,
                    flags,
                    flush,
                )
                .map_err(PageMapError::from)
            },
            Size2MiB::SIZE => unsafe {
                map_existing_frame::<Size2MiB, A>(
                    &mut mapper,
                    &mut table_allocator,
                    virt,
                    phys,
                    flags,
                    flush,
                )
                .map_err(PageMapError::from)
            },
            Size1GiB::SIZE => unsafe {
                map_existing_frame::<Size1GiB, A>(
                    &mut mapper,
                    &mut table_allocator,
                    virt,
                    phys,
                    flags,
                    flush,
                )
                .map_err(PageMapError::from)
            },
            _ => Err(PageMapError::TranslationFailed()),
        }
    }

    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        _allocator: &mut A,
        virt: VirtAddr,
        size: MappingSize,
        disposition: UnmapFrameDisposition,
        flush: LocalTlbFlush,
    ) -> Result<Option<PhysAddr>, PageMapError> {
        let recursive_index = boot_info()
            .arch_info
            .recursive_index
            .into_option()
            .ok_or(PageMapError::NoMemoryMap())?;
        let mut mapper = unsafe { init_mapper(recursive_index) };
        let virt = X86VirtAddr::new(virt.as_u64());

        match size.bytes {
            Size4KiB::SIZE => unmap_leaf_inner::<Size4KiB>(&mut mapper, virt, disposition, flush),
            Size2MiB::SIZE => unmap_leaf_inner::<Size2MiB>(&mut mapper, virt, disposition, flush),
            Size1GiB::SIZE => unmap_leaf_inner::<Size1GiB>(&mut mapper, virt, disposition, flush),
            _ => Err(PageMapError::TranslationFailed()),
        }
    }

    fn resolve_mapping(virt: VirtAddr) -> Option<ResolvedMapping> {
        let recursive_index = boot_info().arch_info.recursive_index.into_option()?;
        let (mapping_size, phys_addr, user_accessible, writable) =
            mapper::translate_addr(recursive_index, virt)?;
        Some(ResolvedMapping {
            mapping_size,
            phys_addr,
            user_accessible,
            writable,
        })
    }

    fn resolve_mapping_in_root(root: Self::Root, virt: VirtAddr) -> Option<ResolvedMapping> {
        let previous = <Self as AddressSpacePlatform>::current_root();
        if previous != root {
            unsafe { <Self as AddressSpacePlatform>::switch_root(root) };
        }
        let resolved = Self::resolve_mapping(virt);
        if previous != root {
            unsafe { <Self as AddressSpacePlatform>::switch_root(previous) };
        }
        resolved
    }

    fn local_flush_tlb_all() {
        x86_64::instructions::tlb::flush_all();
    }

    fn local_flush_tlb_range(start: VirtAddr, size: u64, stride: u64) {
        let stride = if stride == 0 { return } else { stride };
        let mut addr = start.as_u64() & !(stride - 1);
        let Some(end) = start
            .as_u64()
            .checked_add(size)
            .and_then(|value| value.checked_add(stride - 1))
            .map(|value| value & !(stride - 1))
        else {
            x86_64::instructions::tlb::flush_all();
            return;
        };

        while addr < end {
            let Ok(virt) = X86VirtAddr::try_new(addr) else {
                x86_64::instructions::tlb::flush_all();
                return;
            };
            x86_64::instructions::tlb::flush(virt);
            let Some(next) = addr.checked_add(stride) else {
                x86_64::instructions::tlb::flush_all();
                return;
            };
            addr = next;
        }
    }

    fn broadcast_tlb_shootdown() -> bool {
        unsafe {
            if let Some(apic) = APIC.lock().as_ref() {
                apic.lapic.send_ipi(
                    IpiDest::AllExcludingSelf,
                    IpiKind::Fixed {
                        vector: super::super::idt::TLB_FLUSH_VECTOR,
                    },
                );
                return true;
            }
        }
        false
    }
}
