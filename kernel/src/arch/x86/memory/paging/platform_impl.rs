use alloc::vec::Vec;

use kernel_types::arch::{AddressSpaceRoot, PageFlags, PhysAddr, VirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::{PageMapError, PageMapFailure};
use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64_paging::PageTableFlags;
use x86_64_paging::paging::mapper::{Mapper, MapperError};
use x86_64_paging::paging::translation::walk::WalkOutputAddr;

use crate::memory::paging::frame_alloc::{KernelFrameAllocator, KernelPageTableFrameAllocator};
use crate::memory::paging::types::{
    KernelVirtualLayout, MappingSize, PagingCapabilities, ResolvedMapping,
};
use crate::platform::{AddressSpacePlatform, PageTableFrameAllocator, PagingPlatform};
use crate::util::boot_info;

use super::super::super::interrupts::apic::controller::APIC;
use super::super::super::interrupts::apic::local::{IpiDest, IpiKind, LocalApic};
use super::super::super::platform::X86Platform;
use super::flags::page_flags_to_x86;
use super::layout;
use super::mapper::{
    NoTableFrames,  X86TableAccess, X86TableFrames, input_address,
    mapping_level, page_error, root_table,
};
use super::tables;

const X86_MAPPING_SIZES_WITH_1G: [MappingSize; 3] = [
    MappingSize { bytes: 0x4000_0000 },
    MappingSize { bytes: 0x20_0000 },
    MappingSize { bytes: 0x1000 },
];

const X86_MAPPING_SIZES_WITHOUT_1G: [MappingSize; 2] = [
    MappingSize { bytes: 0x20_0000 },
    MappingSize { bytes: 0x1000 },
];

impl PagingPlatform for X86Platform {
    fn paging_capabilities() -> PagingCapabilities {
        let supports_1g = super::super::super::cpu::get_cpu_info()
            .get_extended_processor_and_feature_identifiers()
            .is_some_and(|features| features.has_1gib_pages());

        PagingCapabilities {
            base_page_size: 0x1000,
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
        crate::memory::paging::types::UserVmLayout {
            start: 0x1000,
            end: 0x0000_8000_0000_0000,
            base_page_size: 0x1000,
            stack_alignment: 16,
        }
    }

    fn bootstrap_emergency_zero_address() -> Option<VirtAddr> {
        let address = boot_info().arch_info.scratch_page;
        (address != 0).then_some(VirtAddr::new(address))
    }

    unsafe fn prepare_emergency_zero_mapping(
        virtual_address: VirtAddr,
    ) -> Result<(), PageMapError> {
        let size = MappingSize { bytes: 0x1000 };
        let physical_address =
            KernelFrameAllocator::allocate_mapping_frame(size).ok_or(PageMapError::NoMemory())?;
        let mut allocator = KernelPageTableFrameAllocator;
        let result = unsafe {
            Self::map_leaf(
                Self::kernel_root(),
                &mut allocator,
                virtual_address,
                physical_address,
                size,
                PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE,
                None,
            )
        };
        if result.is_ok() {
            let recursive_index = boot_info()
                .arch_info
                .recursive_index
                .into_option()
                .ok_or(PageMapError::NoMemoryMap())?;
            let raw = virtual_address.as_u64();
            let rec = u64::from(recursive_index);
            let table = tables::recursive_table_addr(
                rec,
                (raw >> 39) & 0x1ff,
                (raw >> 30) & 0x1ff,
                (raw >> 21) & 0x1ff,
            );
            unsafe {
                (table as *mut u64)
                    .add(((raw >> 12) & 0x1ff) as usize)
                    .write_volatile(0)
            };
        }
        unsafe { KernelFrameAllocator::release_reserved_mapping_frame(physical_address, size) };
        result
    }

    unsafe fn emergency_zero_physical_frame(
        virtual_address: VirtAddr,
        physical_address: PhysAddr,
    ) -> Result<(), PageMapError> {
        if virtual_address.as_u64() % 0x1000 != 0 || physical_address.as_u64() % 0x1000 != 0 {
            return Err(PageMapError::TranslationFailed());
        }

        let recursive_index = boot_info()
            .arch_info
            .recursive_index
            .into_option()
            .ok_or(PageMapError::NoMemoryMap())?;
        let raw = virtual_address.as_u64();
        let rec = u64::from(recursive_index);
        let table = tables::recursive_table_addr(
            rec,
            (raw >> 39) & 0x1ff,
            (raw >> 30) & 0x1ff,
            (raw >> 21) & 0x1ff,
        );
        let entry = unsafe { (table as *mut u64).add(((raw >> 12) & 0x1ff) as usize) };
        if unsafe { entry.read_volatile() } != 0 {
            return Err(PageMapError::Page4KiB(PageMapFailure::PageAlreadyMapped));
        }

        unsafe {
            entry.write_volatile(
                physical_address.as_u64()
                    | (PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::NO_EXECUTE)
                        .bits(),
            )
        };
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(virtual_address.as_u64()));
        unsafe { core::ptr::write_bytes(virtual_address.as_mut_ptr::<u8>(), 0, 0x1000) };
        unsafe { entry.write_volatile(0) };
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(virtual_address.as_u64()));
        Ok(())
    }

    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        root: AddressSpaceRoot,
        allocator: &mut A,
        virt: VirtAddr,
        phys: PhysAddr,
        size: MappingSize,
        flags: PageFlags,
        cache: Option<PhysicalMappingCache>,
    ) -> Result<(), PageMapError> {
        crate::platform::with_interrupts_disabled(|| {
            let mut reclaims = Vec::new();
            let input = input_address(virt)?;
            let level = mapping_level(size)?;
            let leaf_flags = page_flags_to_x86(flags, cache) | PageTableFlags::PRESENT;
            let table_flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | (leaf_flags & PageTableFlags::USER_ACCESSIBLE);
            let result = {
                let access = X86TableAccess::new(root)?;
                let frames = X86TableFrames {
                    allocator,
                    reclaims: &mut reclaims,
                };
                let mut page_mapper = Mapper::new_offline(root_table(root)?, access, frames)
                    .map_err(|_| PageMapError::TranslationFailed())?;
                page_mapper
                    .map_leaf(
                        input,
                        WalkOutputAddr::new(phys.as_u64()),
                        level,
                        leaf_flags,
                        table_flags,
                    )
                    .map(|_| ())
                    .map_err(|error| match error {
                        MapperError::Frame(PageMapError::NoMemory()) => {
                            page_error(size, PageMapFailure::FrameAllocationFailed)
                        }
                        MapperError::AlreadyMapped { level: actual, .. }
                            if actual.is_before(level) =>
                        {
                            page_error(size, PageMapFailure::ParentEntryHugePage)
                        }
                        MapperError::AlreadyMapped { .. } => {
                            page_error(size, PageMapFailure::PageAlreadyMapped)
                        }
                        MapperError::Access(error) | MapperError::Frame(error) => error,
                        _ => PageMapError::TranslationFailed(),
                    })
            };
            for physical_address in reclaims {
                allocator.free_page_table_frame(physical_address);
            }
            result
        })
    }

    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        root: AddressSpaceRoot,
        allocator: &mut A,
        virt: VirtAddr,
        size: MappingSize,
        table_reclaims: &mut Vec<PhysAddr>,
    ) -> Result<Option<PhysAddr>, PageMapError> {
        crate::platform::with_interrupts_disabled(|| {
            let access = X86TableAccess::new(root)?;
            let frames = X86TableFrames {
                allocator,
                reclaims: table_reclaims,
            };
            let mut page_mapper = Mapper::new_offline(root_table(root)?, access, frames)
                .map_err(|_| PageMapError::TranslationFailed())?;
            let input = input_address(virt)?;
            let Some(mapping) = page_mapper
                .translate(input)
                .map_err(|_| PageMapError::TranslationFailed())?
            else {
                return Err(PageMapError::TranslationFailed());
            };
            if mapping.covered_input_base() != input.raw() || mapping.covered_size() != size.bytes {
                return Err(PageMapError::TranslationFailed());
            }
            let physical = PhysAddr::new(mapping.output_base().raw());
            unsafe { page_mapper.unmap_reclaim(input) }
                .map_err(|_| PageMapError::TranslationFailed())?;
            Ok(Some(physical))
        })
    }

    fn resolve_mapping(root: AddressSpaceRoot, virt: VirtAddr) -> Option<ResolvedMapping> {
        crate::platform::with_interrupts_disabled(|| {
            let access = X86TableAccess::new(root).ok()?;
            let page_mapper =
                Mapper::new_offline(root_table(root).ok()?, access, NoTableFrames).ok()?;
            let mapping = page_mapper.translate(input_address(virt).ok()?).ok()??;
            let flags = PageTableFlags::from_bits_retain(mapping.raw());
            Some(ResolvedMapping {
                mapping_size: mapping.covered_size(),
                phys_addr: PhysAddr::new(mapping.output().raw()),
                user_accessible: flags.contains(PageTableFlags::USER_ACCESSIBLE),
                writable: flags.contains(PageTableFlags::WRITABLE),
            })
        })
    }

    fn local_flush_tlb_all(include_global: bool) {
        let cr4 = Cr4::read();
        if include_global && cr4.contains(Cr4Flags::PAGE_GLOBAL) {
            unsafe { Cr4::write(cr4 - Cr4Flags::PAGE_GLOBAL) };
            unsafe { Cr4::write(cr4) };
        } else {
            x86_64::instructions::tlb::flush_all();
        }
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
            Self::local_flush_tlb_all(false);
            return;
        };

        while addr < end {
            let Ok(virt) = x86_64::VirtAddr::try_new(addr) else {
                Self::local_flush_tlb_all(false);
                return;
            };
            x86_64::instructions::tlb::flush(virt);
            let Some(next) = addr.checked_add(stride) else {
                Self::local_flush_tlb_all(false);
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
                        vector: super::super::super::idt::table::TLB_FLUSH_VECTOR,
                    },
                );
                return true;
            }
        }
        false
    }
}
