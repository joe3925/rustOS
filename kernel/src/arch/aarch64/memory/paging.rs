use core::arch::asm;

use aarch64_vmsa::address::{Level, TranslationGranule};
use aarch64_vmsa::attrs::{
    AllocationHints, AttributeCodec, CachePolicy, Cacheability, DataAccess, DeviceMemoryType,
    DirtyBitManagement, DirtyControl, MemoryAttributes, MemoryTransience, SemanticLeafAttrs,
    SemanticTableAttrs, SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    Shareability, SoftwareMetadata, Stage1EffectivePermissions, Stage1MemoryConfig,
    Stage1PermissionConfig, TwoPrivilegeTablePermissionLimits,
};
use aarch64_vmsa::config::format::Vmsa64;
use aarch64_vmsa::config::granule::Granule4KiB;
use aarch64_vmsa::config::regime::NonSecureEl1Stage1;
use aarch64_vmsa::descriptor::{DescriptorFormat, DescriptorLayout, HasLayout};
use aarch64_vmsa::mapper::{
    Mapper, MapperError, MapperInvalidation, SemanticMapperError, decode_semantic_leaf,
};
use aarch64_vmsa::regime::TranslationRegime;
use aarch64_vmsa::table::{
    RecursiveTableAccess, RootTable, RootTableGeometry, TableAccessLocation, TableAddr,
    TableAllocLayout, TableFrameProvider, TableGeometry, TableReclaim,
};
use aarch64_vmsa::translation::{WalkInputAddr, WalkOutcome, WalkOutputAddr, Walker};
use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::{PageMapError, PageMapFailure};

use crate::memory::paging::types::UserVmLayout;
use crate::memory::paging::frame_alloc::{KernelFrameAllocator, KernelPageTableFrameAllocator};
use crate::memory::paging::types::{KernelVirtualLayout, LocalTlbFlush, MappingSize, PagingCapabilities, ResolvedMapping, UnmapFrameDisposition};
use crate::platform::{AddressSpacePlatform, PageTableFrameAllocator, PagingPlatform};
use crate::util::boot_info;

use super::super::platform::Aarch64Platform;
use super::address_space::Root;

type Regime = NonSecureEl1Stage1;
type Granule = Granule4KiB;
type Access = RecursiveTableAccess<Vmsa64, Granule>;
type KernelWalker = Walker<Vmsa64, Regime, Granule, Access>;
type LeafAttrs = SemanticLeafAttrs<Vmsa64, Regime>;
type TableAttrs = SemanticTableAttrs<Vmsa64, Regime>;

const AARCH64_MAPPING_SIZES: [MappingSize; 3] = [
    MappingSize {
        bytes: 1024 * 1024 * 1024,
    },
    MappingSize {
        bytes: 2 * 1024 * 1024,
    },
    MappingSize {
        bytes: Granule::SIZE,
    },
];

#[derive(Clone, Copy)]
struct MapperConfig {
    mair: u64,
}

impl Stage1MemoryConfig for MapperConfig {
    fn mair(&self) -> u64 {
        self.mair
    }
}

impl Stage1PermissionConfig for MapperConfig {}

struct Aarch64TableFrames<'a, A: PageTableFrameAllocator> {
    allocator: &'a mut A,
}

unsafe impl<A: PageTableFrameAllocator> TableFrameProvider<Granule> for Aarch64TableFrames<'_, A> {
    type Error = PageMapError;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<Granule>, Self::Error> {
        if layout.bytes() > Granule::SIZE || layout.align() > Granule::SIZE {
            return Err(PageMapError::TranslationFailed());
        }

        let physical_address = self
            .allocator
            .allocate_page_table_frame()
            .ok_or(PageMapError::NoMemory())?;
        if physical_address.as_u64() & (Granule::SIZE - 1) != 0 {
            self.allocator.free_page_table_frame(physical_address);
            return Err(PageMapError::TranslationFailed());
        }

        TableAddr::new(physical_address.as_u64()).map_err(|_| PageMapError::TranslationFailed())
    }

    fn reclaim_table(&mut self, reclaim: TableReclaim<Granule>) -> Result<(), Self::Error> {
        self.allocator
            .free_page_table_frame(PhysAddr::new(reclaim.addr().raw()));
        Ok(())
    }
}

struct Aarch64Invalidation;

unsafe impl MapperInvalidation<Vmsa64, Granule> for Aarch64Invalidation {
    fn leaf_inserted(&mut self, _: TableAccessLocation<Vmsa64, Granule>, _: usize, _: u64, _: u64) {
    }

    fn leaf_removed(&mut self, _: TableAccessLocation<Vmsa64, Granule>, _: usize, _: u64) {}

    fn table_descriptor_inserted(
        &mut self,
        _: TableAccessLocation<Vmsa64, Granule>,
        _: usize,
        _: u64,
        _: u64,
    ) {
    }

    fn table_descriptor_removed(
        &mut self,
        _: TableAccessLocation<Vmsa64, Granule>,
        _: usize,
        _: u64,
    ) {
    }

    fn before_table_frame_reclaim(&mut self, _: TableAddr<Granule>, _: TableAllocLayout) {}

    fn synchronize(&mut self) {
        synchronize_all();
    }
}

fn root_table(root: Root) -> Result<RootTable<Vmsa64, Regime, Granule>, PageMapError> {
    let info = &boot_info().arch_info;
    let address = TableAddr::new(root.physical_address().as_u64())
        .map_err(|_| PageMapError::TranslationFailed())?;
    let geometry = RootTableGeometry::<Vmsa64, Granule>::new(
        address,
        info.input_addr_bits,
        info.output_addr_bits,
    )
    .map_err(|_| PageMapError::TranslationFailed())?;
    Ok(geometry.with_regime::<Regime>())
}

fn recursive_access(root: RootTable<Vmsa64, Regime, Granule>) -> Result<Access, PageMapError> {
    let info = &boot_info().arch_info;
    unsafe {
        RecursiveTableAccess::new(
            usize::from(info.recursive_index),
            aarch64_vmsa::address::VirtAddr(info.recursive_base),
            root.addr(),
            root.level(),
        )
    }
    .map_err(|_| PageMapError::TranslationFailed())
}

fn current_walker() -> Result<KernelWalker, PageMapError> {
    let root = root_table(<Aarch64Platform as AddressSpacePlatform>::current_root())?;
    let access = recursive_access(root)?;
    Walker::new(root, access).map_err(|_| PageMapError::TranslationFailed())
}

fn input_address(
    root: RootTable<Vmsa64, Regime, Granule>,
    address: u64,
) -> Result<WalkInputAddr, PageMapError> {
    WalkInputAddr::from_canonical(address, root.addr_bits())
        .map_err(|_| PageMapError::TranslationFailed())
}

fn mapping_level(size: MappingSize) -> Result<Level, PageMapError> {
    match size.bytes {
        0x4000_0000 => Ok(Level::L1),
        0x20_0000 => Ok(Level::L2),
        Granule::SIZE => Ok(Level::L3),
        _ => Err(PageMapError::TranslationFailed()),
    }
}

fn page_error(size: MappingSize, failure: PageMapFailure) -> PageMapError {
    match size.bytes {
        0x4000_0000 => PageMapError::Page1GiB(failure),
        0x20_0000 => PageMapError::Page2MiB(failure),
        _ => PageMapError::Page4KiB(failure),
    }
}

fn leaf_attributes(flags: PageFlags, cache: Option<PhysicalMappingCache>) -> LeafAttrs {
    let (memory, shareability) = match cache.unwrap_or(PhysicalMappingCache::Cached) {
        PhysicalMappingCache::Cached => {
            let cacheability = Cacheability::Cacheable {
                policy: CachePolicy::WriteBack,
                transience: MemoryTransience::NonTransient,
                allocation: AllocationHints::ReadWriteAllocate,
            };
            (
                MemoryAttributes::Normal {
                    inner: cacheability,
                    outer: cacheability,
                },
                Shareability::InnerShareable,
            )
        }
        PhysicalMappingCache::WriteCombining => (
            MemoryAttributes::Normal {
                inner: Cacheability::NonCacheable,
                outer: Cacheability::NonCacheable,
            },
            Shareability::InnerShareable,
        ),
        PhysicalMappingCache::Uncached => (
            MemoryAttributes::Device(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck),
            Shareability::OuterShareable,
        ),
    };
    let data = if flags.contains(PageFlags::WRITABLE) {
        DataAccess::ReadWrite
    } else {
        DataAccess::ReadOnly
    };
    let user = flags.contains(PageFlags::USER_ACCESSIBLE);
    let executable = !flags.contains(PageFlags::NO_EXECUTE);

    LeafAttrs {
        memory,
        permissions: Stage1EffectivePermissions {
            privileged_data: data,
            unprivileged_data: if user { data } else { DataAccess::None },
            privileged_execute: executable,
            unprivileged_execute: user && executable,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability,
            access_flag: true,
            global: flags.contains(PageFlags::GLOBAL),
            dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    }
}

fn synchronize_all() {
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}

fn synchronize_address(address: VirtAddr) {
    let operand = (address.as_u64() >> Granule::SHIFT) & ((1u64 << 44) - 1);
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vaae1is, {operand}",
            "dsb ish",
            "isb",
            operand = in(reg) operand,
            options(nostack, preserves_flags)
        );
    }
}

unsafe fn replace_leaf_with_walker(
    virtual_address: VirtAddr,
    physical_address: Option<PhysAddr>,
) -> Result<Option<PhysAddr>, PageMapError> {
    let walker = current_walker()?;
    let root = root_table(<Aarch64Platform as AddressSpacePlatform>::current_root())?;
    let input = input_address(root, virtual_address.as_u64())?;
    let outcome = walker
        .start_at(input)
        .map_err(|_| PageMapError::TranslationFailed())?
        .finish()
        .map_err(|_| PageMapError::TranslationFailed())?;

    let (cursor, index, old) = match outcome {
        WalkOutcome::Invalid(invalid) if physical_address.is_some() => {
            if invalid.level() != Vmsa64::FINAL_LEVEL {
                return Err(PageMapError::NoMemoryMap());
            }
            (invalid.cursor(), invalid.entry_index(), None)
        }
        WalkOutcome::Leaf(leaf) if physical_address.is_none() => {
            if leaf.level() != Vmsa64::FINAL_LEVEL {
                return Err(PageMapError::TranslationFailed());
            }
            (
                leaf.cursor(),
                leaf.entry_index(),
                Some(PhysAddr::new(leaf.output_base().raw())),
            )
        }
        WalkOutcome::Leaf(_) => {
            return Err(PageMapError::Page4KiB(PageMapFailure::PageAlreadyMapped));
        }
        WalkOutcome::Invalid(_) => return Err(PageMapError::TranslationFailed()),
    };

    let path = cursor.path();
    let mut depth = path.len();
    let mut slot_level = Vmsa64::FINAL_LEVEL;
    let mut descriptor_address = boot_info().arch_info.recursive_base;
    while depth > 0 {
        depth -= 1;
        let entry = path
            .entry(cursor.root_level(), depth)
            .ok_or(PageMapError::TranslationFailed())?;
        let stride_count = entry.parent().stride_count().raw();
        let index_mask =
            TableGeometry::<Vmsa64, Granule>::checked_index_mask_for_stride_count(stride_count)
                .ok_or(PageMapError::TranslationFailed())?;
        let shift = TableGeometry::<Vmsa64, Granule>::checked_level_shift(slot_level)
            .ok_or(PageMapError::TranslationFailed())?;
        let field_mask = index_mask
            .checked_shl(u32::from(shift))
            .ok_or(PageMapError::TranslationFailed())?;
        descriptor_address = (descriptor_address & !field_mask) | ((entry.index() as u64) << shift);
        slot_level = Level::new(slot_level.as_i8() - stride_count as i8);
    }

    let raw = if let Some(physical_address) = physical_address {
        let config = MapperConfig {
            mair: boot_info().arch_info.mair_el1,
        };
        let fields = <Vmsa64 as AttributeCodec<Regime, Granule, MapperConfig>>::encode_leaf(
            &config,
            Vmsa64::FINAL_LEVEL,
            leaf_attributes(
                PageFlags::PRESENT
                    | PageFlags::WRITABLE
                    | PageFlags::NO_EXECUTE
                    | PageFlags::GLOBAL,
                None,
            ),
        )
        .map_err(|_| PageMapError::TranslationFailed())?;
        <<Vmsa64 as HasLayout<
            <Regime as TranslationRegime>::Stage,
            Granule,
        >>::Layout as DescriptorLayout<<Regime as TranslationRegime>::Stage, Granule>>::leaf_descriptor(
            aarch64_vmsa::address::PhysAddr(physical_address.as_u64()),
            Vmsa64::FINAL_LEVEL,
            fields,
        )
        .map_err(|_| PageMapError::TranslationFailed())?
    } else {
        Vmsa64::invalid()
    };

    let pointer = (descriptor_address as *mut u64).wrapping_add(index);
    unsafe { Vmsa64::write_descriptor(pointer, raw) };
    synchronize_address(virtual_address);
    Ok(old)
}

unsafe fn zero_frame_with_walker(
    virtual_address: VirtAddr,
    physical_address: PhysAddr,
) -> Result<(), PageMapError> {
    if virtual_address.as_u64() & (Granule::SIZE - 1) != 0
        || physical_address.as_u64() & (Granule::SIZE - 1) != 0
        || physical_address.as_u64() >= 1u64 << boot_info().arch_info.output_addr_bits
    {
        return Err(PageMapError::TranslationFailed());
    }

    unsafe { replace_leaf_with_walker(virtual_address, Some(physical_address))? };
    unsafe {
        core::ptr::write_bytes(
            virtual_address.as_mut_ptr::<u8>(),
            0,
            Granule::SIZE as usize,
        );
    }
    unsafe { replace_leaf_with_walker(virtual_address, None)? };
    Ok(())
}

fn resolve_in_current_root(virtual_address: VirtAddr) -> Option<ResolvedMapping> {
    let walker = current_walker().ok()?;
    let root = root_table(<Aarch64Platform as AddressSpacePlatform>::current_root()).ok()?;
    let input = input_address(root, virtual_address.as_u64()).ok()?;
    let leaf = walker.translate(input).ok()??;
    let mapping_size = TableGeometry::<Vmsa64, Granule>::level_span(leaf.level())?;
    let config = MapperConfig {
        mair: boot_info().arch_info.mair_el1,
    };
    let attrs = decode_semantic_leaf::<Vmsa64, Regime, Granule, MapperConfig>(
        &config,
        leaf.level(),
        *leaf.fields(),
    )
    .ok()?;

    Some(ResolvedMapping {
        mapping_size,
        phys_addr: PhysAddr::new(leaf.output().raw()),
        user_accessible: attrs.permissions.unprivileged_data != DataAccess::None
            || attrs.permissions.unprivileged_execute,
        writable: attrs.permissions.privileged_data == DataAccess::ReadWrite,
    })
}

impl PagingPlatform for Aarch64Platform {
    fn paging_capabilities() -> PagingCapabilities {
        PagingCapabilities {
            base_page_size: Granule::SIZE,
            leaf_mapping_sizes: &AARCH64_MAPPING_SIZES,
            supports_global_mappings: true,
            supports_execute_disable: true,
            supports_cache_attributes: true,
        }
    }

    fn kernel_virtual_layout() -> KernelVirtualLayout {
        KernelVirtualLayout {
            kernel_space_base: VirtAddr::new(super::layout::KERNEL_SPACE_BASE),
            managed_kernel_range_start: VirtAddr::new(super::layout::MANAGED_KERNEL_RANGE_START),
            managed_kernel_range_end: VirtAddr::new(super::layout::MANAGED_KERNEL_RANGE_END),
            heap_range_start: VirtAddr::new(super::layout::HEAP_RANGE_START),
            heap_range_end: VirtAddr::new(super::layout::HEAP_RANGE_END),
            mmio_base: VirtAddr::new(super::layout::MMIO_BASE),
            low_physical_reserve_bytes: super::layout::LOW_PHYSICAL_RESERVE_BYTES,
        }
    }

    fn user_virtual_layout() -> UserVmLayout {
        UserVmLayout {
            start: Granule::SIZE,
            end: 0x0000_8000_0000_0000,
            base_page_size: Granule::SIZE,
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
        let size = MappingSize {
            bytes: Granule::SIZE,
        };
        let physical_address =
            KernelFrameAllocator::allocate_mapping_frame(size).ok_or(PageMapError::NoMemory())?;
        let mut allocator = KernelPageTableFrameAllocator;
        if let Err(error) = unsafe {
            Self::map_leaf(
                &mut allocator,
                virtual_address,
                physical_address,
                size,
                PageFlags::PRESENT
                    | PageFlags::WRITABLE
                    | PageFlags::NO_EXECUTE
                    | PageFlags::GLOBAL,
                None,
                LocalTlbFlush::Flush,
            )
        } {
            unsafe { KernelFrameAllocator::release_reserved_mapping_frame(physical_address, size) };
            return Err(error);
        }

        if let Err(error) = unsafe { replace_leaf_with_walker(virtual_address, None) } {
            return Err(error);
        }
        unsafe { KernelFrameAllocator::release_reserved_mapping_frame(physical_address, size) };
        Ok(())
    }

    unsafe fn emergency_zero_physical_frame(
        virtual_address: VirtAddr,
        physical_address: PhysAddr,
    ) -> Result<(), PageMapError> {
        unsafe { zero_frame_with_walker(virtual_address, physical_address) }
    }

    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: VirtAddr,
        phys: PhysAddr,
        size: MappingSize,
        flags: PageFlags,
        cache: Option<PhysicalMappingCache>,
        _flush: LocalTlbFlush,
    ) -> Result<(), PageMapError> {
        let root = root_table(<Self as AddressSpacePlatform>::current_root())?;
        let input = input_address(root, virt.as_u64())?;
        let level = mapping_level(size)?;
        let access = recursive_access(root)?;
        let frames = Aarch64TableFrames { allocator };
        let mut mapper = Mapper::new_live(root, access, frames, Aarch64Invalidation)
            .map_err(|_| PageMapError::TranslationFailed())?;
        let config = MapperConfig {
            mair: boot_info().arch_info.mair_el1,
        };
        let table_attrs = TableAttrs {
            permission_limits: TwoPrivilegeTablePermissionLimits {
                privileged_data_limit: DataAccess::ReadWrite,
                unprivileged_data_limit: DataAccess::ReadWrite,
                privileged_execute_limit: true,
                unprivileged_execute_limit: true,
            },
            pas: (),
            controls: SemanticVmsa64Stage1TableControls {
                access_flag: false,
                software: SoftwareMetadata::new(0),
            },
        };

        mapper
            .map_semantic_leaf(
                &config,
                input,
                WalkOutputAddr::new(phys.as_u64()),
                level,
                leaf_attributes(flags, cache),
                table_attrs,
            )
            .map(|_| ())
            .map_err(|error| match error {
                SemanticMapperError::Mapper(MapperError::Frame(_)) => {
                    page_error(size, PageMapFailure::FrameAllocationFailed)
                }
                SemanticMapperError::Mapper(MapperError::AlreadyMapped {
                    level: existing, ..
                }) if existing.is_before(level) => {
                    page_error(size, PageMapFailure::ParentEntryHugePage)
                }
                SemanticMapperError::Mapper(MapperError::AlreadyMapped { .. }) => {
                    page_error(size, PageMapFailure::PageAlreadyMapped)
                }
                _ => PageMapError::TranslationFailed(),
            })
    }

    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        allocator: &mut A,
        virt: VirtAddr,
        size: MappingSize,
        disposition: UnmapFrameDisposition,
        _flush: LocalTlbFlush,
    ) -> Result<Option<PhysAddr>, PageMapError> {
        let root = root_table(<Self as AddressSpacePlatform>::current_root())?;
        let input = input_address(root, virt.as_u64())?;
        let level = mapping_level(size)?;
        let access = recursive_access(root)?;
        let frames = Aarch64TableFrames { allocator };
        let mut mapper = Mapper::new_live(root, access, frames, Aarch64Invalidation)
            .map_err(|_| PageMapError::TranslationFailed())?;
        let mapping = mapper
            .translate(input)
            .map_err(|_| PageMapError::TranslationFailed())?
            .ok_or(PageMapError::TranslationFailed())?;
        if mapping.level() != level || mapping.covered_size() != size.bytes {
            return Err(PageMapError::TranslationFailed());
        }
        let physical_address = PhysAddr::new(mapping.output_base().raw());
        unsafe { mapper.unmap_reclaim(input) }.map_err(|_| PageMapError::TranslationFailed())?;

        match disposition {
            UnmapFrameDisposition::FreeMappedFrame => unsafe {
                KernelFrameAllocator::free_mapping_frame(physical_address, size)
            },
            UnmapFrameDisposition::ReleaseReservedFrame => unsafe {
                KernelFrameAllocator::release_reserved_mapping_frame(physical_address, size)
            },
            UnmapFrameDisposition::KeepFrame => {}
        }
        Ok(Some(physical_address))
    }

    fn resolve_mapping(virt: VirtAddr) -> Option<ResolvedMapping> {
        resolve_in_current_root(virt)
    }

    fn resolve_mapping_in_root(root: Self::Root, virt: VirtAddr) -> Option<ResolvedMapping> {
        let previous = <Self as AddressSpacePlatform>::current_root();
        if previous != root {
            unsafe { <Self as AddressSpacePlatform>::switch_root(root) };
        }
        let resolved = resolve_in_current_root(virt);
        if previous != root {
            unsafe { <Self as AddressSpacePlatform>::switch_root(previous) };
        }
        resolved
    }

    fn local_flush_tlb_all() {
        unsafe {
            asm!(
                "dsb ishst",
                "tlbi vmalle1",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags)
            );
        }
    }

    fn local_flush_tlb_range(start: VirtAddr, size: u64, stride: u64) {
        let stride = if stride == 0 { Granule::SIZE } else { stride };
        if !stride.is_power_of_two() {
            Self::local_flush_tlb_all();
            return;
        }
        let mut address = start.as_u64() & !(stride - 1);
        let Some(end) = start
            .as_u64()
            .checked_add(size)
            .and_then(|value| value.checked_add(stride - 1))
            .map(|value| value & !(stride - 1))
        else {
            Self::local_flush_tlb_all();
            return;
        };

        unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) };
        while address < end {
            let operand = (address >> Granule::SHIFT) & ((1u64 << 44) - 1);
            unsafe {
                asm!(
                    "tlbi vaae1, {operand}",
                    operand = in(reg) operand,
                    options(nostack, preserves_flags)
                );
            }
            let Some(next) = address.checked_add(stride) else {
                Self::local_flush_tlb_all();
                return;
            };
            address = next;
        }
        unsafe {
            asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
    }

    fn broadcast_tlb_shootdown() -> bool {
        synchronize_all();
        false
    }
}
