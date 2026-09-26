use core::arch::asm;
use core::convert::Infallible;
use core::ptr::NonNull;

use alloc::vec::Vec;

use aarch64_vmsa::address::{Level, TranslationGranule};
use aarch64_vmsa::attrs::{
    AllocationHints, CachePolicy, Cacheability, DataRights, DeviceMemoryType,
    DirtyBitManagement, DirtyControl, MemoryAttributes, MemoryTransience, SemanticLeafAttrs,
    SemanticTableAttrs, SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    Shareability, SoftwareMetadata, Stage1MemoryConfig, Stage1PermissionConfig, Stage1Permissions,
    TwoPrivilegeTableRestrictions,
};
use aarch64_vmsa::config::format::{NativeEndian, Vmsa64};
use aarch64_vmsa::config::granule::Granule4KiB;
use aarch64_vmsa::config::regime::NonSecureEl1Stage1;
use aarch64_vmsa::mapper::{Mapper, MapperError, SemanticMapperError, decode_semantic_leaf};
use aarch64_vmsa::table::{
    RootTable, RootTableGeometry, TableAccess, TableAccessLocation, TableAccessMut, TableAddr,
    TableAllocLayout, TableFrameProvider, TableReclaim, TranslationTable,
    TranslationTableMut,
};
use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};
use kernel_types::arch::{AddressSpaceRoot, PageFlags, PhysAddr, VirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::{PageMapError, PageMapFailure};

use crate::memory::paging::types::UserVmLayout;
use crate::memory::paging::types::{
    KernelVirtualLayout, MappingSize, PagingCapabilities, ResolvedMapping,
};
use crate::platform::{PageTableFrameAllocator, PagingPlatform};
use crate::util::boot_info;

use super::super::platform::Aarch64Platform;

type Regime = NonSecureEl1Stage1;
type Granule = Granule4KiB;
type Format = Vmsa64<NativeEndian>;
type LeafAttrs = SemanticLeafAttrs<Format, Regime>;
type TableAttrs = SemanticTableAttrs<Format, Regime>;

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
    reclaims: &'a mut Vec<PhysAddr>,
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

        match TableAddr::new(physical_address.as_u64()) {
            Ok(address) => Ok(address),
            Err(_) => {
                self.allocator.free_page_table_frame(physical_address);
                Err(PageMapError::TranslationFailed())
            }
        }
    }

    fn reclaim_table(&mut self, reclaim: TableReclaim<Granule>) -> Result<(), Self::Error> {
        self.reclaims.push(PhysAddr::new(reclaim.addr().raw()));
        Ok(())
    }
}

fn root_table(root: AddressSpaceRoot) -> Result<RootTable<Format, Regime, Granule>, PageMapError> {
    let info = &boot_info().arch_info;
    let address = TableAddr::new(root.physical_address().as_u64())
        .map_err(|_| PageMapError::TranslationFailed())?;
    let geometry = RootTableGeometry::<Format, Granule>::new(
        address,
        info.input_addr_bits,
        info.output_addr_bits,
    )
    .map_err(|_| PageMapError::TranslationFailed())?;
    Ok(geometry.with_regime::<Regime>())
}

fn input_address(
    root: RootTable<Format, Regime, Granule>,
    address: u64,
) -> Result<WalkInputAddr, PageMapError> {
    aarch64_vmsa::translation::from_canonical(address, root.addr_bits())
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


struct OffsetTableAccess;

impl OffsetTableAccess {
    fn new() -> Result<Self, PageMapError> {
        Ok(Self)
    }

    fn map_table(
        &self,
        location: TableAccessLocation<'_, Format, Granule>,
    ) -> Result<NonNull<u64>, PageMapError> {
        let info = &boot_info().arch_info;
        let bytes = location
            .shape()
            .alloc_layout()
            .map_err(|_| PageMapError::TranslationFailed())?
            .bytes();
        let end = location
            .addr()
            .raw()
            .checked_add(bytes)
            .ok_or(PageMapError::TranslationFailed())?;
        if end > info.physical_memory_len {
            return Err(PageMapError::NoMemoryMap());
        }
        let address = info
            .physical_memory_offset
            .checked_add(location.addr().raw())
            .ok_or(PageMapError::TranslationFailed())?;
        NonNull::new(address as *mut u64).ok_or(PageMapError::NoMemoryMap())
    }
}

unsafe impl TableAccess<Format, Granule> for OffsetTableAccess {
    type Error = PageMapError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<'a, Format, Granule>,
    ) -> Result<TranslationTable<'a, Format, Granule>, Self::Error> {
        let base = self.map_table(location)?;
        Ok(unsafe { TranslationTable::from_raw_parts(base, location.shape()) })
    }
}

unsafe impl TableAccessMut<Format, Granule> for OffsetTableAccess {
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<'a, Format, Granule>,
    ) -> Result<TranslationTableMut<'a, Format, Granule>, Self::Error> {
        let base = self.map_table(location)?;
        Ok(unsafe { TranslationTableMut::from_raw_parts(base, location.shape()) })
    }
}

struct NoTableFrames;

unsafe impl TableFrameProvider<Granule> for NoTableFrames {
    type Error = Infallible;

    fn allocate_zeroed_table(
        &mut self,
        _: TableAllocLayout,
    ) -> Result<TableAddr<Granule>, Self::Error> {
        unreachable!()
    }

    fn reclaim_table(&mut self, _: TableReclaim<Granule>) -> Result<(), Self::Error> {
        unreachable!()
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
    let writable = flags.contains(PageFlags::WRITABLE);
    let data = if writable {
        DataRights::ReadWrite
    } else {
        DataRights::Read
    };
    let user = flags.contains(PageFlags::USER_ACCESSIBLE);
    let executable = !flags.contains(PageFlags::NO_EXECUTE);
    let privileged_executable = executable && !(user && writable);

    LeafAttrs {
        memory,
        permissions: Stage1Permissions::new(
            data,
            if user { data } else { DataRights::None },
            privileged_executable,
            user && executable,
            false,
            false,
        ),
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

fn resolve_in_root(
    address_space_root: AddressSpaceRoot,
    virtual_address: VirtAddr,
) -> Option<ResolvedMapping> {
    let root = root_table(address_space_root).ok()?;
    let input = input_address(root, virtual_address.as_u64()).ok()?;
    let access = OffsetTableAccess::new().ok()?;
    let mapper = Mapper::new_offline(root, access, NoTableFrames).ok()?;
    let mapping = mapper.translate(input).ok()??;
    let config = MapperConfig {
        mair: boot_info().arch_info.mair_el1,
    };
    let attrs = decode_semantic_leaf::<Format, Regime, Granule, MapperConfig>(
        &config,
        mapping.level(),
        *mapping.fields(),
    )
    .ok()?;

    Some(ResolvedMapping {
        mapping_size: mapping.covered_size(),
        phys_addr: PhysAddr::new(mapping.output().raw()),
        user_accessible: attrs.permissions.data.unprivileged != DataRights::None
            || attrs.permissions.execute.unprivileged(),
        writable: attrs.permissions.data.privileged == DataRights::ReadWrite,
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

    unsafe fn map_leaf<A: PageTableFrameAllocator>(
        address_space_root: AddressSpaceRoot,
        allocator: &mut A,
        virt: VirtAddr,
        phys: PhysAddr,
        size: MappingSize,
        flags: PageFlags,
        cache: Option<PhysicalMappingCache>,
    ) -> Result<(), PageMapError> {
        crate::platform::with_interrupts_disabled(|| {
            let root = root_table(address_space_root)?;
            let input = input_address(root, virt.as_u64())?;
            let level = mapping_level(size)?;
            let mut reclaims = Vec::new();
            let config = MapperConfig {
                mair: boot_info().arch_info.mair_el1,
            };
            let table_attrs = TableAttrs {
                restrictions: TwoPrivilegeTableRestrictions {
                    privileged_data_limit: DataRights::ReadWrite,
                    unprivileged_data_limit: DataRights::ReadWrite,
                    privileged_execute_limit: true,
                    unprivileged_execute_limit: true,
                },
                pas: (),
                controls: SemanticVmsa64Stage1TableControls {
                    access_flag: true,
                    software: SoftwareMetadata::new(0),
                },
            };

            let result = {
                let access = OffsetTableAccess::new()?;
                let frames = Aarch64TableFrames {
                    allocator,
                    reclaims: &mut reclaims,
                };
                let mut mapper = Mapper::new_offline(root, access, frames)
                    .map_err(|_| PageMapError::TranslationFailed())?;
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
                        SemanticMapperError::Mapper(MapperError::Frame(
                            PageMapError::NoMemory(),
                        )) => page_error(size, PageMapFailure::FrameAllocationFailed),
                        SemanticMapperError::Mapper(MapperError::AlreadyMapped {
                            level: existing,
                            ..
                        }) if existing.is_before(level) => {
                            page_error(size, PageMapFailure::ParentEntryHugePage)
                        }
                        SemanticMapperError::Mapper(MapperError::AlreadyMapped { .. }) => {
                            page_error(size, PageMapFailure::PageAlreadyMapped)
                        }
                        SemanticMapperError::Mapper(MapperError::Access(error))
                        | SemanticMapperError::Mapper(MapperError::Frame(error)) => error,
                        _ => PageMapError::TranslationFailed(),
                    })
            };
            for physical_address in reclaims {
                allocator.free_page_table_frame(physical_address);
            }
            unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) };
            result
        })
    }

    unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
        address_space_root: AddressSpaceRoot,
        allocator: &mut A,
        virt: VirtAddr,
        size: MappingSize,
        table_reclaims: &mut Vec<PhysAddr>,
    ) -> Result<Option<PhysAddr>, PageMapError> {
        crate::platform::with_interrupts_disabled(|| {
            let root = root_table(address_space_root)?;
            let input = input_address(root, virt.as_u64())?;
            let level = mapping_level(size)?;
            let access = OffsetTableAccess::new()?;
            let frames = Aarch64TableFrames {
                allocator,
                reclaims: table_reclaims,
            };
            let mut mapper = Mapper::new_offline(root, access, frames)
                .map_err(|_| PageMapError::TranslationFailed())?;
            let mapping = mapper
                .translate(input)
                .map_err(|_| PageMapError::TranslationFailed())?
                .ok_or(PageMapError::TranslationFailed())?;
            if mapping.level() != level
                || mapping.covered_input_base() != input.raw()
                || mapping.covered_size() != size.bytes
            {
                return Err(PageMapError::TranslationFailed());
            }
            let physical_address = PhysAddr::new(mapping.output_base().raw());
            unsafe { mapper.unmap_reclaim(input) }
                .map_err(|_| PageMapError::TranslationFailed())?;
            Ok(Some(physical_address))
        })
    }

    fn resolve_mapping(
        address_space_root: AddressSpaceRoot,
        virt: VirtAddr,
    ) -> Option<ResolvedMapping> {
        crate::platform::with_interrupts_disabled(|| {
            resolve_in_root(address_space_root, virt)
        })
    }

    fn local_flush_tlb_all(_include_global: bool) {
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
            Self::local_flush_tlb_all(false);
            return;
        }
        let mut address = start.as_u64() & !(stride - 1);
        let Some(end) = start
            .as_u64()
            .checked_add(size)
            .and_then(|value| value.checked_add(stride - 1))
            .map(|value| value & !(stride - 1))
        else {
            Self::local_flush_tlb_all(false);
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
                Self::local_flush_tlb_all(false);
                return;
            };
            address = next;
        }
        unsafe {
            asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
    }

    fn broadcast_tlb_shootdown() -> bool {
        super::super::interrupts::init::controller()
            .broadcast_ipi(crate::platform::tlb_shootdown_vector());
        true
    }
}
