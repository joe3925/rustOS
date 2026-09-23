use alloc::vec::Vec;
use core::convert::Infallible;
use core::ptr::NonNull;

use kernel_types::arch::{AddressSpaceRoot, PhysAddr, VirtAddr};
use kernel_types::status::PageMapError;
use x86_64_paging::paging::address::{Level, TranslationGranule, VirtAddr as PagingVirtAddr};
use x86_64_paging::paging::table::{
    RecursiveTableAccess, RootTable, RootTableGeometry, TableAccess, TableAccessLocation,
    TableAccessMut, TableAddr, TableAllocLayout, TableFrameProvider, TableReclaim,
    TranslationTable, TranslationTableMut,
};
use x86_64_paging::{Amd64, Granule4KiB, LongMode4Level, PageTableFlags, from_canonical};

use crate::memory::paging::types::MappingSize;
use crate::platform::PageTableFrameAllocator;
use crate::util::boot_info;

use super::tables::recursive_table_addr;

pub(super) type X86RootTable = RootTable<Amd64, LongMode4Level, Granule4KiB>;


pub(super) fn root_table(root: AddressSpaceRoot) -> Result<X86RootTable, PageMapError> {
    let address = TableAddr::new(root.as_u64()).map_err(|_| PageMapError::TranslationFailed())?;
    let output_address_bits = super::super::super::cpu::get_cpu_info()
        .get_processor_capacity_feature_info()
        .map(|capacity| capacity.physical_address_bits())
        .unwrap_or(48);
    RootTableGeometry::<Amd64, Granule4KiB>::new(address, 48, output_address_bits)
        .map(|geometry| geometry.with_regime())
        .map_err(|_| PageMapError::TranslationFailed())
}

pub(super) fn input_address(
    address: VirtAddr,
) -> Result<x86_64_paging::paging::translation::walk::WalkInputAddr, PageMapError> {
    from_canonical(address.as_u64(), 48).map_err(|_| PageMapError::TranslationFailed())
}

pub(super) fn mapping_level(size: MappingSize) -> Result<Level, PageMapError> {
    match size.bytes {
        0x4000_0000 => Ok(Level::new(1)),
        0x20_0000 => Ok(Level::new(2)),
        0x1000 => Ok(Level::new(3)),
        _ => Err(PageMapError::TranslationFailed()),
    }
}

pub(super) fn page_error(
    size: MappingSize,
    failure: kernel_types::status::PageMapFailure,
) -> PageMapError {
    match size.bytes {
        0x4000_0000 => PageMapError::Page1GiB(failure),
        0x20_0000 => PageMapError::Page2MiB(failure),
        _ => PageMapError::Page4KiB(failure),
    }
}

pub(super) struct ScratchTableAccess {
    scratch: VirtAddr,
    descriptor: *mut u64,
}

pub(super) enum X86TableAccess {
    Recursive(RecursiveTableAccess<Amd64, Granule4KiB>),
    Scratch(ScratchTableAccess),
}

impl X86TableAccess {
    pub(super) fn new(root: AddressSpaceRoot) -> Result<Self, PageMapError> {
        let (active_root, _) = x86_64::registers::control::Cr3::read();
        if root.as_u64() == active_root.start_address().as_u64() {
            let recursive_index = boot_info()
                .arch_info
                .recursive_index
                .into_option()
                .ok_or(PageMapError::NoMemoryMap())?;
            let recursive_base = super::tables::recursive_level_4_table_addr(recursive_index);
            let table_root = TableAddr::new(root.as_u64())
                .map_err(|_| PageMapError::TranslationFailed())?;
            let access = unsafe {
                RecursiveTableAccess::new(
                    usize::from(u16::from(recursive_index)),
                    PagingVirtAddr(recursive_base.as_u64()),
                    table_root,
                    Level::new(0),
                )
            }
            .map_err(|_| PageMapError::TranslationFailed())?;
            return Ok(Self::Recursive(access));
        }

        ScratchTableAccess::new().map(Self::Scratch)
    }
}

unsafe impl TableAccess<Amd64, Granule4KiB> for X86TableAccess {
    type Error = PageMapError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<'a, Amd64, Granule4KiB>,
    ) -> Result<TranslationTable<'a, Amd64, Granule4KiB>, Self::Error> {
        match self {
            Self::Recursive(access) => access
                .table_at(location)
                .map_err(|_| PageMapError::TranslationFailed()),
            Self::Scratch(access) => access.table_at(location),
        }
    }
}

unsafe impl TableAccessMut<Amd64, Granule4KiB> for X86TableAccess {
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<'a, Amd64, Granule4KiB>,
    ) -> Result<TranslationTableMut<'a, Amd64, Granule4KiB>, Self::Error> {
        match self {
            Self::Recursive(access) => access
                .table_at_mut(location)
                .map_err(|_| PageMapError::TranslationFailed()),
            Self::Scratch(access) => access.table_at_mut(location),
        }
    }
}

impl ScratchTableAccess {
    pub(super) fn new() -> Result<Self, PageMapError> {
        let scratch = crate::memory::paging::zero::page_table_scratch_address()?;
        let recursive_index = boot_info()
            .arch_info
            .recursive_index
            .into_option()
            .ok_or(PageMapError::NoMemoryMap())?;
        let raw = scratch.as_u64();
        let rec = u64::from(recursive_index);
        let p4 = (raw >> 39) & 0x1ff;
        let p3 = (raw >> 30) & 0x1ff;
        let p2 = (raw >> 21) & 0x1ff;
        let p1 = (raw >> 12) & 0x1ff;
        let table = recursive_table_addr(rec, p4, p3, p2);
        Ok(Self {
            scratch,
            descriptor: unsafe { (table as *mut u64).add(p1 as usize) },
        })
    }

    fn map_table<F>(
        &self,
        location: TableAccessLocation<'_, F, Granule4KiB>,
    ) -> Result<NonNull<u64>, PageMapError>
    where
        F: x86_64_paging::paging::descriptor::DescriptorFormat<Raw = u64>,
    {
        let raw = location.addr().raw()
            | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE)
                .bits();
        unsafe { self.descriptor.write_volatile(raw) };
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(self.scratch.as_u64()));
        NonNull::new(self.scratch.as_mut_ptr::<u64>()).ok_or(PageMapError::NoMemoryMap())
    }
}

impl Drop for ScratchTableAccess {
    fn drop(&mut self) {
        unsafe { self.descriptor.write_volatile(0) };
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(self.scratch.as_u64()));
    }
}

unsafe impl TableAccess<Amd64, Granule4KiB> for ScratchTableAccess {
    type Error = PageMapError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<'a, Amd64, Granule4KiB>,
    ) -> Result<TranslationTable<'a, Amd64, Granule4KiB>, Self::Error> {
        let base = self.map_table(location)?;
        Ok(unsafe { TranslationTable::from_raw_parts(base, location.shape()) })
    }
}

unsafe impl TableAccessMut<Amd64, Granule4KiB> for ScratchTableAccess {
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<'a, Amd64, Granule4KiB>,
    ) -> Result<TranslationTableMut<'a, Amd64, Granule4KiB>, Self::Error> {
        let base = self.map_table(location)?;
        Ok(unsafe { TranslationTableMut::from_raw_parts(base, location.shape()) })
    }
}

pub(super) struct X86TableFrames<'a, A: PageTableFrameAllocator> {
    pub(super) allocator: &'a mut A,
    pub(super) reclaims: &'a mut Vec<PhysAddr>,
}

unsafe impl<A: PageTableFrameAllocator> TableFrameProvider<Granule4KiB> for X86TableFrames<'_, A> {
    type Error = PageMapError;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<Granule4KiB>, Self::Error> {
        if layout.bytes() != Granule4KiB::SIZE || layout.align() != Granule4KiB::SIZE {
            return Err(PageMapError::TranslationFailed());
        }
        let address = self
            .allocator
            .allocate_page_table_frame()
            .ok_or(PageMapError::NoMemory())?;
        match TableAddr::new(address.as_u64()) {
            Ok(address) => Ok(address),
            Err(_) => {
                self.allocator.free_page_table_frame(address);
                Err(PageMapError::TranslationFailed())
            }
        }
    }

    fn reclaim_table(&mut self, reclaim: TableReclaim<Granule4KiB>) -> Result<(), Self::Error> {
        self.reclaims.push(PhysAddr::new(reclaim.addr().raw()));
        Ok(())
    }
}

pub(super) struct NoTableFrames;

unsafe impl TableFrameProvider<Granule4KiB> for NoTableFrames {
    type Error = Infallible;

    fn allocate_zeroed_table(
        &mut self,
        _: TableAllocLayout,
    ) -> Result<TableAddr<Granule4KiB>, Self::Error> {
        unreachable!()
    }

    fn reclaim_table(&mut self, _: TableReclaim<Granule4KiB>) -> Result<(), Self::Error> {
        unreachable!()
    }
}
