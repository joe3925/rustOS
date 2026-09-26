use alloc::vec::Vec;
use core::convert::Infallible;
use core::ptr::NonNull;

use kernel_types::arch::{AddressSpaceRoot, PhysAddr, VirtAddr};
use kernel_types::status::PageMapError;
use x86_64_paging::paging::address::{Level, TranslationGranule};
use x86_64_paging::paging::table::{
    RootTable, RootTableGeometry, TableAccess, TableAccessLocation, TableAccessMut, TableAddr,
    TableAllocLayout, TableFrameProvider, TableReclaim, TranslationTable, TranslationTableMut,
};
use x86_64_paging::{Amd64, Granule4KiB, LongMode4Level, PageTableFlags, from_canonical};

use crate::memory::paging::types::MappingSize;
use crate::platform::PageTableFrameAllocator;
use crate::util::boot_info;

pub(super) type X86RootTable = RootTable<Amd64, LongMode4Level, Granule4KiB>;


pub(super) fn root_table(root: AddressSpaceRoot) -> Result<X86RootTable, PageMapError> {
    let address = TableAddr::new(root.as_u64()).map_err(|_| PageMapError::TranslationFailed())?;
    RootTableGeometry::<Amd64, Granule4KiB>::new(
        address,
        48,
        super::tables::paging_properties().output_address_bits,
    )
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

pub(super) struct X86TableAccess;

impl X86TableAccess {
    pub(super) fn new(_: AddressSpaceRoot) -> Result<Self, PageMapError> {
        Ok(Self)
    }
}

unsafe impl TableAccess<Amd64, Granule4KiB> for X86TableAccess {
    type Error = PageMapError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<'a, Amd64, Granule4KiB>,
    ) -> Result<TranslationTable<'a, Amd64, Granule4KiB>, Self::Error> {
        let base = table_pointer(
            location.addr().raw(),
            location
                .shape()
                .alloc_layout()
                .map_err(|_| PageMapError::TranslationFailed())?
                .bytes(),
        )?;
        Ok(unsafe { TranslationTable::from_raw_parts(base, location.shape()) })
    }
}

unsafe impl TableAccessMut<Amd64, Granule4KiB> for X86TableAccess {
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<'a, Amd64, Granule4KiB>,
    ) -> Result<TranslationTableMut<'a, Amd64, Granule4KiB>, Self::Error> {
        let base = table_pointer(
            location.addr().raw(),
            location
                .shape()
                .alloc_layout()
                .map_err(|_| PageMapError::TranslationFailed())?
                .bytes(),
        )?;
        Ok(unsafe { TranslationTableMut::from_raw_parts(base, location.shape()) })
    }
}

fn table_pointer(physical_address: u64, size: u64) -> Result<NonNull<u64>, PageMapError> {
    let info = &boot_info().arch_info;
    let end = physical_address
        .checked_add(size)
        .ok_or(PageMapError::TranslationFailed())?;
    if end > info.physical_memory_len {
        return Err(PageMapError::NoMemoryMap());
    }
    let address = info
        .physical_memory_offset
        .checked_add(physical_address)
        .ok_or(PageMapError::TranslationFailed())?;
    NonNull::new(address as *mut u64).ok_or(PageMapError::NoMemoryMap())
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
