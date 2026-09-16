use aarch64_vmsa::config::format::{NativeEndian, Vmsa64};
use aarch64_vmsa::config::granule::Granule4KiB;
use aarch64_vmsa::format::DescriptorFormat;
use aarch64_vmsa::granule::TranslationGranule;
use aarch64_vmsa::table::{
    AccessError, TableAccess, TableAccessLocation, TableAccessMut, TableAddr, TableAllocLayout,
    TableFrameProvider, TableReclaim, TranslationTable, TranslationTableMut,
};
use alloc::boxed::Box;
use core::ptr::NonNull;
use kernel_types::arch::PageFlags;
use spin::Mutex;

use crate::memory::device_mmu::DeviceMmuError;
use crate::memory::paging::map::{allocate_auto_kernel_range_mapped_contiguous, virt_to_phys};

pub(super) type Format = Vmsa64<NativeEndian>;
pub(super) type Granule = Granule4KiB;

pub(super) const MIN_TABLE_ARENA_SIZE: u64 = 32 * 1024 * 1024;

pub(super) struct TableArena {
    phys: u64,
    virt: u64,
    end: u64,
    next: Mutex<u64>,
    reclaimed: Mutex<Box<[Option<ReclaimedTable>]>>,
}

#[derive(Clone, Copy)]
struct ReclaimedTable {
    phys: u64,
    bytes: u64,
    align: u64,
}

const MAX_RECLAIMED_TABLES: usize = 4096;
const VMSA64_TABLE_DESCRIPTOR_TYPE_MASK: u64 = 0b11;
const VMSA64_TABLE_DESCRIPTOR_TYPE_TABLE: u64 = 0b11;
const VMSA64_TABLE_DESCRIPTOR_ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const VMSA64_TABLE_ENTRY_COUNT: u64 = 512;
const VMSA64_TABLE_BYTES: u64 = 4096;

impl TableArena {
    pub(super) fn new(size: u64) -> Result<Self, DeviceMmuError> {
        let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE;
        let virt = allocate_auto_kernel_range_mapped_contiguous(size, flags)
            .map_err(|_| DeviceMmuError::NoBackingFrame)?;
        let (_, phys) = virt_to_phys(virt).ok_or(DeviceMmuError::NoBackingFrame)?;
        unsafe { core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, size as usize) };
        Ok(Self {
            phys: phys.as_u64(),
            virt: virt.as_u64(),
            end: phys.as_u64() + size,
            next: Mutex::new(phys.as_u64()),
            reclaimed: Mutex::new(alloc::vec![None; MAX_RECLAIMED_TABLES].into_boxed_slice()),
        })
    }

    pub(super) fn allocate(&self, bytes: u64, align: u64) -> Result<u64, DeviceMmuError> {
        let mut reclaimed = self.reclaimed.lock();
        if let Some(slot) = reclaimed
            .iter_mut()
            .find(|slot| slot.is_some_and(|table| table.bytes == bytes && table.align == align))
        {
            let table = slot.take().unwrap();
            unsafe {
                core::ptr::write_bytes(
                    self.virtual_address(table.phys) as *mut u8,
                    0,
                    bytes as usize,
                )
            };
            return Ok(table.phys);
        }
        drop(reclaimed);
        let mut next = self.next.lock();
        let base = next
            .checked_add(align - 1)
            .map(|value| value & !(align - 1))
            .ok_or(DeviceMmuError::NoBackingFrame)?;
        let end = base
            .checked_add(bytes)
            .ok_or(DeviceMmuError::NoBackingFrame)?;
        if end > self.end {
            return Err(DeviceMmuError::NoBackingFrame);
        }
        unsafe { core::ptr::write_bytes(self.virtual_address(base) as *mut u8, 0, bytes as usize) };
        *next = end;
        Ok(base)
    }

    pub(super) fn virtual_address(&self, phys: u64) -> u64 {
        self.virt + (phys - self.phys)
    }


    pub(super) fn clean_allocated(&self) {
        let bytes = *self.next.lock() - self.phys;
        crate::arch::aarch64::cpu::clean_to_poc(self.virt, bytes as usize);
    }

    pub(super) fn reclaim_translation_tree(&self, root: u64) {
        unsafe fn reclaim_level(arena: &TableArena, table: u64, level: u8) {
            if level < 3 {
                let virtual_address = arena.virtual_address(table);
                for index in 0..VMSA64_TABLE_ENTRY_COUNT {
                    let descriptor = unsafe {
                        core::ptr::read_volatile(
                            (virtual_address + index * core::mem::size_of::<u64>() as u64)
                                as *const u64,
                        )
                    };
                    if descriptor & VMSA64_TABLE_DESCRIPTOR_TYPE_MASK
                        == VMSA64_TABLE_DESCRIPTOR_TYPE_TABLE
                    {
                        let child = descriptor & VMSA64_TABLE_DESCRIPTOR_ADDRESS_MASK;
                        unsafe { reclaim_level(arena, child, level + 1) };
                    }
                }
            }
            let _ = arena.reclaim(ReclaimedTable {
                phys: table,
                bytes: VMSA64_TABLE_BYTES,
                align: VMSA64_TABLE_BYTES,
            });
        }
        unsafe { reclaim_level(self, root, 0) };
    }

    pub(super) fn reclaim_allocation(&self, phys: u64, bytes: u64, align: u64) {
        let _ = self.reclaim(ReclaimedTable { phys, bytes, align });
    }

    fn reclaim(&self, table: ReclaimedTable) -> Result<(), DeviceMmuError> {
        let mut reclaimed = self.reclaimed.lock();
        let slot = reclaimed
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(DeviceMmuError::NoBackingFrame)?;
        *slot = Some(table);
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct TableMemory(pub(super) alloc::sync::Arc<TableArena>);

unsafe impl<G: TranslationGranule> TableFrameProvider<G> for TableMemory {
    type Error = DeviceMmuError;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<G>, Self::Error> {
        let phys = self.0.allocate(layout.bytes(), layout.align())?;
        TableAddr::new(phys).map_err(|_| DeviceMmuError::NoBackingFrame)
    }

    fn reclaim_table(&mut self, reclaim: TableReclaim<G>) -> Result<(), Self::Error> {
        self.0.reclaim(ReclaimedTable {
            phys: reclaim.addr().raw(),
            bytes: reclaim.layout().bytes(),
            align: reclaim.layout().align(),
        })
    }
}

unsafe impl<F: DescriptorFormat, G: TranslationGranule> TableAccess<F, G> for TableMemory {
    type Error = AccessError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        let address = self.0.virtual_address(location.addr().raw());
        let ptr = NonNull::new(address as *mut F::Raw).ok_or(AccessError::NullMapping)?;
        Ok(unsafe { TranslationTable::from_raw_parts(ptr, location.shape()) })
    }
}

unsafe impl<F: DescriptorFormat, G: TranslationGranule> TableAccessMut<F, G> for TableMemory {
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        let address = self.0.virtual_address(location.addr().raw());
        let ptr = NonNull::new(address as *mut F::Raw).ok_or(AccessError::NullMapping)?;
        Ok(unsafe { TranslationTableMut::from_raw_parts(ptr, location.shape()) })
    }
}
