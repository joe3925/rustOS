use alloc::{string::String, sync::Arc, vec::Vec};
use core::mem::ManuallyDrop;

use crate::arch::VirtAddr;
use crate::fs::Path;

use crate::sparse_range_radix::{SparseRangeRadix, SparseRangeRadixError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeAllocationError {
    Overlap,
    OutOfRange,
    Unaligned,
}

pub struct RangeAllocationIter<'a> {
    manager: &'a RangeManager,
    cursor: u64,
}

impl Iterator for RangeAllocationIter<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let (first, count) = self.manager.ranges.next_allocation(self.cursor)?;
        self.cursor = first.checked_add(count)?;
        Some((
            self.manager.start + first * self.manager.granularity,
            count * self.manager.granularity,
        ))
    }
}

#[derive(Debug)]
pub struct RangeManager {
    ranges: SparseRangeRadix,
    start: u64,
    end: u64,
    granularity: u64,
}

impl RangeManager {
    pub fn new(start: u64, end: u64, granularity: u64) -> Self {
        let units = if granularity == 0 || end <= start {
            1
        } else {
            ((end - start) / granularity).max(1)
        };
        Self {
            ranges: SparseRangeRadix::try_new(units).expect("failed to create sparse range radix"),
            start,
            end,
            granularity,
        }
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn alloc(self: &Arc<Self>, base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
        let reservation = self.reserve(base, size)?;
        let address = reservation.start();
        core::mem::forget(reservation);
        Ok(address)
    }

    pub fn alloc_auto(self: &Arc<Self>, size: u64) -> Option<VirtAddr> {
        self.alloc_auto_aligned(size, self.granularity)
    }

    pub fn alloc_auto_aligned(self: &Arc<Self>, size: u64, alignment: u64) -> Option<VirtAddr> {
        let reservation = self.reserve_auto_aligned(size, alignment).ok()?;
        let address = reservation.start();
        core::mem::forget(reservation);
        Some(address)
    }

    pub unsafe fn dealloc(&self, base: u64, size: u64) {
        if let Some(size) = self.align_size(size) {
            self.release(base, size);
        }
    }

    pub fn get_allocations(&self) -> RangeAllocationIter<'_> {
        RangeAllocationIter {
            manager: self,
            cursor: 0,
        }
    }

    pub fn reserve(
        self: &Arc<Self>,
        base: u64,
        size: u64,
    ) -> Result<RangeReservation, RangeAllocationError> {
        let size = self
            .align_size(size)
            .ok_or(RangeAllocationError::OutOfRange)?;
        if base % self.granularity != 0 || self.start % self.granularity != 0 {
            return Err(RangeAllocationError::Unaligned);
        }
        let end = base
            .checked_add(size)
            .ok_or(RangeAllocationError::OutOfRange)?;
        if base < self.start || end > self.end {
            return Err(RangeAllocationError::OutOfRange);
        }
        let first = (base - self.start) / self.granularity;
        let count = size / self.granularity;
        self.ranges
            .try_claim(first, count)
            .map_err(map_range_error)?;
        Ok(RangeReservation {
            manager: self.clone(),
            base: VirtAddr::new(base),
            size,
        })
    }

    pub fn reserve_auto(
        self: &Arc<Self>,
        size: u64,
    ) -> Result<RangeReservation, RangeAllocationError> {
        self.reserve_auto_aligned(size, self.granularity)
    }

    pub fn reserve_auto_aligned(
        self: &Arc<Self>,
        size: u64,
        alignment: u64,
    ) -> Result<RangeReservation, RangeAllocationError> {
        let size = self
            .align_size(size)
            .ok_or(RangeAllocationError::OutOfRange)?;
        if size == 0 || self.start >= self.end || size > self.end.saturating_sub(self.start) {
            return Err(RangeAllocationError::OutOfRange);
        }
        if self.granularity == 0
            || self.start % self.granularity != 0
            || alignment < self.granularity
            || !alignment.is_power_of_two()
            || alignment % self.granularity != 0
        {
            return Err(RangeAllocationError::Unaligned);
        }
        let first = self
            .ranges
            .try_claim_auto(size / self.granularity, alignment / self.granularity)
            .map_err(map_range_error)?;
        let base = self
            .start
            .checked_add(
                first
                    .checked_mul(self.granularity)
                    .ok_or(RangeAllocationError::OutOfRange)?,
            )
            .ok_or(RangeAllocationError::OutOfRange)?;
        Ok(RangeReservation {
            manager: self.clone(),
            base: VirtAddr::new(base),
            size,
        })
    }

    fn align_size(&self, size: u64) -> Option<u64> {
        align_up(size, self.granularity)
    }

    fn release(&self, base: u64, size: u64) {
        if self.granularity != 0
            && base >= self.start
            && size % self.granularity == 0
            && base.checked_add(size).is_some_and(|end| end <= self.end)
        {
            let first = (base - self.start) / self.granularity;
            let count = size / self.granularity;
            unsafe { self.ranges.release(first, count) };
        }
    }
}

fn map_range_error(error: SparseRangeRadixError) -> RangeAllocationError {
    match error {
        SparseRangeRadixError::Conflict => RangeAllocationError::Overlap,
        SparseRangeRadixError::OutOfRange | SparseRangeRadixError::AllocationFailed => {
            RangeAllocationError::OutOfRange
        }
    }
}

#[must_use]
#[repr(C)]
#[derive(Debug)]
pub struct RangeReservation {
    manager: Arc<RangeManager>,
    base: VirtAddr,
    size: u64,
}

impl RangeReservation {
    pub fn start(&self) -> VirtAddr {
        self.base
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn end(&self) -> VirtAddr {
        VirtAddr::new(self.base.as_u64() + self.size)
    }

    pub fn contains(&self, offset: u64, size: u64) -> bool {
        offset
            .checked_add(size)
            .is_some_and(|end| size != 0 && end <= self.size)
    }
    /// # Saftey:
    /// Using this method is safe iff the callers knows that there is no other KernelMapping that overlaps and knows that the created mapping repersents a valid mapping.
    pub fn into_allocated_mapping(self, offset: u64, size: u64) -> Result<KernelMapping, Self> {
        KernelMapping::new(self, offset, size, true)
    }

    /// # Saftey:
    /// Using this method is safe iff the caller knows that there is no other KernelMapping that overlaps and knows that the created mapping repersents a valid mapping.
    /// The caller of this method must also own the physical frames backing the mapping.
    pub fn into_borrowed_mapping(self, offset: u64, size: u64) -> Result<KernelMapping, Self> {
        KernelMapping::new(self, offset, size, false)
    }
}

impl Drop for RangeReservation {
    fn drop(&mut self) {
        self.manager.release(self.base.as_u64(), self.size);
    }
}

#[repr(C)]
#[derive(Debug)]
struct MappedKernelRange {
    base: VirtAddr,
    size: u64,
    owns_frames: bool,
}

#[cfg(not(any(test, feature = "hosted-tests")))]
unsafe extern "C" {
    // FIXME: MappedKernelRange Drop uses a linker seam.
    fn kernel_mapping_drop(base: VirtAddr, size: u64, owns_frames: bool);
}

impl Drop for MappedKernelRange {
    fn drop(&mut self) {
        #[cfg(not(any(test, feature = "hosted-tests")))]
        unsafe {
            kernel_mapping_drop(self.base, self.size, self.owns_frames);
        }
    }
}

#[must_use]
#[repr(C)]
#[derive(Debug)]
pub struct KernelMapping {
    mapped: MappedKernelRange,
    reservation: RangeReservation,
}

impl KernelMapping {
    fn new(
        reservation: RangeReservation,
        offset: u64,
        size: u64,
        owns_frames: bool,
    ) -> Result<Self, RangeReservation> {
        if !reservation.contains(offset, size) {
            return Err(reservation);
        }
        let base = VirtAddr::new(reservation.start().as_u64() + offset);
        Ok(Self {
            mapped: MappedKernelRange {
                base,
                size,
                owns_frames,
            },
            reservation,
        })
    }

    pub fn address(&self) -> VirtAddr {
        self.mapped.base
    }

    pub fn size(&self) -> u64 {
        self.mapped.size
    }

    pub fn reservation_start(&self) -> VirtAddr {
        self.reservation.start()
    }

    pub fn reservation_size(&self) -> u64 {
        self.reservation.size()
    }

    pub fn offset(&self) -> u64 {
        self.mapped.base.as_u64() - self.reservation.start().as_u64()
    }

    pub fn into_reservation(self) -> RangeReservation {
        let this = ManuallyDrop::new(self);
        unsafe {
            core::ptr::drop_in_place(core::ptr::addr_of!(this.mapped).cast_mut());
            core::ptr::read(core::ptr::addr_of!(this.reservation))
        }
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalMappingCache {
    Cached,
    WriteCombining,
    Uncached,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeInfo {
    pub is_64: bool,
    pub is_dll: bool,
    pub machine: u16,
    pub characteristics: u16,
    pub time_date_stamp: u32,
    pub optional_magic: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub preferred_image_base: u64,
    pub loaded_image_base: VirtAddr,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_code: u64,
    pub size_of_initialized_data: u64,
    pub size_of_uninitialized_data: u64,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub aslr: bool,
    pub relocated: bool,
    pub sections: Vec<PeSectionInfo>,
    pub imports: Vec<PeImportInfo>,
    pub exports: Vec<PeExportInfo>,
    pub pdb: Option<PePdbInfo>,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeImportInfo {
    pub dll: String,
    pub name: String,
    pub ordinal: u16,
    pub import_address_table_rva: u64,
    pub hint_name_table_rva: u64,
    pub thunk_size: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeExportInfo {
    pub name: Option<String>,
    pub rva: u64,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PePdbInfo {
    pub format: PePdbFormat,
    pub path: String,
    pub age: u32,
    pub guid: Option<[u8; 16]>,
    pub signature: Option<u32>,
    pub codeview_offset: Option<u32>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PePdbFormat {
    Pdb70,
    Pdb20,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct Module {
    pub title: String,
    pub image_path: Path,
    pub parent_pid: u64,
    pub image_base: VirtAddr,
    pub image_size: u64,
    pub exports: Vec<(String, usize)>,
    pub pe_info: Option<PeInfo>,
}
