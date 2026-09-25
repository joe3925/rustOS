use alloc::{string::String, sync::Arc, vec::Vec};
use core::mem::ManuallyDrop;

use spin::{Mutex, MutexGuard};

use crate::arch::VirtAddr;
use crate::fs::Path;

const MAX_RANGE_ALLOCATIONS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeAllocationError {
    Overlap,
    OutOfRange,
    Unaligned,
}

#[derive(Debug)]
struct RangeAllocations {
    entries: [(u64, u64); MAX_RANGE_ALLOCATIONS],
    len: usize,
}

pub struct RangeAllocationIter<'a> {
    guard: MutexGuard<'a, RangeAllocations>,
    index: usize,
}

impl Iterator for RangeAllocationIter<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.guard.len {
            return None;
        }
        let entry = self.guard.entries[self.index];
        self.index += 1;
        Some(entry)
    }
}

#[derive(Debug)]
pub struct RangeManager {
    allocations: Mutex<RangeAllocations>,
    start: u64,
    end: u64,
    granularity: u64,
}

impl RangeManager {
    pub const fn new(start: u64, end: u64, granularity: u64) -> Self {
        Self {
            allocations: Mutex::new(RangeAllocations {
                entries: [(0, 0); MAX_RANGE_ALLOCATIONS],
                len: 0,
            }),
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
            guard: self.allocations.lock(),
            index: 0,
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
        if base % self.granularity != 0 {
            return Err(RangeAllocationError::Unaligned);
        }
        let end = base
            .checked_add(size)
            .ok_or(RangeAllocationError::OutOfRange)?;
        let mut allocations = self.allocations.lock();
        if base < self.start || end > self.end {
            return Err(RangeAllocationError::OutOfRange);
        }
        if allocations.entries[..allocations.len]
            .iter()
            .any(|&(allocated_base, allocated_size)| {
                let allocated_end = allocated_base + allocated_size;
                base < allocated_end && end > allocated_base
            })
        {
            return Err(RangeAllocationError::Overlap);
        }
        if allocations.len == MAX_RANGE_ALLOCATIONS {
            return Err(RangeAllocationError::OutOfRange);
        }
        let index = allocations.len;
        allocations.entries[index] = (base, size);
        allocations.len += 1;
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
        if size == 0
            || alignment < self.granularity
            || !alignment.is_power_of_two()
            || alignment % self.granularity != 0
        {
            return Err(RangeAllocationError::Unaligned);
        }
        let mut allocations = self.allocations.lock();
        if allocations.len == MAX_RANGE_ALLOCATIONS {
            return Err(RangeAllocationError::OutOfRange);
        }
        let len = allocations.len;
        allocations.entries[..len].sort_unstable_by_key(|&(base, _)| base);
        let mut current =
            align_up(self.start, alignment).ok_or(RangeAllocationError::OutOfRange)?;
        for index in 0..len {
            let (allocated_base, allocated_size) = allocations.entries[index];
            if current
                .checked_add(size)
                .is_some_and(|end| end <= allocated_base)
            {
                allocations.entries[len] = (current, size);
                allocations.len += 1;
                return Ok(RangeReservation {
                    manager: self.clone(),
                    base: VirtAddr::new(current),
                    size,
                });
            }
            let allocated_end = allocated_base
                .checked_add(allocated_size)
                .ok_or(RangeAllocationError::OutOfRange)?;
            if allocated_end > current {
                current =
                    align_up(allocated_end, alignment).ok_or(RangeAllocationError::OutOfRange)?;
            }
        }
        if current.checked_add(size).is_some_and(|end| end <= self.end) {
            allocations.entries[len] = (current, size);
            allocations.len += 1;
            return Ok(RangeReservation {
                manager: self.clone(),
                base: VirtAddr::new(current),
                size,
            });
        }
        Err(RangeAllocationError::OutOfRange)
    }

    fn align_size(&self, size: u64) -> Option<u64> {
        align_up(size, self.granularity)
    }

    fn release(&self, base: u64, size: u64) {
        let mut allocations = self.allocations.lock();
        if let Some(index) = allocations.entries[..allocations.len].iter().position(
            |&(allocated_base, allocated_size)| allocated_base == base && allocated_size == size,
        ) {
            allocations.len -= 1;
            let last = allocations.len;
            allocations.entries[index] = allocations.entries[last];
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
