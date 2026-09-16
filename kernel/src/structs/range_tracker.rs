use crate::memory::paging::layout::base_page_size;
use spin::{Mutex, MutexGuard};

use kernel_types::arch::VirtAddr;

const MAX_ALLOCATIONS: usize = 4096;

#[derive(Debug)]
struct Allocations {
    entries: [(u64, u64); MAX_ALLOCATIONS],
    len: usize,
}

pub struct AllocationIter<'a> {
    guard: MutexGuard<'a, Allocations>,
    idx: usize,
}

impl<'a> Iterator for AllocationIter<'a> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.guard.len {
            return None;
        }
        let out = self.guard.entries[self.idx];
        self.idx += 1;
        Some(out)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.guard.len - self.idx;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AllocationIter<'_> {}

pub enum RangeAllocationError {
    Overlap,
    OutOfRange,
    Unaligned,
}

#[derive(Debug)]
pub struct RangeTracker {
    allocations: Mutex<Allocations>,
    pub start: u64,
    pub end: u64,
    granularity: u64,
}

impl RangeTracker {
    pub fn new(start: u64, end: u64) -> Self {
        Self::new_with_granularity(start, end, base_page_size())
    }

    pub fn new_with_granularity(start: u64, end: u64, granularity: u64) -> Self {
        Self {
            allocations: Mutex::new(Allocations {
                entries: [(0, 0); MAX_ALLOCATIONS],
                len: 0,
            }),
            start,
            end,
            granularity,
        }
    }

    fn align_size(&self, size: u64) -> Option<u64> {
        align_up(size, self.granularity)
    }

    pub fn alloc(&self, base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
        let aligned_size = self.align_size(size).ok_or(RangeAllocationError::OutOfRange)?;
        let mut lock = self.allocations.lock();
        let request_end = base.checked_add(aligned_size).ok_or(RangeAllocationError::OutOfRange)?;
        if base < self.start || request_end > self.end {
            return Err(RangeAllocationError::OutOfRange);
        }
        if lock.entries[..lock.len].iter().any(|&(allocated_base, allocated_size)| {
            let allocated_end = allocated_base + allocated_size;
            !(base >= allocated_end || request_end <= allocated_base)
        }) {
            return Err(RangeAllocationError::Overlap);
        }
        if lock.len == MAX_ALLOCATIONS {
            return Err(RangeAllocationError::OutOfRange);
        }
        let index = lock.len;
        lock.entries[index] = (base, aligned_size);
        lock.len += 1;
        Ok(VirtAddr::new(base))
    }

    pub fn get_allocations(&self) -> AllocationIter<'_> {
        AllocationIter {
            guard: self.allocations.lock(),
            idx: 0,
        }
    }

    pub unsafe fn dealloc(&self, base: u64, size: u64) {
        let Some(aligned_size) = self.align_size(size) else {
            return;
        };
        let mut lock = self.allocations.lock();
        if let Some(index) = lock.entries[..lock.len]
            .iter()
            .position(|&(allocated_base, allocated_size)| allocated_base == base && allocated_size == aligned_size)
        {
            lock.len -= 1;
            let last = lock.len;
            lock.entries[index] = lock.entries[last];
        }
    }

    pub fn alloc_auto(&self, size: u64) -> Option<VirtAddr> {
        let aligned_size = self.align_size(size)?;
        self.alloc_auto_aligned(aligned_size, self.granularity)
    }

    pub fn alloc_auto_aligned(&self, size: u64, alignment: u64) -> Option<VirtAddr> {
        let aligned_size = self.align_size(size)?;
        if aligned_size == 0
            || alignment < self.granularity
            || !alignment.is_power_of_two()
            || alignment % self.granularity != 0
        {
            return None;
        }

        let mut lock = self.allocations.lock();
        if lock.len == MAX_ALLOCATIONS {
            return None;
        }
        let len = lock.len;
        lock.entries[..len].sort_unstable_by_key(|&(base, _)| base);
        let mut current = align_up(self.start, alignment)?;

        for index in 0..len {
            let (allocated_base, allocated_size) = lock.entries[index];
            if current.checked_add(aligned_size).is_some_and(|end| end <= allocated_base) {
                lock.entries[len] = (current, aligned_size);
                lock.len += 1;
                return Some(VirtAddr::new(current));
            }
            let allocated_end = allocated_base.checked_add(allocated_size)?;
            if allocated_end > current {
                current = align_up(allocated_end, alignment)?;
            }
            if current > self.end {
                return None;
            }
        }

        if current.checked_add(aligned_size).is_some_and(|end| end <= self.end) {
            lock.entries[len] = (current, aligned_size);
            lock.len += 1;
            return Some(VirtAddr::new(current));
        }
        None
    }
}

#[inline]
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    debug_assert!(alignment.is_power_of_two());
    value.checked_add(alignment - 1).map(|value| value & !(alignment - 1))
}
