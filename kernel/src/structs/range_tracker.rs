use alloc::vec::Vec;
use spin::{Mutex, MutexGuard};
use x86_64::VirtAddr;

pub struct AllocationIter<'a> {
    guard: MutexGuard<'a, Vec<(u64, u64)>>,
    idx: usize,
}

impl<'a> Iterator for AllocationIter<'a> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let out = self.guard.get(self.idx).copied();
        if out.is_some() {
            self.idx += 1;
        }
        out
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.guard.len() - self.idx;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for AllocationIter<'a> {}

pub enum RangeAllocationError {
    Overlap,
    OutOfRange,
    Unaligned,
}
#[derive(Debug)]
pub struct RangeTracker {
    allocations: Mutex<Vec<(u64, u64)>>,

    pub start: u64,
    pub end: u64,
}

impl RangeTracker {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            allocations: Mutex::new(Vec::new()),
            start,
            end,
        }
    }

    pub fn alloc(&self, base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        let mut lock = self.allocations.lock();
        if (base < self.start || base + aligned_size > self.end) {
            return Err(RangeAllocationError::OutOfRange);
        }
        // Ensure no overlap
        if lock.iter().any(|&(a, s)| {
            let end = a + s;
            let req_end = base + aligned_size;
            !(base >= end || req_end <= a)
        }) {
            return Err(RangeAllocationError::Overlap);
        }

        lock.push((base, aligned_size));
        Ok(VirtAddr::new(base))
    }
    pub fn get_allocations(&self) -> AllocationIter<'_> {
        AllocationIter {
            guard: self.allocations.lock(),
            idx: 0,
        }
    }

    pub fn dealloc(&self, base: u64, size: u64) {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        let mut lock = self.allocations.lock();
        if let Some(index) = lock
            .iter()
            .position(|&(a, s)| a == base && s == aligned_size)
        {
            lock.remove(index);
        }
    }

    // Finds a free region of at least `size` bytes and allocates it
    pub fn alloc_auto(&self, size: u64) -> Option<VirtAddr> {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        let mut lock = self.allocations.lock();

        // Sort existing allocations by base address
        lock.sort_unstable_by_key(|&(base, _)| base);

        let mut current = self.start;

        for &(alloc_base, alloc_size) in lock.iter() {
            let alloc_end = alloc_base;

            if current + aligned_size <= alloc_end {
                // Found gap
                lock.push((current, aligned_size));
                return Some(VirtAddr::new(current));
            }

            // Move past this allocation
            current = alloc_base + alloc_size;
            if current > self.end {
                return None;
            }
        }

        // Check space at the end
        if current + aligned_size <= self.end {
            lock.push((current, aligned_size));
            return Some(VirtAddr::new(current));
        }

        None
    }
}
