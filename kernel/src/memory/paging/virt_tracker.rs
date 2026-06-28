use alloc::sync::Arc;
use core::sync::atomic::AtomicUsize;

use kernel_types::arch::VirtAddr;
use lazy_static::lazy_static;

use crate::structs::range_tracker::{RangeAllocationError, RangeTracker};

use super::layout::{
    align_up_to_base_page, base_page_size, managed_kernel_range_end, managed_kernel_range_start,
};

pub(crate) const MAX_PENDING_FREES: usize = 64;
pub(crate) static mut PENDING_FREES: [Option<(u64, u64)>; MAX_PENDING_FREES] =
    [None; MAX_PENDING_FREES];
pub(crate) static PENDING_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    pub static ref KERNEL_RANGE_TRACKER: Arc<RangeTracker> =
        Arc::new(RangeTracker::new_with_granularity(
            managed_kernel_range_start().as_u64(),
            managed_kernel_range_end().as_u64(),
            base_page_size(),
        ));
}

pub fn allocate_auto_kernel_range(size: u64) -> Option<VirtAddr> {
    let aligned_size = align_up_to_base_page(size)?;
    let addr = KERNEL_RANGE_TRACKER.alloc_auto(aligned_size)?;
    debug_assert_eq!(addr.as_u64() % base_page_size(), 0);
    Some(addr.into())
}

pub fn allocate_auto_kernel_range_aligned(size: u64, alignment: u64) -> Option<VirtAddr> {
    let aligned_size = align_up_to_base_page(size)?;
    let base_page = base_page_size();

    if alignment < base_page {
        return None;
    }
    if (alignment & (alignment - 1)) != 0 {
        return None;
    }
    if (alignment % base_page) != 0 {
        return None;
    }

    let addr = if alignment == base_page {
        KERNEL_RANGE_TRACKER.alloc_auto(aligned_size)?
    } else {
        KERNEL_RANGE_TRACKER.alloc_auto_aligned(aligned_size, alignment)?
    };

    Some(addr.into())
}

pub fn allocate_kernel_range(base: u64, size: u64) -> Result<VirtAddr, RangeAllocationError> {
    if base % base_page_size() != 0 {
        return Err(RangeAllocationError::Unaligned);
    }
    let aligned_size = align_up_to_base_page(size).ok_or(RangeAllocationError::OutOfRange)?;
    let addr = KERNEL_RANGE_TRACKER.alloc(base, aligned_size)?;
    debug_assert_eq!(addr.as_u64() % base_page_size(), 0);
    Ok(addr.into())
}

/// # Safety
/// The range must currently be allocated in the kernel range tracker and must
/// be released exactly once after all uses have ended.
pub unsafe fn deallocate_kernel_range(addr: VirtAddr, size: u64) {
    debug_assert_eq!(addr.as_u64() % base_page_size(), 0);
    if let Some(aligned_size) = align_up_to_base_page(size) {
        unsafe { KERNEL_RANGE_TRACKER.dealloc(addr.as_u64(), aligned_size) };
    }
}
