use alloc::sync::Arc;
use core::sync::atomic::AtomicUsize;

use kernel_types::memory::{
    RangeAllocationError as ReservationError, RangeManager, RangeReservation,
};
use lazy_static::lazy_static;

use super::layout::{
    align_up_to_base_page, base_page_size, managed_kernel_range_end, managed_kernel_range_start,
};

pub(crate) const MAX_PENDING_FREES: usize = 64;
pub(crate) static mut PENDING_FREES: [Option<(u64, u64)>; MAX_PENDING_FREES] =
    [None; MAX_PENDING_FREES];
pub(crate) static PENDING_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    pub static ref KERNEL_RANGE_MANAGER: Arc<RangeManager> = Arc::new(RangeManager::new(
        managed_kernel_range_start().as_u64(),
        managed_kernel_range_end().as_u64(),
        base_page_size(),
    ));
}
pub fn reserve_auto_kernel_range(size: u64) -> Result<RangeReservation, ReservationError> {
    let size = align_up_to_base_page(size).ok_or(ReservationError::OutOfRange)?;
    KERNEL_RANGE_MANAGER.reserve_auto(size)
}

pub fn reserve_auto_kernel_range_aligned(
    size: u64,
    alignment: u64,
) -> Result<RangeReservation, ReservationError> {
    let size = align_up_to_base_page(size).ok_or(ReservationError::OutOfRange)?;
    KERNEL_RANGE_MANAGER.reserve_auto_aligned(size, alignment)
}

pub fn reserve_kernel_range(base: u64, size: u64) -> Result<RangeReservation, ReservationError> {
    let size = align_up_to_base_page(size).ok_or(ReservationError::OutOfRange)?;
    KERNEL_RANGE_MANAGER.reserve(base, size)
}
