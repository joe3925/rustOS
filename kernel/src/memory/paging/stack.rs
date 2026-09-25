use kernel_types::arch::{PageFlags, VirtAddr};
use kernel_types::memory::RangeReservation;
use kernel_types::status::PageMapError;

use super::layout::{align_up, base_page_size, supported_mapping_sizes};
use super::map::{map_kernel_range, unmap_kernel_reserved_range_unchecked};
use super::virt_tracker::reserve_auto_kernel_range_aligned;

#[derive(Debug)]
pub struct KernelStack {
    reservation: RangeReservation,
}

impl KernelStack {
    pub fn top(&self) -> VirtAddr {
        self.reservation.end()
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        unsafe {
            unmap_kernel_reserved_range_unchecked(
                self.reservation.start(),
                self.reservation.size(),
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StackSize {
    Tiny,
    Small,
    Medium,
    Large,
    #[default]
    Huge,
}

impl StackSize {
    #[inline]
    pub fn as_bytes(self) -> u64 {
        match self {
            Self::Tiny => 4 * 1024,
            Self::Small => 8 * 1024,
            Self::Medium => 16 * 1024,
            Self::Large => 64 * 1024,
            Self::Huge => 16 * 1024 * 1024,
        }
    }

    #[inline]
    pub fn total_size_with_guard(self) -> u64 {
        self.as_bytes() + base_page_size()
    }

    #[inline]
    pub fn required_alignment(self) -> u64 {
        required_alignment_for_bytes(self.as_bytes())
    }
}

fn required_alignment_for_bytes(bytes: u64) -> u64 {
    for size in supported_mapping_sizes() {
        if bytes >= size.bytes {
            return size.bytes;
        }
    }
    base_page_size()
}

pub fn kernel_stack_max_bytes() -> u64 {
    StackSize::Huge.as_bytes()
}

pub fn kernel_stack_reservation_bytes() -> u64 {
    kernel_stack_max_bytes() + base_page_size()
}

pub fn allocate_kernel_stack(size: StackSize) -> Result<KernelStack, PageMapError> {
    let max_stack = kernel_stack_max_bytes();
    let reserve_total = kernel_stack_reservation_bytes();

    let map_bytes = {
        let bytes = align_up(size.as_bytes(), base_page_size()).ok_or(PageMapError::NoMemory())?;
        if bytes > max_stack { max_stack } else { bytes }
    };

    let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE;

    let reservation = reserve_auto_kernel_range_aligned(
        reserve_total,
        required_alignment_for_bytes(max_stack),
    )
    .map_err(|_| PageMapError::NoMemory())?;
    let region_base = reservation.start();
    let stack_top = reservation.end();
    let map_start = VirtAddr::new(stack_top.as_u64() - map_bytes);

    if let Err(err) = unsafe { map_kernel_range(map_start, map_bytes, flags, false) } {
        return Err(err);
    }

    Ok(KernelStack { reservation })
}
