use kernel_types::arch::VirtAddr;

use crate::memory::paging::KernelVirtualLayout;

pub const KERNEL_SPACE_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const MMIO_BASE: u64 = 0xFFFF_9000_0000_0000;
pub const MANAGED_KERNEL_RANGE_START: u64 = MMIO_BASE;
pub const MANAGED_KERNEL_RANGE_END: u64 = 0xFFFF_FFFF_8000_0000;
pub const LOW_PHYSICAL_RESERVE_BYTES: u64 = 2 * 1024 * 1024;

pub fn kernel_virtual_layout() -> KernelVirtualLayout {
    KernelVirtualLayout {
        kernel_space_base: VirtAddr::new(KERNEL_SPACE_BASE),
        managed_kernel_range_start: VirtAddr::new(MANAGED_KERNEL_RANGE_START),
        managed_kernel_range_end: VirtAddr::new(MANAGED_KERNEL_RANGE_END),
        mmio_base: VirtAddr::new(MMIO_BASE),
        low_physical_reserve_bytes: LOW_PHYSICAL_RESERVE_BYTES,
    }
}
