use kernel_types::arch::{PhysAddr, VirtAddr};

#[inline(always)]
pub fn virt_to_phys(to_phys: VirtAddr) -> Option<(u64, PhysAddr)> {
    unsafe { kernel_sys::virt_to_phys(to_phys) }
}
