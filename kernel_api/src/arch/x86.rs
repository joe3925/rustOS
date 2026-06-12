use kernel_types::arch::{self, PhysAddr, VirtAddr};

#[inline(always)]
pub fn virt_to_phys(mem_offset: VirtAddr, to_phys: VirtAddr) -> Option<PhysAddr> {
    arch::translate_current_virtual_address(mem_offset, to_phys)
        .map(|translation| translation.phys_addr)
}
