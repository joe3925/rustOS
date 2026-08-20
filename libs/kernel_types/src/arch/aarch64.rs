use crate::arch::PagingPlatform;
use crate::arch::PhysAddr;
use crate::arch::PlatformInfo;
use crate::arch::TranslatedBlock;
use crate::arch::VirtAddr;
pub struct Platform;

pub type X86Platform = Platform;
impl PlatformInfo for Platform {
    const NAME: &'static str = "x86_64";

    fn cycle_counter() -> u64 {
        let value: u64;

        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {value}, cntvct_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags)
            );
        }

        value
    }
}

impl PagingPlatform for Platform {
    fn translate_addr(addr: VirtAddr) -> Option<TranslatedBlock> {
        sys_resolve_virtual_range_frame(addr).map(|(block_size, phys_addr)| TranslatedBlock {
            phys_addr,
            block_size,
        })
    }
}
#[cfg(any(test, feature = "hosted-tests"))]
fn sys_resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    Some((Size4KiB::SIZE, PhysAddr::new(addr.as_u64())))
}

#[cfg(not(any(test, feature = "hosted-tests")))]
fn sys_resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    unsafe extern "C" {
        fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)>;
    }

    unsafe { resolve_virtual_range_frame(addr) }
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __chkstk() {
    core::arch::naked_asm!(
        "mov x16, sp",
        "mov x17, x15",
        "lsl x17, x17, #4",
        "cmp x17, #0x1000",
        "b.lo 2f",
        "1:",
        "sub x16, x16, #0x1000",
        "ldr xzr, [x16]",
        "sub x17, x17, #0x1000",
        "cmp x17, #0x1000",
        "b.hs 1b",
        "2:",
        "sub x16, x16, x17",
        "ldr xzr, [x16]",
        "ret"
    );
}
