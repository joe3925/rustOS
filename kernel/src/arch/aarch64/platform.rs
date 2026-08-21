use core::arch::asm;

use crate::platform::{DebugTransportPlatform, Platform};

pub struct Aarch64Platform;

impl Platform for Aarch64Platform {
    type BootArchInfo = kernel_abi::arch::Aarch64BootArchInfo;

    const NAME: &'static str = "aarch64";
    const KERNEL_IMAGE_BASE: u64 = kernel_abi::arch::KERNEL_PE_BASE;

    fn init_boot_processor() {
        unsafe {
            asm!(
                "msr daifset, #0xf",
                options(nomem, nostack, preserves_flags)
            );
        }

        <Self as DebugTransportPlatform>::init_debug_metadata_transport();

        // TODO: Install the EL1 exception vector table in VBAR_EL1.
        // TODO: Initialize the boot CPU GIC interface and interrupt distributor.
        // TODO: Initialize the AArch64 synchronous exception and syscall path.
    }
}
