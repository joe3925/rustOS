use crate::platform::{DebugTransportPlatform, Platform};
use aarch64_cpu::asm::barrier::{SY, isb};
use aarch64_cpu::registers::VBAR_EL1;
use aarch64_cpu::registers::Writeable;

pub struct Aarch64Platform;

impl Platform for Aarch64Platform {
    type BootArchInfo = kernel_abi::arch::Aarch64BootArchInfo;

    const NAME: &'static str = "aarch64";
    const KERNEL_IMAGE_BASE: u64 = kernel_abi::arch::KERNEL_PE_BASE;

    fn init_early_kernel() {
        VBAR_EL1.set(
            &raw const super::interrupts::entry::aarch64_exception_vectors as u64,
        );
        isb(SY);
    }

    fn init_boot_processor() {
        aarch64_cpu::registers::DAIF.set(0xf << 6);

        <Self as DebugTransportPlatform>::init_debug_metadata_transport();
        super::interrupts::init::init_boot_interrupts();
    }
}
