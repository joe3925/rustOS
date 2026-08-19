use crate::platform::Platform;

pub struct Aarch64Platform;

impl Platform for Aarch64Platform {
    type BootArchInfo = kernel_abi::arch::Aarch64BootArchInfo;

    const NAME: &'static str = "aarch64";
    const KERNEL_IMAGE_BASE: u64 = kernel_abi::arch::KERNEL_PE_BASE;

    fn init_boot_processor() {
        todo!()
    }
}
