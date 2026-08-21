use crate::platform::{AddressSpacePlatform, DebugTransportPlatform, InterruptPlatform, Platform};

pub struct X86Platform;

impl Platform for X86Platform {
    type BootArchInfo = kernel_abi::arch::X86BootArchInfo;

    const NAME: &'static str = "x86_64";
    const KERNEL_IMAGE_BASE: u64 = kernel_abi::arch::KERNEL_PE_BASE;

    fn init_boot_processor() {
        super::idt::load_idt();
        Self::init_kernel_root();
        unsafe {
            super::gdt::PER_CPU_GDT.lock().init_gdt();
            super::drivers::interrupt_index::PICS.lock().initialize();
        }
        Self::disable_interrupts();
        super::syscalls::syscall::syscall_init();
        <Self as DebugTransportPlatform>::init_debug_metadata_transport();
    }
}
