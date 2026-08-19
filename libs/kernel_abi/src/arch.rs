#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    PeTlsDirectory, X86BootArchInfo, KERNEL_PE_BASE, STUB_DYNAMIC_RANGE_END,
    STUB_DYNAMIC_RANGE_START, STUB_IMAGE_BASE,
};

#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    Aarch64BootArchInfo, Aarch64PeTlsDirectory, RawTableFrameProvider, RecursiveFrameZeroProvider,
    KERNEL_PE_BASE, STUB_DYNAMIC_RANGE_END, STUB_DYNAMIC_RANGE_START, STUB_IMAGE_BASE,
};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("kernel_abi does not support this target architecture");
