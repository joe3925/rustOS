#[cfg(not(target_arch = "x86_64"))]
compile_error!("kernel_abi does not have an implementation for this target architecture");

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
pub mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::{
    ArchInfo, PeTlsDirectory, KERNEL_PE_BASE, STUB_DYNAMIC_RANGE_END, STUB_DYNAMIC_RANGE_START,
    STUB_IMAGE_BASE,
};
