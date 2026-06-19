#[path = "arch/x86_64.rs"]
pub mod x86_64;

pub use x86_64::{
    PeTlsDirectory, X86BootArchInfo, KERNEL_PE_BASE, STUB_DYNAMIC_RANGE_END,
    STUB_DYNAMIC_RANGE_START, STUB_IMAGE_BASE,
};
