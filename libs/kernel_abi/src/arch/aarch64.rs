use crate::layout::aarch64::BOOT_VIRTUAL_LAYOUT;
use crate::BootArchInfo;

pub const KERNEL_PE_BASE: u64 = BOOT_VIRTUAL_LAYOUT.kernel_image_base;
pub const STUB_IMAGE_BASE: u64 = BOOT_VIRTUAL_LAYOUT.stub_image_base;

pub const STUB_DYNAMIC_RANGE_START: u64 = BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_start;
pub const STUB_DYNAMIC_RANGE_END: u64 = BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_end;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Aarch64BootArchInfo {
    pub reserved: u64,
}

impl Aarch64BootArchInfo {
    pub const fn empty() -> Self {
        Self { reserved: 0 }
    }
}

impl BootArchInfo for Aarch64BootArchInfo {
    const EMPTY: Self = Self::empty();
}
