use crate::layout::aarch64::BOOT_VIRTUAL_LAYOUT;
use crate::{BootArchInfo, Optional};

pub const KERNEL_PE_BASE: u64 = BOOT_VIRTUAL_LAYOUT.kernel_image_base;
pub const STUB_IMAGE_BASE: u64 = BOOT_VIRTUAL_LAYOUT.stub_image_base;

pub const STUB_DYNAMIC_RANGE_START: u64 = BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_start;
pub const STUB_DYNAMIC_RANGE_END: u64 = BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_end;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Aarch64BootArchInfo {
    pub root_table: u64,
    pub physical_memory_offset: u64,
    pub physical_memory_len: u64,
    pub granule_shift: u8,
    pub input_addr_bits: u8,
    pub output_addr_bits: u8,
    pub mair_el1: u64,
    pub tcr_el1: u64,
    pub tcr2_el1: u64,
    pub ttbr1_el1: u64,
    pub pe_tls_directory: Optional<Aarch64PeTlsDirectory>,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Aarch64PeTlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

impl Aarch64BootArchInfo {
    pub const fn empty() -> Self {
        Self {
            root_table: 0,
            physical_memory_offset: 0,
            physical_memory_len: 0,
            granule_shift: 0,
            input_addr_bits: 0,
            output_addr_bits: 0,
            mair_el1: 0,
            tcr_el1: 0,
            tcr2_el1: 0,
            ttbr1_el1: 0,
            pe_tls_directory: Optional::None,
        }
    }
}

impl BootArchInfo for Aarch64BootArchInfo {
    const EMPTY: Self = Self::empty();
}
