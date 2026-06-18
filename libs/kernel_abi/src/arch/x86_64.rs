use crate::Optional;

pub const KERNEL_PE_BASE: u64 = 0xFFFF_8500_0000_0000;
pub const STUB_IMAGE_BASE: u64 = 0xFFFF_8800_0000_0000;

// Keep the bootloader's dynamic mappings out of the fixed stub image P4 slot.
// The bootloader reserves dynamic virtual space in whole P4 entries, so this
// band deliberately spans several entries for the stack, boot info, framebuffer,
// and any other early mappings it creates before the stub runs.
pub const STUB_DYNAMIC_RANGE_START: u64 = 0xFFFF_8900_0000_0000;
pub const STUB_DYNAMIC_RANGE_END: u64 = 0xFFFF_9000_0000_0000;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ArchInfo {
    pub recursive_index: Optional<u16>,
    pub pe_tls_directory: Optional<PeTlsDirectory>,
}

impl ArchInfo {
    pub const fn empty() -> Self {
        Self {
            recursive_index: Optional::None,
            pe_tls_directory: Optional::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PeTlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}
