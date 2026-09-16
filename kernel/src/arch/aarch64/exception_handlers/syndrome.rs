pub(super) const ESR_EL1_EC_SHIFT: u64 = 26;
pub(super) const ESR_EL1_EC_MASK: u64 = 0x3f;
pub(super) const ESR_EL1_ISS_DFSC_MASK: u64 = 0x3f;
pub(super) const ESR_EL1_EC_INSTRUCTION_ABORT_LOWER_EL: u64 = 0b100000;
pub(super) const ESR_EL1_EC_INSTRUCTION_ABORT_CURRENT_EL: u64 = 0b100001;
pub(super) const ESR_EL1_EC_DATA_ABORT_LOWER_EL: u64 = 0b100100;
pub(super) const ESR_EL1_EC_DATA_ABORT_CURRENT_EL: u64 = 0b100101;
pub(super) const ESR_EL1_EC_BREAKPOINT_LOWER_EL: u64 = 0b110000;
pub(super) const ESR_EL1_EC_BREAKPOINT_CURRENT_EL: u64 = 0b110001;
pub(super) const ESR_EL1_EC_SOFTWARE_STEP_LOWER_EL: u64 = 0b110010;
pub(super) const ESR_EL1_EC_SOFTWARE_STEP_CURRENT_EL: u64 = 0b110011;
pub(super) const ESR_EL1_EC_WATCHPOINT_LOWER_EL: u64 = 0b110100;
pub(super) const ESR_EL1_EC_WATCHPOINT_CURRENT_EL: u64 = 0b110101;
pub(super) const ESR_EL1_EC_BRK: u64 = 0b111100;
pub(super) const ESR_EL1_DFSC_TRANSLATION_FAULT_LEVEL_0: u64 = 0b000100;
pub(super) const ESR_EL1_DFSC_TRANSLATION_FAULT_LEVEL_3: u64 = 0b000111;

pub(super) fn exception_class(syndrome: u64) -> u64 {
    (syndrome >> ESR_EL1_EC_SHIFT) & ESR_EL1_EC_MASK
}

pub(super) fn is_translation_fault(syndrome: u64) -> bool {
    (ESR_EL1_DFSC_TRANSLATION_FAULT_LEVEL_0..=ESR_EL1_DFSC_TRANSLATION_FAULT_LEVEL_3)
        .contains(&(syndrome & ESR_EL1_ISS_DFSC_MASK))
}
