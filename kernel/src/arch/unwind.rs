use core::slice;

use kernel_types::memory::Module;

use crate::profiling::backtrace::{BacktraceStatus, StackBounds};

pub const STATUS_BAD_STACK_READ: u32 = 1 << 0;
pub const STATUS_BAD_UNWIND_INFO: u32 = 1 << 1;
pub const STATUS_LEAF_FALLBACK: u32 = 1 << 2;
pub const STATUS_NO_UNWIND_INFO: u32 = 1 << 3;
pub const STATUS_PE_UNWIND: u32 = 1 << 4;
pub const STATUS_UNKNOWN_FRAME: u32 = 1 << 5;
pub const STATUS_UNSUPPORTED_OPCODE: u32 = 1 << 6;

pub struct PeUnwindModule {
    pub image_base: u64,
    pub image_end: u64,
    pub pdata_base: u64,
    pub pdata_len: usize,
}

impl PeUnwindModule {
    pub fn from_module(module: &Module) -> Option<Self> {
        let pe = module.pe_info.as_ref()?;
        let pdata = pe
            .sections
            .iter()
            .find(|section| section.name == ".pdata")?;
        let image_base = module.image_base.as_u64();
        let image_end = image_base.checked_add(module.image_size)?;
        let pdata_base = image_base.checked_add(pdata.virtual_address as u64)?;
        let pdata_len = core::cmp::min(pdata.virtual_size, pdata.raw_size) as usize;
        let pdata_end = pdata_base.checked_add(pdata_len as u64)?;
        (pdata_end <= image_end).then_some(Self {
            image_base,
            image_end,
            pdata_base,
            pdata_len,
        })
    }
}

pub fn backtrace_status(status: u32) -> BacktraceStatus {
    let mut result = BacktraceStatus::empty();
    for (flag, mapped) in [
        (STATUS_BAD_STACK_READ, BacktraceStatus::BAD_STACK_READ),
        (STATUS_BAD_UNWIND_INFO, BacktraceStatus::BAD_UNWIND_INFO),
        (STATUS_LEAF_FALLBACK, BacktraceStatus::LEAF_FALLBACK),
        (STATUS_NO_UNWIND_INFO, BacktraceStatus::NO_UNWIND_INFO),
        (STATUS_PE_UNWIND, BacktraceStatus::PE_UNWIND),
        (STATUS_UNKNOWN_FRAME, BacktraceStatus::UNKNOWN_FRAME),
        (
            STATUS_UNSUPPORTED_OPCODE,
            BacktraceStatus::UNSUPPORTED_OPERATION,
        ),
    ] {
        if status & flag != 0 {
            result |= mapped;
        }
    }
    result
}

pub fn read_image_u32(module: &PeUnwindModule, addr: u64) -> Option<u32> {
    let bytes = read_image_bytes(module, addr, 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn read_image_bytes(module: &PeUnwindModule, addr: u64, len: usize) -> Option<&'static [u8]> {
    let end = addr.checked_add(len as u64)?;
    if addr < module.image_base || end > module.image_end {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(addr as *const u8, len) })
}

pub fn read_stack_u64(bounds: StackBounds, addr: u64) -> Option<u64> {
    let end = addr.checked_add(8)?;
    if addr < bounds.low.as_u64() || end > bounds.high.as_u64() || (addr & 0x7) != 0 {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(addr as *const u64) })
}
