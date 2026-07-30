use core::slice;

use kernel_types::arch::VirtAddr;
use kernel_types::memory::Module;

use crate::platform::UnwindPlatform;
use crate::profiling::backtrace::{BacktraceStatus, StackBounds, UnwindStart, UnwindStep};

use super::platform::X86Platform;
use super::scheduling::state::State;

const STATUS_BAD_STACK_READ: u32 = 1 << 0;
const STATUS_BAD_UNWIND_INFO: u32 = 1 << 1;
const STATUS_LEAF_FALLBACK: u32 = 1 << 2;
const STATUS_NO_UNWIND_INFO: u32 = 1 << 3;
const STATUS_PE_UNWIND: u32 = 1 << 4;
const STATUS_UNKNOWN_FRAME: u32 = 1 << 5;
const STATUS_UNSUPPORTED_OPCODE: u32 = 1 << 6;

const UNW_FLAG_EHANDLER: u8 = 0x1;
const UNW_FLAG_UHANDLER: u8 = 0x2;
const UNW_FLAG_CHAININFO: u8 = 0x4;

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

#[derive(Clone, Copy)]
struct RuntimeFunction {
    begin_rva: u32,
    end_rva: u32,
    unwind_rva: u32,
}

struct PeUnwindModule {
    image_base: u64,
    image_end: u64,
    pdata_base: u64,
    pdata_len: usize,
}

impl PeUnwindModule {
    fn from_module(module: &Module) -> Option<Self> {
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
        (pdata_len >= 12 && pdata_end <= image_end).then_some(Self {
            image_base,
            image_end,
            pdata_base,
            pdata_len,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnwindFinish {
    NeedsReturnAddress,
    ContextIsCaller,
}

impl UnwindPlatform for X86Platform {
    type UnwindContext = UnwindContext;

    fn begin_current_unwind() -> UnwindStart<Self::UnwindContext> {
        let mut context = UnwindContext {
            rip: 0,
            rsp: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip_is_return_address: false,
        };
        let context_ptr = &mut context as *mut UnwindContext;

        unsafe {
            core::arch::asm!(
                "lea rax, [rip + 2f]",
                "mov [rcx + {rip}], rax",
                "mov [rcx + {rsp}], rsp",
                "mov [rcx + {rbx}], rbx",
                "mov [rcx + {rbp}], rbp",
                "mov [rcx + {rsi}], rsi",
                "mov [rcx + {rdi}], rdi",
                "mov [rcx + {r12}], r12",
                "mov [rcx + {r13}], r13",
                "mov [rcx + {r14}], r14",
                "mov [rcx + {r15}], r15",
                "2:",
                in("rcx") context_ptr,
                rip = const core::mem::offset_of!(UnwindContext, rip),
                rsp = const core::mem::offset_of!(UnwindContext, rsp),
                rbx = const core::mem::offset_of!(UnwindContext, rbx),
                rbp = const core::mem::offset_of!(UnwindContext, rbp),
                rsi = const core::mem::offset_of!(UnwindContext, rsi),
                rdi = const core::mem::offset_of!(UnwindContext, rdi),
                r12 = const core::mem::offset_of!(UnwindContext, r12),
                r13 = const core::mem::offset_of!(UnwindContext, r13),
                r14 = const core::mem::offset_of!(UnwindContext, r14),
                r15 = const core::mem::offset_of!(UnwindContext, r15),
                lateout("rax") _,
                options(nostack, preserves_flags),
            );
        }

        UnwindStart {
            pc: VirtAddr::new(context.rip),
            context,
        }
    }

    fn begin_unwind(state: &State) -> UnwindStart<Self::UnwindContext> {
        UnwindStart {
            context: UnwindContext::from_state(state),
            pc: VirtAddr::new(state.rip),
        }
    }

    fn unwind_next(
        context: &mut Self::UnwindContext,
        module: Option<&Module>,
        stack_bounds: StackBounds,
    ) -> UnwindStep {
        let before_rip = context.rip;
        let before_rsp = context.rsp;
        let control_pc = context.control_pc();
        let status = match module.and_then(PeUnwindModule::from_module) {
            Some(module) => unwind_pe_x64(context, stack_bounds, control_pc, &module),
            None => {
                let status = STATUS_UNKNOWN_FRAME | STATUS_NO_UNWIND_INFO | STATUS_LEAF_FALLBACK;
                leaf_unwind(context, stack_bounds)
                    .map_or(status | STATUS_BAD_STACK_READ, |_| status)
            }
        };
        let pc = (context.rip != 0
            && is_canonical(context.rip)
            && (context.rip != before_rip || context.rsp != before_rsp))
            .then(|| VirtAddr::new(context.rip));
        UnwindStep {
            pc,
            status: backtrace_status(status),
        }
    }
}

fn backtrace_status(status: u32) -> BacktraceStatus {
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

fn unwind_pe_x64(
    ctx: &mut UnwindContext,
    bounds: StackBounds,
    control_pc: u64,
    module: &PeUnwindModule,
) -> u32 {
    if control_pc < module.image_base || control_pc >= module.image_end {
        let status = STATUS_NO_UNWIND_INFO | STATUS_LEAF_FALLBACK;
        return leaf_unwind(ctx, bounds).map_or(status | STATUS_BAD_STACK_READ, |_| status);
    }

    let rva = (control_pc - module.image_base) as u32;
    let Some(mut rf) = lookup_runtime_function(module, rva) else {
        let status = STATUS_NO_UNWIND_INFO | STATUS_LEAF_FALLBACK;
        return leaf_unwind(ctx, bounds).map_or(status | STATUS_BAD_STACK_READ, |_| status);
    };

    let mut status = STATUS_PE_UNWIND;

    if let Some(epilog_status) = try_unwind_epilog(module, control_pc, ctx, bounds) {
        return status | epilog_status;
    }

    for _ in 0..8 {
        let (flags, chained, finish, op_status) = process_unwind_info(module, rf, rva, ctx, bounds);

        status |= op_status;

        if status & (STATUS_BAD_UNWIND_INFO | STATUS_BAD_STACK_READ | STATUS_UNSUPPORTED_OPCODE)
            != 0
        {
            return status;
        }

        if finish == UnwindFinish::ContextIsCaller {
            return status;
        }

        if flags & UNW_FLAG_CHAININFO == 0 {
            return leaf_unwind(ctx, bounds).map_or(status | STATUS_BAD_STACK_READ, |_| status);
        }

        let Some(next) = chained else {
            return status | STATUS_BAD_UNWIND_INFO;
        };

        rf = next;
    }

    status | STATUS_BAD_UNWIND_INFO
}

fn lookup_runtime_function(module: &PeUnwindModule, rva: u32) -> Option<RuntimeFunction> {
    let mut lo = 0usize;
    let mut hi = module.pdata_len / 12;

    while lo < hi {
        let mid = (lo + hi) / 2;
        let address = module.pdata_base.checked_add((mid * 12) as u64)?;
        let f = RuntimeFunction {
            begin_rva: read_image_u32(module, address)?,
            end_rva: read_image_u32(module, address.checked_add(4)?)?,
            unwind_rva: read_image_u32(module, address.checked_add(8)?)?,
        };
        if f.end_rva <= f.begin_rva
            || f.end_rva as u64 > module.image_end - module.image_base
            || f.unwind_rva == 0
            || f.unwind_rva as u64 >= module.image_end - module.image_base
        {
            return None;
        }

        if rva < f.begin_rva {
            hi = mid;
        } else if rva >= f.end_rva {
            lo = mid + 1;
        } else {
            return Some(f);
        }
    }

    None
}

fn process_unwind_info(
    module: &PeUnwindModule,
    rf: RuntimeFunction,
    rva: u32,
    ctx: &mut UnwindContext,
    bounds: StackBounds,
) -> (u8, Option<RuntimeFunction>, UnwindFinish, u32) {
    let info = module.image_base.saturating_add(rf.unwind_rva as u64);
    let Some(header) = read_image_bytes(module, info, 4) else {
        return (
            0,
            None,
            UnwindFinish::NeedsReturnAddress,
            STATUS_BAD_UNWIND_INFO,
        );
    };

    let version = header[0] & 0x7;
    let flags = header[0] >> 3;
    let prolog_size = header[1] as u32;
    let code_count = header[2] as usize;
    let frame_reg = header[3] & 0x0f;
    let frame_off = (header[3] >> 4) as u64 * 16;

    if version != 1 {
        return (
            flags,
            None,
            UnwindFinish::NeedsReturnAddress,
            STATUS_BAD_UNWIND_INFO,
        );
    }

    if flags & UNW_FLAG_CHAININFO != 0 && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        return (
            flags,
            None,
            UnwindFinish::NeedsReturnAddress,
            STATUS_BAD_UNWIND_INFO,
        );
    }

    let function_offset = rva.saturating_sub(rf.begin_rva);
    let in_prolog = function_offset < prolog_size;
    let frame_base = if frame_reg != 0 {
        ctx.get_reg(frame_reg)
            .and_then(|v| v.checked_sub(frame_off))
            .unwrap_or(ctx.rsp)
    } else {
        ctx.rsp
    };

    let mut idx = 0usize;
    let mut status = 0u32;

    while idx < code_count {
        let Some((code_offset, op, op_info)) = read_unwind_code(module, info, idx) else {
            return (
                flags,
                None,
                UnwindFinish::NeedsReturnAddress,
                status | STATUS_BAD_UNWIND_INFO,
            );
        };

        idx += 1;

        let apply = !in_prolog || code_offset as u32 <= function_offset;

        match op {
            UWOP_PUSH_NONVOL => {
                if apply {
                    match read_stack_u64(bounds, ctx.rsp) {
                        Some(value) => {
                            ctx.set_reg(op_info, value);
                            ctx.rsp = ctx.rsp.saturating_add(8);
                        }
                        None => status |= STATUS_BAD_STACK_READ,
                    }
                }
            }
            UWOP_ALLOC_LARGE => {
                let needed = if op_info == 0 { 1 } else { 2 };
                if op_info > 1 || idx.checked_add(needed).is_none_or(|end| end > code_count) {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                }

                let Some(size) = read_alloc_large_size(module, info, idx, op_info) else {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                };

                idx += needed;

                if apply {
                    ctx.rsp = ctx.rsp.saturating_add(size as u64);
                }
            }
            UWOP_ALLOC_SMALL => {
                if apply {
                    ctx.rsp = ctx.rsp.saturating_add((op_info as u64 * 8) + 8);
                }
            }
            UWOP_SET_FPREG => {
                if apply {
                    ctx.rsp = frame_base;
                }
            }
            UWOP_SAVE_NONVOL => {
                if idx >= code_count {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                }

                let Some(slot) = read_unwind_u16_slot(module, info, idx) else {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                };

                idx += 1;

                if apply {
                    let addr = frame_base.saturating_add(slot as u64 * 8);
                    match read_stack_u64(bounds, addr) {
                        Some(value) => ctx.set_reg(op_info, value),
                        None => status |= STATUS_BAD_STACK_READ,
                    }
                }
            }
            UWOP_SAVE_NONVOL_FAR => {
                if idx.checked_add(2).is_none_or(|end| end > code_count) {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                }

                let Some(slot) = read_unwind_u32_slot(module, info, idx) else {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                };

                idx += 2;

                if apply {
                    let addr = frame_base.saturating_add(slot as u64);
                    match read_stack_u64(bounds, addr) {
                        Some(value) => ctx.set_reg(op_info, value),
                        None => status |= STATUS_BAD_STACK_READ,
                    }
                }
            }
            UWOP_SAVE_XMM128 => {
                if idx >= code_count {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                }

                idx += 1;
            }
            UWOP_SAVE_XMM128_FAR => {
                if idx.checked_add(2).is_none_or(|end| end > code_count) {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | STATUS_BAD_UNWIND_INFO,
                    );
                }

                idx += 2;
            }
            UWOP_PUSH_MACHFRAME => {
                if apply {
                    let error_code = op_info != 0;
                    match unwind_machine_frame(ctx, bounds, error_code) {
                        Some(()) => {
                            return (flags, None, UnwindFinish::ContextIsCaller, status);
                        }
                        None => status |= STATUS_BAD_STACK_READ,
                    }
                }
            }
            _ => {
                return (
                    flags,
                    None,
                    UnwindFinish::NeedsReturnAddress,
                    status | STATUS_UNSUPPORTED_OPCODE | STATUS_BAD_UNWIND_INFO,
                );
            }
        }

        if status & STATUS_BAD_STACK_READ != 0 {
            return (flags, None, UnwindFinish::NeedsReturnAddress, status);
        }
    }

    let chained = if flags & UNW_FLAG_CHAININFO != 0 {
        read_chained_runtime_function(module, info, code_count)
    } else {
        None
    };

    (flags, chained, UnwindFinish::NeedsReturnAddress, status)
}

fn try_unwind_epilog(
    module: &PeUnwindModule,
    control_pc: u64,
    ctx: &mut UnwindContext,
    bounds: StackBounds,
) -> Option<u32> {
    let bytes = read_image_bytes(module, control_pc, 32)?;
    let mut tmp = *ctx;
    let mut idx = 0usize;
    let mut consumed_any = false;

    loop {
        if idx >= bytes.len() {
            return None;
        }

        if let Some((new_rsp, consumed)) = decode_add_rsp(bytes, idx, tmp.rsp) {
            tmp.rsp = new_rsp;
            idx += consumed;
            consumed_any = true;
            continue;
        }

        if let Some((new_rsp, consumed)) = decode_lea_rsp(bytes, idx, &tmp) {
            tmp.rsp = new_rsp;
            idx += consumed;
            consumed_any = true;
            continue;
        }

        if let Some((reg, consumed)) = decode_pop_reg(bytes, idx) {
            let Some(value) = read_stack_u64(bounds, tmp.rsp) else {
                return Some(STATUS_BAD_STACK_READ);
            };

            tmp.set_reg(reg, value);
            tmp.rsp = tmp.rsp.saturating_add(8);
            idx += consumed;
            consumed_any = true;
            continue;
        }

        if bytes[idx] == 0xc3 {
            let Some(rip) = read_stack_u64(bounds, tmp.rsp) else {
                return Some(STATUS_BAD_STACK_READ);
            };

            tmp.rsp = tmp.rsp.saturating_add(8);
            tmp.rip = rip;
            tmp.rip_is_return_address = true;
            *ctx = tmp;
            return Some(0);
        }

        if bytes[idx] == 0xc2 {
            if idx + 2 >= bytes.len() {
                return None;
            }

            let stack_adjust = u16::from_le_bytes([bytes[idx + 1], bytes[idx + 2]]) as u64;
            let Some(rip) = read_stack_u64(bounds, tmp.rsp) else {
                return Some(STATUS_BAD_STACK_READ);
            };

            tmp.rsp = tmp.rsp.saturating_add(8).saturating_add(stack_adjust);
            tmp.rip = rip;
            tmp.rip_is_return_address = true;
            *ctx = tmp;
            return Some(0);
        }

        return if consumed_any { None } else { None };
    }
}

fn decode_add_rsp(bytes: &[u8], idx: usize, rsp: u64) -> Option<(u64, usize)> {
    if idx + 3 < bytes.len()
        && bytes[idx] == 0x48
        && bytes[idx + 1] == 0x83
        && bytes[idx + 2] == 0xc4
    {
        let imm = bytes[idx + 3] as i8 as i64;
        return add_signed_u64(rsp, imm).map(|value| (value, 4));
    }

    if idx + 6 < bytes.len()
        && bytes[idx] == 0x48
        && bytes[idx + 1] == 0x81
        && bytes[idx + 2] == 0xc4
    {
        let imm = i32::from_le_bytes([
            bytes[idx + 3],
            bytes[idx + 4],
            bytes[idx + 5],
            bytes[idx + 6],
        ]) as i64;

        return add_signed_u64(rsp, imm).map(|value| (value, 7));
    }

    None
}

fn decode_lea_rsp(bytes: &[u8], idx: usize, ctx: &UnwindContext) -> Option<(u64, usize)> {
    if idx + 3 >= bytes.len() {
        return None;
    }

    let rex = bytes[idx];
    if rex & 0xf0 != 0x40 || rex & 0x08 == 0 || rex & 0x04 != 0 {
        return None;
    }

    if bytes[idx + 1] != 0x8d {
        return None;
    }

    let modrm = bytes[idx + 2];
    let mode = modrm >> 6;
    let reg = (modrm >> 3) & 0x7;
    let rm = modrm & 0x7;

    if reg != 4 || rm == 4 {
        return None;
    }

    let base_reg = rm | ((rex & 0x01) << 3);
    let base = ctx.get_reg(base_reg)?;

    match mode {
        1 => {
            if idx + 3 >= bytes.len() {
                return None;
            }

            let disp = bytes[idx + 3] as i8 as i64;
            add_signed_u64(base, disp).map(|value| (value, 4))
        }
        2 => {
            if idx + 6 >= bytes.len() {
                return None;
            }

            let disp = i32::from_le_bytes([
                bytes[idx + 3],
                bytes[idx + 4],
                bytes[idx + 5],
                bytes[idx + 6],
            ]) as i64;

            add_signed_u64(base, disp).map(|value| (value, 7))
        }
        _ => None,
    }
}

fn decode_pop_reg(bytes: &[u8], idx: usize) -> Option<(u8, usize)> {
    if idx >= bytes.len() {
        return None;
    }

    let byte = bytes[idx];
    if (0x58..=0x5f).contains(&byte) {
        return Some((byte - 0x58, 1));
    }

    if idx + 1 >= bytes.len() {
        return None;
    }

    let rex = bytes[idx];
    let next = bytes[idx + 1];

    if rex & 0xf0 == 0x40 && rex & 0x01 != 0 && (0x58..=0x5f).contains(&next) {
        return Some((8 + next - 0x58, 2));
    }

    None
}

fn unwind_machine_frame(
    ctx: &mut UnwindContext,
    bounds: StackBounds,
    error_code: bool,
) -> Option<()> {
    let frame = if error_code {
        ctx.rsp.checked_add(8)?
    } else {
        ctx.rsp
    };

    let rip = read_stack_u64(bounds, frame)?;
    let old_rsp = read_stack_u64(bounds, frame.checked_add(0x18)?)?;

    ctx.rip = rip;
    ctx.rsp = old_rsp;
    ctx.rip_is_return_address = false;

    Some(())
}

fn add_signed_u64(value: u64, offset: i64) -> Option<u64> {
    if offset >= 0 {
        value.checked_add(offset as u64)
    } else {
        value.checked_sub(offset.unsigned_abs())
    }
}

fn read_chained_runtime_function(
    module: &PeUnwindModule,
    info: u64,
    code_count: usize,
) -> Option<RuntimeFunction> {
    let aligned_count = (code_count + 1) & !1;
    let addr = info.checked_add(4 + (aligned_count * 2) as u64)?;

    let begin_rva = read_image_u32(module, addr)?;
    let end_rva = read_image_u32(module, addr + 4)?;
    let unwind_rva = read_image_u32(module, addr + 8)?;

    if begin_rva == 0 || end_rva <= begin_rva || unwind_rva == 0 {
        return None;
    }

    Some(RuntimeFunction {
        begin_rva,
        end_rva,
        unwind_rva,
    })
}

fn read_unwind_code(module: &PeUnwindModule, info: u64, idx: usize) -> Option<(u8, u8, u8)> {
    let slot = info.checked_add(4 + (idx * 2) as u64)?;
    let bytes = read_image_bytes(module, slot, 2)?;
    Some((bytes[0], bytes[1] & 0x0f, bytes[1] >> 4))
}

fn read_alloc_large_size(
    module: &PeUnwindModule,
    info: u64,
    idx: usize,
    op_info: u8,
) -> Option<u32> {
    match op_info {
        0 => read_unwind_u16_slot(module, info, idx).map(|v| v as u32 * 8),
        1 => read_unwind_u32_slot(module, info, idx),
        _ => None,
    }
}

fn read_unwind_u16_slot(module: &PeUnwindModule, info: u64, idx: usize) -> Option<u16> {
    let slot = info.checked_add(4 + (idx * 2) as u64)?;
    let bytes = read_image_bytes(module, slot, 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_unwind_u32_slot(module: &PeUnwindModule, info: u64, idx: usize) -> Option<u32> {
    let slot = info.checked_add(4 + (idx * 2) as u64)?;
    read_image_u32(module, slot)
}

fn read_image_u32(module: &PeUnwindModule, addr: u64) -> Option<u32> {
    let bytes = read_image_bytes(module, addr, 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_image_bytes(module: &PeUnwindModule, addr: u64, len: usize) -> Option<&'static [u8]> {
    let end = addr.checked_add(len as u64)?;

    if addr < module.image_base || end > module.image_end {
        return None;
    }

    Some(unsafe { slice::from_raw_parts(addr as *const u8, len) })
}

fn leaf_unwind(ctx: &mut UnwindContext, bounds: StackBounds) -> Option<()> {
    let rip = read_stack_u64(bounds, ctx.rsp)?;
    ctx.rsp = ctx.rsp.checked_add(8)?;
    ctx.rip = rip;
    ctx.rip_is_return_address = true;
    Some(())
}

fn read_stack_u64(bounds: StackBounds, addr: u64) -> Option<u64> {
    let end = addr.checked_add(8)?;

    if addr < bounds.low.as_u64() || end > bounds.high.as_u64() || (addr & 0x7) != 0 {
        return None;
    }

    Some(unsafe { core::ptr::read_unaligned(addr as *const u64) })
}

fn is_canonical(addr: u64) -> bool {
    let high = addr >> 48;
    let sign = (addr >> 47) & 1;
    (sign == 0 && high == 0) || (sign == 1 && high == 0xffff)
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct UnwindContext {
    rip: u64,
    rsp: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip_is_return_address: bool,
}

impl UnwindContext {
    fn from_state(state: &State) -> Self {
        Self {
            rip: state.rip,
            rsp: state.rsp,
            rbx: state.rbx,
            rbp: state.rbp,
            rsi: state.rsi,
            rdi: state.rdi,
            r12: state.r12,
            r13: state.r13,
            r14: state.r14,
            r15: state.r15,
            rip_is_return_address: false,
        }
    }

    fn control_pc(&self) -> u64 {
        if self.rip_is_return_address {
            self.rip.saturating_sub(1)
        } else {
            self.rip
        }
    }

    fn get_reg(&self, reg: u8) -> Option<u64> {
        match reg {
            3 => Some(self.rbx),
            5 => Some(self.rbp),
            6 => Some(self.rsi),
            7 => Some(self.rdi),
            12 => Some(self.r12),
            13 => Some(self.r13),
            14 => Some(self.r14),
            15 => Some(self.r15),
            _ => None,
        }
    }

    fn set_reg(&mut self, reg: u8, value: u64) {
        match reg {
            3 => self.rbx = value,
            5 => self.rbp = value,
            6 => self.rsi = value,
            7 => self.rdi = value,
            12 => self.r12 = value,
            13 => self.r13 = value,
            14 => self.r14 = value,
            15 => self.r15 = value,
            _ => {}
        }
    }
}
