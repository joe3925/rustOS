use alloc::vec::Vec;
use core::{slice, sync::atomic::Ordering};

use kernel_abi::KernelSection;
use kernel_types::benchmark::{
    BENCH_FRAME_KIND_PE_X64, BENCH_FRAME_KIND_UNKNOWN, BENCH_UNWIND_STATUS_BAD_STACK_READ,
    BENCH_UNWIND_STATUS_BAD_UNWIND_INFO, BENCH_UNWIND_STATUS_LEAF_FALLBACK,
    BENCH_UNWIND_STATUS_NO_UNWIND_INFO, BENCH_UNWIND_STATUS_PE_UNWIND,
    BENCH_UNWIND_STATUS_STACK_BOUNDS_MISSING, BENCH_UNWIND_STATUS_TRUNCATED,
    BENCH_UNWIND_STATUS_UNKNOWN_FRAME, BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE,
};
use kernel_types::memory::PeSectionInfo;
use spin::RwLock;

use crate::scheduling::state::State;
use crate::scheduling::task::TaskRef;

pub const MAX_CALLCHAIN_DEPTH: usize = 64;

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
pub struct StackBounds {
    pub low: u64,
    pub high: u64,
}

#[derive(Clone, Copy)]
pub struct CapturedCallchain {
    pub frames: [u64; MAX_CALLCHAIN_DEPTH],
    pub frame_kinds: [u32; MAX_CALLCHAIN_DEPTH],
    pub depth: u8,
    pub status: u32,
    pub stack_low: u64,
    pub stack_high: u64,
}

impl Default for CapturedCallchain {
    fn default() -> Self {
        Self {
            frames: [0; MAX_CALLCHAIN_DEPTH],
            frame_kinds: [BENCH_FRAME_KIND_UNKNOWN; MAX_CALLCHAIN_DEPTH],
            depth: 0,
            status: 0,
            stack_low: 0,
            stack_high: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct RuntimeFunction {
    begin_rva: u32,
    end_rva: u32,
    unwind_rva: u32,
}

struct PeUnwindModule {
    image_base: u64,
    image_end: u64,
    functions: Vec<RuntimeFunction>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnwindFinish {
    NeedsReturnAddress,
    ContextIsCaller,
}

static PE_UNWIND_MODULES: RwLock<Vec<PeUnwindModule>> = RwLock::new(Vec::new());

pub fn register_pe_unwind_module(image_base: u64, image_size: u64, sections: &[PeSectionInfo]) {
    let Some(pdata) = sections.iter().find(|s| s.name == ".pdata") else {
        return;
    };

    let text_virtual_address = sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| s.virtual_address);

    let section_image_size = sections
        .iter()
        .filter_map(|s| {
            let size = core::cmp::max(s.virtual_size, s.raw_size);
            s.virtual_address.checked_add(size)
        })
        .max()
        .unwrap_or(image_size as u32) as u64;

    register_pe_unwind_module_from_pdata(
        image_base,
        core::cmp::max(image_size, section_image_size),
        pdata.virtual_address,
        pdata.virtual_size,
        pdata.raw_size,
        text_virtual_address,
    );
}

pub fn register_kernel_pe_unwind_module(
    image_base: u64,
    image_size: u64,
    sections: &[KernelSection],
) {
    let Some(pdata) = sections
        .iter()
        .find(|section| pe_section_name_eq(&section.name, b".pdata"))
    else {
        return;
    };

    let text_virtual_address = sections
        .iter()
        .find(|section| pe_section_name_eq(&section.name, b".text"))
        .map(|section| section.virtual_address);

    let section_image_size = sections
        .iter()
        .filter_map(|section| {
            let size = core::cmp::max(section.virtual_size, section.raw_size);
            section.virtual_address.checked_add(size)
        })
        .max()
        .unwrap_or(image_size as u32) as u64;

    register_pe_unwind_module_from_pdata(
        image_base,
        core::cmp::max(image_size, section_image_size),
        pdata.virtual_address,
        pdata.virtual_size,
        pdata.raw_size,
        text_virtual_address,
    );
}

fn register_pe_unwind_module_from_pdata(
    image_base: u64,
    image_size: u64,
    pdata_virtual_address: u32,
    pdata_virtual_size: u32,
    pdata_raw_size: u32,
    text_virtual_address: Option<u32>,
) {
    let mut best_base = image_base;
    let mut best_functions = collect_runtime_functions(
        image_base,
        image_size,
        pdata_virtual_address,
        pdata_virtual_size,
        pdata_raw_size,
    );

    if let Some(text_virtual_address) = text_virtual_address {
        if text_virtual_address != 0 {
            if let Some(adjusted_base) = image_base.checked_sub(text_virtual_address as u64) {
                let adjusted_functions = collect_runtime_functions(
                    adjusted_base,
                    image_size,
                    pdata_virtual_address,
                    pdata_virtual_size,
                    pdata_raw_size,
                );

                if runtime_function_score(&adjusted_functions)
                    > runtime_function_score(&best_functions)
                {
                    best_base = adjusted_base;
                    best_functions = adjusted_functions;
                }
            }
        }
    }

    if best_functions.is_empty() {
        return;
    }

    best_functions.sort_unstable_by(|a, b| {
        a.begin_rva
            .cmp(&b.begin_rva)
            .then_with(|| a.end_rva.cmp(&b.end_rva))
            .then_with(|| a.unwind_rva.cmp(&b.unwind_rva))
    });

    let mut modules = PE_UNWIND_MODULES.write();
    if let Some(slot) = modules.iter_mut().find(|m| m.image_base == best_base) {
        slot.image_end = best_base.saturating_add(image_size);
        slot.functions = best_functions;
    } else {
        modules.push(PeUnwindModule {
            image_base: best_base,
            image_end: best_base.saturating_add(image_size),
            functions: best_functions,
        });
    }
}

fn collect_runtime_functions(
    image_base: u64,
    image_size: u64,
    pdata_virtual_address: u32,
    pdata_virtual_size: u32,
    pdata_raw_size: u32,
) -> Vec<RuntimeFunction> {
    let bytes = core::cmp::min(pdata_virtual_size, pdata_raw_size) as usize;
    if bytes < 12 {
        return Vec::new();
    }

    let Some(image_end) = image_base.checked_add(image_size) else {
        return Vec::new();
    };

    let Some(base) = image_base.checked_add(pdata_virtual_address as u64) else {
        return Vec::new();
    };

    let Some(pdata_end) = base.checked_add(bytes as u64) else {
        return Vec::new();
    };

    if base < image_base || pdata_end > image_end {
        return Vec::new();
    }

    let entry_count = bytes / 12;
    let mut functions = Vec::with_capacity(entry_count);

    for idx in 0..entry_count {
        let addr = base + (idx * 12) as u64;
        let begin_rva = unsafe { read_unaligned_u32(addr) };
        let end_rva = unsafe { read_unaligned_u32(addr + 4) };
        let unwind_rva = unsafe { read_unaligned_u32(addr + 8) };

        if begin_rva == 0 {
            continue;
        }

        if end_rva <= begin_rva {
            continue;
        }

        if unwind_rva == 0 {
            continue;
        }

        if end_rva as u64 > image_size || unwind_rva as u64 >= image_size {
            continue;
        }

        functions.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_rva,
        });
    }

    functions
}

fn runtime_function_score(functions: &[RuntimeFunction]) -> usize {
    if functions.is_empty() {
        return 0;
    }

    let mut sorted = functions.to_vec();
    sorted.sort_unstable_by(|a, b| a.begin_rva.cmp(&b.begin_rva));

    let mut score = sorted.len() * 4;
    let mut prev_end = 0u32;

    for function in sorted {
        if function.begin_rva >= prev_end {
            score += 1;
        } else {
            score = score.saturating_sub(2);
        }

        prev_end = core::cmp::max(prev_end, function.end_rva);
    }

    score
}

fn pe_section_name_eq(name: &[u8; 8], target: &[u8]) -> bool {
    if target.len() > name.len() || &name[..target.len()] != target {
        return false;
    }

    name[target.len()..].iter().all(|b| *b == 0)
}

pub fn capture_callchain_from_state(state: &State, task: Option<&TaskRef>) -> CapturedCallchain {
    capture_callchain_from_state_limited(state, task, MAX_CALLCHAIN_DEPTH)
}

pub fn capture_callchain_from_state_limited(
    state: &State,
    task: Option<&TaskRef>,
    max_depth: usize,
) -> CapturedCallchain {
    let mut out = CapturedCallchain::default();
    let max_depth = max_depth.clamp(1, MAX_CALLCHAIN_DEPTH);

    let bounds = task.and_then(stack_bounds_for_task);
    if let Some(bounds) = bounds {
        out.stack_low = bounds.low;
        out.stack_high = bounds.high;
    } else {
        out.status |= BENCH_UNWIND_STATUS_STACK_BOUNDS_MISSING;
    }

    let mut ctx = UnwindContext::from_state(state);
    push_frame(&mut out, ctx.rip);

    while (out.depth as usize) < max_depth {
        let Some(bounds) = bounds else {
            break;
        };

        if ctx.rsp < bounds.low || ctx.rsp >= bounds.high {
            out.status |= BENCH_UNWIND_STATUS_BAD_STACK_READ;
            break;
        }

        let before_rip = ctx.rip;
        let before_rsp = ctx.rsp;
        let status = unwind_one(&mut ctx, bounds);
        out.status |= status;

        if ctx.rip == 0 || !is_canonical(ctx.rip) {
            break;
        }

        if ctx.rip == before_rip && ctx.rsp == before_rsp {
            break;
        }

        push_frame(&mut out, ctx.rip);

        if status
            & (BENCH_UNWIND_STATUS_BAD_STACK_READ
                | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO
                | BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE)
            != 0
        {
            break;
        }
    }

    if (out.depth as usize) == max_depth {
        out.status |= BENCH_UNWIND_STATUS_TRUNCATED;
    }

    out
}

fn stack_bounds_for_task(task: &TaskRef) -> Option<StackBounds> {
    let high = task.stack_start.load(Ordering::Acquire);
    let size = task.stack_size.load(Ordering::Acquire);

    if high == 0 || size == 0 {
        return None;
    }

    let low = high.checked_sub(size)?;
    Some(StackBounds { low, high })
}

fn push_frame(out: &mut CapturedCallchain, pc: u64) {
    let idx = out.depth as usize;
    if idx >= MAX_CALLCHAIN_DEPTH {
        out.status |= BENCH_UNWIND_STATUS_TRUNCATED;
        return;
    }

    out.frames[idx] = pc;
    out.frame_kinds[idx] = classify_pc(pc);
    out.depth = out.depth.saturating_add(1);
}

fn classify_pc(pc: u64) -> u32 {
    if is_registered_pe_pc(pc) {
        return BENCH_FRAME_KIND_PE_X64;
    }

    BENCH_FRAME_KIND_UNKNOWN
}

fn unwind_one(ctx: &mut UnwindContext, bounds: StackBounds) -> u32 {
    let control_pc = ctx.control_pc();

    if is_registered_pe_pc(control_pc) {
        return unwind_pe_x64(ctx, bounds, control_pc);
    }

    let status = BENCH_UNWIND_STATUS_UNKNOWN_FRAME
        | BENCH_UNWIND_STATUS_NO_UNWIND_INFO
        | BENCH_UNWIND_STATUS_LEAF_FALLBACK;

    leaf_unwind(ctx, bounds).map_or(status | BENCH_UNWIND_STATUS_BAD_STACK_READ, |_| status)
}

fn is_registered_pe_pc(pc: u64) -> bool {
    let Some(modules) = PE_UNWIND_MODULES.try_read() else {
        return false;
    };

    modules
        .iter()
        .any(|module| pc >= module.image_base && pc < module.image_end)
}

fn unwind_pe_x64(ctx: &mut UnwindContext, bounds: StackBounds, control_pc: u64) -> u32 {
    let Some(modules) = PE_UNWIND_MODULES.try_read() else {
        let status = BENCH_UNWIND_STATUS_NO_UNWIND_INFO | BENCH_UNWIND_STATUS_LEAF_FALLBACK;
        return leaf_unwind(ctx, bounds)
            .map_or(status | BENCH_UNWIND_STATUS_BAD_STACK_READ, |_| status);
    };

    let Some(module) = modules
        .iter()
        .find(|m| control_pc >= m.image_base && control_pc < m.image_end)
    else {
        let status = BENCH_UNWIND_STATUS_NO_UNWIND_INFO | BENCH_UNWIND_STATUS_LEAF_FALLBACK;
        return leaf_unwind(ctx, bounds)
            .map_or(status | BENCH_UNWIND_STATUS_BAD_STACK_READ, |_| status);
    };

    let rva = (control_pc - module.image_base) as u32;
    let Some(mut rf) = lookup_runtime_function(module, rva) else {
        let status = BENCH_UNWIND_STATUS_NO_UNWIND_INFO | BENCH_UNWIND_STATUS_LEAF_FALLBACK;
        return leaf_unwind(ctx, bounds)
            .map_or(status | BENCH_UNWIND_STATUS_BAD_STACK_READ, |_| status);
    };

    let mut status = BENCH_UNWIND_STATUS_PE_UNWIND;

    if let Some(epilog_status) = try_unwind_epilog(module, control_pc, ctx, bounds) {
        return status | epilog_status;
    }

    for _ in 0..8 {
        let (flags, chained, finish, op_status) = process_unwind_info(module, rf, rva, ctx, bounds);

        status |= op_status;

        if status
            & (BENCH_UNWIND_STATUS_BAD_UNWIND_INFO
                | BENCH_UNWIND_STATUS_BAD_STACK_READ
                | BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE)
            != 0
        {
            return status;
        }

        if finish == UnwindFinish::ContextIsCaller {
            return status;
        }

        if flags & UNW_FLAG_CHAININFO == 0 {
            return leaf_unwind(ctx, bounds)
                .map_or(status | BENCH_UNWIND_STATUS_BAD_STACK_READ, |_| status);
        }

        let Some(next) = chained else {
            return status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO;
        };

        rf = next;
    }

    status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO
}

fn lookup_runtime_function(module: &PeUnwindModule, rva: u32) -> Option<RuntimeFunction> {
    let mut lo = 0usize;
    let mut hi = module.functions.len();

    while lo < hi {
        let mid = (lo + hi) / 2;
        let f = module.functions[mid];

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
            BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
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
            BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
        );
    }

    if flags & UNW_FLAG_CHAININFO != 0 && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        return (
            flags,
            None,
            UnwindFinish::NeedsReturnAddress,
            BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
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
                status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
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
                        None => status |= BENCH_UNWIND_STATUS_BAD_STACK_READ,
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
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
                    );
                }

                let Some(size) = read_alloc_large_size(module, info, idx, op_info) else {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
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
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
                    );
                }

                let Some(slot) = read_unwind_u16_slot(module, info, idx) else {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
                    );
                };

                idx += 1;

                if apply {
                    let addr = frame_base.saturating_add(slot as u64 * 8);
                    match read_stack_u64(bounds, addr) {
                        Some(value) => ctx.set_reg(op_info, value),
                        None => status |= BENCH_UNWIND_STATUS_BAD_STACK_READ,
                    }
                }
            }
            UWOP_SAVE_NONVOL_FAR => {
                if idx.checked_add(2).is_none_or(|end| end > code_count) {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
                    );
                }

                let Some(slot) = read_unwind_u32_slot(module, info, idx) else {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
                    );
                };

                idx += 2;

                if apply {
                    let addr = frame_base.saturating_add(slot as u64);
                    match read_stack_u64(bounds, addr) {
                        Some(value) => ctx.set_reg(op_info, value),
                        None => status |= BENCH_UNWIND_STATUS_BAD_STACK_READ,
                    }
                }
            }
            UWOP_SAVE_XMM128 => {
                if idx >= code_count {
                    return (
                        flags,
                        None,
                        UnwindFinish::NeedsReturnAddress,
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
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
                        status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
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
                        None => status |= BENCH_UNWIND_STATUS_BAD_STACK_READ,
                    }
                }
            }
            _ => {
                return (
                    flags,
                    None,
                    UnwindFinish::NeedsReturnAddress,
                    status
                        | BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE
                        | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
                );
            }
        }

        if status & BENCH_UNWIND_STATUS_BAD_STACK_READ != 0 {
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
                return Some(BENCH_UNWIND_STATUS_BAD_STACK_READ);
            };

            tmp.set_reg(reg, value);
            tmp.rsp = tmp.rsp.saturating_add(8);
            idx += consumed;
            consumed_any = true;
            continue;
        }

        if bytes[idx] == 0xc3 {
            let Some(rip) = read_stack_u64(bounds, tmp.rsp) else {
                return Some(BENCH_UNWIND_STATUS_BAD_STACK_READ);
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
                return Some(BENCH_UNWIND_STATUS_BAD_STACK_READ);
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

    if addr < bounds.low || end > bounds.high || (addr & 0x7) != 0 {
        return None;
    }

    Some(unsafe { core::ptr::read_unaligned(addr as *const u64) })
}

unsafe fn read_unaligned_u32(addr: u64) -> u32 {
    core::ptr::read_unaligned(addr as *const u32)
}

fn is_canonical(addr: u64) -> bool {
    let high = addr >> 48;
    let sign = (addr >> 47) & 1;
    (sign == 0 && high == 0) || (sign == 1 && high == 0xffff)
}

#[derive(Clone, Copy)]
struct UnwindContext {
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
