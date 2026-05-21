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

pub const MAX_CALLCHAIN_DEPTH: usize = 32;

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

static PE_UNWIND_MODULES: RwLock<Vec<PeUnwindModule>> = RwLock::new(Vec::new());

pub fn register_pe_unwind_module(image_base: u64, image_size: u64, sections: &[PeSectionInfo]) {
    let Some(pdata) = sections.iter().find(|s| s.name == ".pdata") else {
        return;
    };

    register_pe_unwind_module_from_pdata(
        image_base,
        image_size,
        pdata.virtual_address,
        pdata.virtual_size,
        pdata.raw_size,
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

    register_pe_unwind_module_from_pdata(
        image_base,
        image_size,
        pdata.virtual_address,
        pdata.virtual_size,
        pdata.raw_size,
    );
}

fn register_pe_unwind_module_from_pdata(
    image_base: u64,
    image_size: u64,
    pdata_virtual_address: u32,
    pdata_virtual_size: u32,
    pdata_raw_size: u32,
) {
    let bytes = core::cmp::min(pdata_virtual_size, pdata_raw_size) as usize;
    if bytes < 12 {
        return;
    }

    let base = image_base.saturating_add(pdata_virtual_address as u64);
    let entry_count = bytes / 12;
    let mut functions = Vec::with_capacity(entry_count);

    for idx in 0..entry_count {
        let addr = base.saturating_add((idx * 12) as u64);
        let begin_rva = unsafe { read_unaligned_u32(addr) };
        let end_rva = unsafe { read_unaligned_u32(addr + 4) };
        let unwind_rva = unsafe { read_unaligned_u32(addr + 8) };
        if begin_rva == 0 || end_rva <= begin_rva || unwind_rva == 0 {
            continue;
        }
        functions.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_rva,
        });
    }

    if functions.is_empty() {
        return;
    }

    functions.sort_unstable_by(|a, b| a.begin_rva.cmp(&b.begin_rva));

    let mut modules = PE_UNWIND_MODULES.write();
    if let Some(slot) = modules.iter_mut().find(|m| m.image_base == image_base) {
        slot.image_end = image_base.saturating_add(image_size);
        slot.functions = functions;
    } else {
        modules.push(PeUnwindModule {
            image_base,
            image_end: image_base.saturating_add(image_size),
            functions,
        });
    }
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
    }

    if (out.depth as usize) == max_depth && max_depth < MAX_CALLCHAIN_DEPTH {
        out.status |= BENCH_UNWIND_STATUS_TRUNCATED;
    }

    if (out.depth as usize) == MAX_CALLCHAIN_DEPTH {
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
    for _ in 0..4 {
        let (flags, chained, op_status) = process_unwind_info(module, rf, rva, ctx, bounds);
        status |= op_status;
        if status & (BENCH_UNWIND_STATUS_BAD_UNWIND_INFO | BENCH_UNWIND_STATUS_BAD_STACK_READ) != 0
        {
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
) -> (u8, Option<RuntimeFunction>, u32) {
    let info = module.image_base.saturating_add(rf.unwind_rva as u64);
    let Some(header) = read_image_bytes(module, info, 4) else {
        return (0, None, BENCH_UNWIND_STATUS_BAD_UNWIND_INFO);
    };

    let version = header[0] & 0x7;
    let flags = header[0] >> 3;
    let prolog_size = header[1] as u32;
    let code_count = header[2] as usize;
    let frame_reg = header[3] & 0x0f;
    let frame_off = (header[3] >> 4) as u64 * 16;

    if version != 1 {
        return (flags, None, BENCH_UNWIND_STATUS_BAD_UNWIND_INFO);
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
            return (flags, None, status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO);
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
                let Some(size) = read_alloc_large_size(module, info, idx, op_info) else {
                    return (flags, None, status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO);
                };
                idx += if op_info == 0 { 1 } else { 2 };
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
                let Some(slot) = read_unwind_u16_slot(module, info, idx) else {
                    return (flags, None, status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO);
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
                let Some(slot) = read_unwind_u32_slot(module, info, idx) else {
                    return (flags, None, status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO);
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
                idx += 1;
            }
            UWOP_SAVE_XMM128_FAR => {
                idx += 2;
            }
            UWOP_PUSH_MACHFRAME => {
                status |= BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE;
            }
            _ => {
                status |= BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE;
            }
        }

        if status & BENCH_UNWIND_STATUS_BAD_STACK_READ != 0 {
            return (flags, None, status);
        }
    }

    let chained = if flags & UNW_FLAG_CHAININFO != 0 {
        read_chained_runtime_function(module, info, code_count)
    } else {
        None
    };

    (flags, chained, status)
}

fn read_chained_runtime_function(
    module: &PeUnwindModule,
    info: u64,
    code_count: usize,
) -> Option<RuntimeFunction> {
    let aligned_count = (code_count + 1) & !1;
    let addr = info.saturating_add(4 + (aligned_count * 2) as u64);
    Some(RuntimeFunction {
        begin_rva: read_image_u32(module, addr)?,
        end_rva: read_image_u32(module, addr + 4)?,
        unwind_rva: read_image_u32(module, addr + 8)?,
    })
}

fn read_unwind_code(module: &PeUnwindModule, info: u64, idx: usize) -> Option<(u8, u8, u8)> {
    let slot = info.saturating_add(4 + (idx * 2) as u64);
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
    let slot = info.saturating_add(4 + (idx * 2) as u64);
    let bytes = read_image_bytes(module, slot, 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_unwind_u32_slot(module: &PeUnwindModule, info: u64, idx: usize) -> Option<u32> {
    let slot = info.saturating_add(4 + (idx * 2) as u64);
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
