use core::arch::asm;

use kernel_types::arch::VirtAddr;
use kernel_types::memory::Module;

use crate::arch::unwind::{
    PeUnwindModule, STATUS_BAD_STACK_READ, STATUS_BAD_UNWIND_INFO, STATUS_LEAF_FALLBACK,
    STATUS_NO_UNWIND_INFO, STATUS_PE_UNWIND, STATUS_UNKNOWN_FRAME, STATUS_UNSUPPORTED_OPCODE,
    backtrace_status, read_image_bytes, read_image_u32, read_stack_u64,
};
use crate::platform::UnwindPlatform;
use crate::profiling::backtrace::{StackBounds, UnwindStart, UnwindStep};

use super::platform::Aarch64Platform;
use super::scheduling::TaskContext;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct UnwindContext {
    pc: u64,
    sp: u64,
    registers: [u64; 12],
    fp: u64,
    lr: u64,
    pc_is_return_address: bool,
}

#[derive(Clone, Copy)]
struct RuntimeFunction {
    begin_rva: u32,
    unwind_data: u32,
}

impl UnwindPlatform for Aarch64Platform {
    type UnwindContext = UnwindContext;

    fn begin_current_unwind() -> UnwindStart<Self::UnwindContext> {
        let mut context = UnwindContext {
            pc: 0,
            sp: 0,
            registers: [0; 12],
            fp: 0,
            lr: 0,
            pc_is_return_address: false,
        };
        let pointer = &mut context as *mut UnwindContext;
        unsafe {
            asm!(
                "adr x16, 2f", "str x16, [x17, {pc}]", "mov x16, sp", "str x16, [x17, {sp}]",
                "str x19, [x17, {x19}]", "str x20, [x17, {x20}]", "str x21, [x17, {x21}]",
                "str x22, [x17, {x22}]", "str x23, [x17, {x23}]", "str x24, [x17, {x24}]",
                "str x25, [x17, {x25}]", "str x26, [x17, {x26}]", "str x27, [x17, {x27}]",
                "str x28, [x17, {x28}]", "str x29, [x17, {fp}]", "str x30, [x17, {lr}]", "2:",
                in("x17") pointer,
                pc = const core::mem::offset_of!(UnwindContext, pc),
                sp = const core::mem::offset_of!(UnwindContext, sp),
                x19 = const core::mem::offset_of!(UnwindContext, registers),
                x20 = const core::mem::offset_of!(UnwindContext, registers) + 8,
                x21 = const core::mem::offset_of!(UnwindContext, registers) + 16,
                x22 = const core::mem::offset_of!(UnwindContext, registers) + 24,
                x23 = const core::mem::offset_of!(UnwindContext, registers) + 32,
                x24 = const core::mem::offset_of!(UnwindContext, registers) + 40,
                x25 = const core::mem::offset_of!(UnwindContext, registers) + 48,
                x26 = const core::mem::offset_of!(UnwindContext, registers) + 56,
                x27 = const core::mem::offset_of!(UnwindContext, registers) + 64,
                x28 = const core::mem::offset_of!(UnwindContext, registers) + 72,
                fp = const core::mem::offset_of!(UnwindContext, fp),
                lr = const core::mem::offset_of!(UnwindContext, lr),
                lateout("x16") _, options(nostack, preserves_flags),
            );
        }
        UnwindStart {
            pc: VirtAddr::new(context.pc),
            context,
        }
    }

    fn begin_unwind(state: &TaskContext) -> UnwindStart<Self::UnwindContext> {
        let context = UnwindContext::from_state(state);
        UnwindStart {
            pc: VirtAddr::new(context.pc),
            context,
        }
    }

    fn unwind_next(
        context: &mut Self::UnwindContext,
        module: Option<&Module>,
        stack_bounds: StackBounds,
    ) -> UnwindStep {
        let before = (context.pc, context.sp);
        let control_pc = context.control_pc();
        let status = match module.and_then(PeUnwindModule::from_module) {
            Some(module) if module.pdata_len >= 8 => {
                unwind_pe(context, stack_bounds, control_pc, &module)
            }
            Some(_) => fallback(context, false),
            None => fallback(context, true),
        };
        let pc = (context.pc != 0
            && context.pc & 3 == 0
            && valid_address(context.pc)
            && (context.pc, context.sp) != before)
            .then(|| VirtAddr::new(context.pc));
        UnwindStep {
            pc,
            status: backtrace_status(status),
        }
    }
}

fn fallback(context: &mut UnwindContext, unknown: bool) -> u32 {
    context.pc = context.lr;
    context.pc_is_return_address = true;
    STATUS_NO_UNWIND_INFO | STATUS_LEAF_FALLBACK | if unknown { STATUS_UNKNOWN_FRAME } else { 0 }
}

fn unwind_pe(
    context: &mut UnwindContext,
    bounds: StackBounds,
    pc: u64,
    module: &PeUnwindModule,
) -> u32 {
    if pc < module.image_base || pc >= module.image_end {
        return fallback(context, false);
    }
    let rva = (pc - module.image_base) as u32;
    let Some(function) = lookup_function(module, rva) else {
        return fallback(context, false);
    };
    let offset = rva - function.begin_rva;
    let result = if function.unwind_data & 3 == 0 {
        unwind_full(context, bounds, module, function.unwind_data, offset)
    } else {
        unwind_packed(context, bounds, function.unwind_data, offset)
    };
    STATUS_PE_UNWIND | result.err().unwrap_or(0)
}

fn lookup_function(module: &PeUnwindModule, rva: u32) -> Option<RuntimeFunction> {
    let mut low = 0usize;
    let mut high = module.pdata_len / 8;
    while low < high {
        let middle = (low + high) / 2;
        let begin = read_image_u32(module, module.pdata_base + (middle * 8) as u64)?;
        if begin <= rva {
            low = middle + 1
        } else {
            high = middle
        }
    }
    let address = module.pdata_base + (low.checked_sub(1)? * 8) as u64;
    let function = RuntimeFunction {
        begin_rva: read_image_u32(module, address)?,
        unwind_data: read_image_u32(module, address + 4)?,
    };
    let length = if function.unwind_data & 3 == 0 {
        let header = read_image_u32(
            module,
            module.image_base + (function.unwind_data & !3) as u64,
        )?;
        (header & 0x3ffff) * 4
    } else {
        ((function.unwind_data >> 2) & 0x7ff) * 4
    };
    (length != 0 && rva < function.begin_rva.checked_add(length)?).then_some(function)
}

fn unwind_full(
    context: &mut UnwindContext,
    bounds: StackBounds,
    module: &PeUnwindModule,
    data: u32,
    function_offset: u32,
) -> Result<(), u32> {
    let xdata = module
        .image_base
        .checked_add((data & !3) as u64)
        .ok_or(STATUS_BAD_UNWIND_INFO)?;
    let header = read_image_u32(module, xdata).ok_or(STATUS_BAD_UNWIND_INFO)?;
    if (header >> 18) & 3 != 0 {
        return Err(STATUS_BAD_UNWIND_INFO);
    }
    let packed_epilog = header & (1 << 21) != 0;
    let mut epilogs = ((header >> 22) & 0x1f) as usize;
    let mut words = ((header >> 27) & 0x1f) as usize;
    let mut header_size = 4u64;
    if epilogs == 0 && words == 0 {
        let extension = read_image_u32(module, xdata + 4).ok_or(STATUS_BAD_UNWIND_INFO)?;
        if extension >> 24 != 0 {
            return Err(STATUS_BAD_UNWIND_INFO);
        }
        epilogs = (extension & 0xffff) as usize;
        words = ((extension >> 16) & 0xff) as usize;
        header_size = 8;
    }
    if words == 0 || words > 64 {
        return Err(STATUS_BAD_UNWIND_INFO);
    }
    let scope_count = if packed_epilog { 0 } else { epilogs };
    let scopes = xdata + header_size;
    let codes_address = scopes
        .checked_add((scope_count * 4) as u64)
        .ok_or(STATUS_BAD_UNWIND_INFO)?;
    let codes = read_image_bytes(module, codes_address, words * 4).ok_or(STATUS_BAD_UNWIND_INFO)?;
    let instruction = (function_offset / 4) as usize;
    let mut start = 0usize;
    let mut skip = 0usize;
    let mut in_epilog = false;
    if packed_epilog {
        let count = code_count(codes, epilogs)?;
        let function_length = (header & 0x3ffff) as usize;
        let epilog_start = function_length.saturating_sub(count);
        if instruction >= epilog_start {
            start = epilogs;
            skip = instruction - epilog_start;
            in_epilog = true;
        }
    } else {
        for index in 0..epilogs {
            let scope = read_image_u32(module, scopes + (index * 4) as u64)
                .ok_or(STATUS_BAD_UNWIND_INFO)?;
            if scope & 0x003c0000 != 0 {
                return Err(STATUS_BAD_UNWIND_INFO);
            }
            let epilog_start = (scope & 0x3ffff) as usize;
            let code_start = (scope >> 22) as usize;
            let count = code_count(codes, code_start)?;
            if instruction >= epilog_start && instruction - epilog_start < count {
                start = code_start;
                skip = instruction - epilog_start;
                in_epilog = true;
                break;
            }
        }
    }
    if !in_epilog {
        let count = code_count(codes, 0)?;
        if instruction < count {
            skip = count - instruction
        }
    }
    execute_codes(context, bounds, codes, start, skip)
}

fn unwind_packed(
    context: &mut UnwindContext,
    bounds: StackBounds,
    data: u32,
    function_offset: u32,
) -> Result<(), u32> {
    let flag = data & 3;
    let function_length = ((data >> 2) & 0x7ff) * 4;
    let reg_f = (data >> 13) & 7;
    let reg_i = (data >> 16) & 0xf;
    let homes = (data >> 20) & 1;
    let chain = (data >> 21) & 3;
    let frame_size = ((data >> 23) & 0x1ff) * 16;
    if flag == 3 || function_length == 0 || reg_i > 10 || frame_size == 0 {
        return Err(STATUS_BAD_UNWIND_INFO);
    }
    let instruction_count = packed_code_count(reg_i, reg_f, homes, chain, frame_size)?;
    if flag == 1 {
        let instruction = function_offset / 4;
        if instruction < instruction_count
            || function_offset >= function_length - instruction_count * 4
        {
            return Err(STATUS_UNSUPPORTED_OPCODE);
        }
    }
    let int_size = reg_i * 8 + u32::from(chain == 1) * 8;
    let fp_size = if reg_f == 0 { 0 } else { (reg_f + 1) * 8 };
    let save_size = (int_size + fp_size + homes * 64 + 15) & !15;
    let local_size = frame_size
        .checked_sub(save_size)
        .ok_or(STATUS_BAD_UNWIND_INFO)?;
    let save_base = context
        .sp
        .checked_add(local_size as u64)
        .ok_or(STATUS_BAD_STACK_READ)?;
    for index in 0..reg_i {
        restore_reg(
            context,
            bounds,
            (19 + index) as u8,
            save_base + (index * 8) as u64,
        )?;
    }
    if chain == 1 {
        context.lr =
            read_stack_u64(bounds, save_base + (reg_i * 8) as u64).ok_or(STATUS_BAD_STACK_READ)?;
    } else if chain >= 2 {
        restore_fplr(context, bounds, context.sp)?;
    }
    context.sp = context
        .sp
        .checked_add(frame_size as u64)
        .ok_or(STATUS_BAD_STACK_READ)?;
    finish(context);
    Ok(())
}

fn packed_code_count(
    reg_i: u32,
    reg_f: u32,
    homes: u32,
    chain: u32,
    frame: u32,
) -> Result<u32, u32> {
    let int_size = reg_i * 8 + u32::from(chain == 1) * 8;
    let fp_size = if reg_f == 0 { 0 } else { (reg_f + 1) * 8 };
    let saves = (int_size + fp_size + homes * 64 + 15) & !15;
    let local = frame.checked_sub(saves).ok_or(STATUS_BAD_UNWIND_INFO)?;
    let mut count = (reg_i + 1) / 2 + (reg_f + 2) / 2 + homes * 4;
    count += u32::from(chain == 1 && reg_i & 1 == 0) + u32::from(chain == 2);
    count += if chain >= 2 {
        2 + u32::from(local > 512) + u32::from(local > 4080)
    } else {
        1 + u32::from(local > 4080)
    };
    Ok(count)
}

fn code_count(codes: &[u8], start: usize) -> Result<usize, u32> {
    let mut index = start;
    let mut count = 0usize;
    while index < codes.len() && count < 256 {
        let opcode = codes[index];
        if opcode == 0xe4 || opcode == 0xe5 {
            return Ok(count);
        }
        index = index
            .checked_add(opcode_len(opcode))
            .ok_or(STATUS_BAD_UNWIND_INFO)?;
        if index > codes.len() {
            return Err(STATUS_BAD_UNWIND_INFO);
        }
        count += 1;
    }
    Err(STATUS_BAD_UNWIND_INFO)
}

fn opcode_len(opcode: u8) -> usize {
    match opcode {
        0xc0..=0xdf | 0xe2 | 0xf8 => 2,
        0xe0 | 0xe7 | 0xfa => 4,
        0xf9 => 3,
        0xfb => 5,
        _ => 1,
    }
}

fn execute_codes(
    context: &mut UnwindContext,
    bounds: StackBounds,
    codes: &[u8],
    start: usize,
    mut skip: usize,
) -> Result<(), u32> {
    let mut index = start;
    let mut last_pair = None;
    for _ in 0..256 {
        let opcode = *codes.get(index).ok_or(STATUS_BAD_UNWIND_INFO)?;
        let length = opcode_len(opcode);
        let bytes = codes
            .get(index..index + length)
            .ok_or(STATUS_BAD_UNWIND_INFO)?;
        index += length;
        if opcode == 0xe4 {
            finish(context);
            return Ok(());
        }
        if opcode == 0xe5 {
            continue;
        }
        if skip != 0 {
            skip -= 1;
            continue;
        }
        match opcode {
            0x00..=0x1f => context.sp = add_sp(context.sp, (opcode & 31) as u64 * 16)?,
            0x20..=0x3f => {
                let address = context.sp;
                restore_pair(context, bounds, 19, address)?;
                context.sp = add_sp(context.sp, (opcode & 31) as u64 * 8)?;
                last_pair = Some((19, address));
            }
            0x40..=0x7f => restore_fplr(context, bounds, context.sp + (opcode & 63) as u64 * 8)?,
            0x80..=0xbf => {
                restore_fplr(context, bounds, context.sp)?;
                context.sp = add_sp(context.sp, ((opcode & 63) as u64 + 1) * 8)?;
            }
            0xc0..=0xc7 => {
                context.sp = add_sp(
                    context.sp,
                    ((((opcode & 7) as u64) << 8) | bytes[1] as u64) * 16,
                )?
            }
            0xc8..=0xcb => {
                let reg = 19 + ((opcode & 3) << 2) + (bytes[1] >> 6);
                let address = context.sp + (bytes[1] & 63) as u64 * 8;
                restore_pair(context, bounds, reg, address)?;
                last_pair = Some((reg, address));
            }
            0xcc..=0xcf => {
                let reg = 19 + ((opcode & 3) << 2) + (bytes[1] >> 6);
                let address = context.sp;
                restore_pair(context, bounds, reg, address)?;
                context.sp = add_sp(context.sp, ((bytes[1] & 63) as u64 + 1) * 8)?;
                last_pair = Some((reg, address));
            }
            0xd0..=0xd3 => {
                let reg = 19 + ((opcode & 3) << 2) + (bytes[1] >> 6);
                restore_reg(
                    context,
                    bounds,
                    reg,
                    context.sp + (bytes[1] & 63) as u64 * 8,
                )?;
            }
            0xd4..=0xd5 => {
                let reg = 19 + ((opcode & 1) << 3) + (bytes[1] >> 5);
                restore_reg(context, bounds, reg, context.sp)?;
                context.sp = add_sp(context.sp, ((bytes[1] & 31) as u64 + 1) * 8)?;
            }
            0xd6..=0xd7 => {
                let reg = 19 + ((opcode & 1) << 2) + (bytes[1] >> 6) * 2;
                let address = context.sp + (bytes[1] & 63) as u64 * 8;
                restore_reg(context, bounds, reg, address)?;
                context.lr = read_stack_u64(bounds, address + 8).ok_or(STATUS_BAD_STACK_READ)?;
            }
            0xd8..=0xd9 | 0xdc..=0xdd => {}
            0xda..=0xdb => context.sp = add_sp(context.sp, ((bytes[1] & 63) as u64 + 1) * 8)?,
            0xde => context.sp = add_sp(context.sp, ((bytes[1] & 31) as u64 + 1) * 8)?,
            0xdf => return Err(STATUS_UNSUPPORTED_OPCODE),
            0xe0 => {
                context.sp = add_sp(
                    context.sp,
                    u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as u64 * 16,
                )?
            }
            0xe1 => context.sp = context.fp,
            0xe2 => {
                context.sp = context
                    .fp
                    .checked_sub(bytes[1] as u64 * 8)
                    .ok_or(STATUS_BAD_STACK_READ)?
            }
            0xe3 | 0xfc => {}
            0xe6 => {
                let (reg, address) = last_pair.ok_or(STATUS_BAD_UNWIND_INFO)?;
                restore_pair(context, bounds, reg + 2, address + 16)?;
                last_pair = Some((reg + 2, address + 16));
            }
            0xe7 => execute_save_any(context, bounds, bytes)?,
            _ => return Err(STATUS_UNSUPPORTED_OPCODE),
        }
    }
    Err(STATUS_BAD_UNWIND_INFO)
}

fn execute_save_any(
    context: &mut UnwindContext,
    bounds: StackBounds,
    bytes: &[u8],
) -> Result<(), u32> {
    if bytes.len() != 4 || bytes[1] & 0x80 != 0 {
        return Err(STATUS_BAD_UNWIND_INFO);
    }
    let pair = bytes[1] & 0x40 != 0;
    let preindexed = bytes[1] & 0x20 != 0;
    let reg = bytes[1] & 0x1f;
    let kind = bytes[2] >> 6;
    let scale = if kind == 2 || pair || preindexed {
        16
    } else {
        8
    };
    let offset = (bytes[2] & 63) as u64 * scale;
    let address = if preindexed {
        context.sp
    } else {
        context.sp + offset
    };
    if kind == 0 {
        restore_reg(context, bounds, reg, address)?;
        if pair {
            restore_reg(context, bounds, reg + 1, address + 8)?
        }
    } else if kind == 3 {
        return Err(STATUS_UNSUPPORTED_OPCODE);
    }
    if preindexed {
        context.sp = add_sp(context.sp, offset)?
    }
    Ok(())
}

fn restore_pair(
    context: &mut UnwindContext,
    bounds: StackBounds,
    reg: u8,
    address: u64,
) -> Result<(), u32> {
    restore_reg(context, bounds, reg, address)?;
    restore_reg(context, bounds, reg + 1, address + 8)
}

fn restore_reg(
    context: &mut UnwindContext,
    bounds: StackBounds,
    reg: u8,
    address: u64,
) -> Result<(), u32> {
    let value = read_stack_u64(bounds, address).ok_or(STATUS_BAD_STACK_READ)?;
    context.set_reg(reg, value);
    Ok(())
}

fn restore_fplr(context: &mut UnwindContext, bounds: StackBounds, address: u64) -> Result<(), u32> {
    context.fp = read_stack_u64(bounds, address).ok_or(STATUS_BAD_STACK_READ)?;
    context.lr = read_stack_u64(bounds, address + 8).ok_or(STATUS_BAD_STACK_READ)?;
    Ok(())
}

fn add_sp(sp: u64, size: u64) -> Result<u64, u32> {
    sp.checked_add(size).ok_or(STATUS_BAD_STACK_READ)
}

fn finish(context: &mut UnwindContext) {
    context.pc = context.lr;
    context.pc_is_return_address = true;
}

fn valid_address(address: u64) -> bool {
    address >> 56 == 0 || address >> 56 == 0xff
}

impl UnwindContext {
    fn from_state(state: &TaskContext) -> Self {
        Self {
            pc: state.rip,
            sp: state.sp,
            registers: [
                state.x19, state.x20, state.x21, state.x22, state.x23, state.x24, state.x25,
                state.x26, state.x27, state.x28, 0, 0,
            ],
            fp: state.fp,
            lr: state.lr,
            pc_is_return_address: false,
        }
    }

    fn control_pc(&self) -> u64 {
        if self.pc_is_return_address {
            self.pc.saturating_sub(4)
        } else {
            self.pc
        }
    }

    fn set_reg(&mut self, reg: u8, value: u64) {
        match reg {
            19..=28 => self.registers[(reg - 19) as usize] = value,
            29 => self.fp = value,
            30 => self.lr = value,
            _ => {}
        }
    }
}
