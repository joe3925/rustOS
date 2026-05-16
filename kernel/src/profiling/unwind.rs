use alloc::vec::Vec;
use core::{slice, sync::atomic::Ordering};

use gimli::{
    BaseAddresses, CfaRule, CieOrFde, DebugFrame, DebugFrameOffset, EhFrame, EhFrameOffset,
    EndianSlice, LittleEndian, Register, RegisterRule as GimliRegisterRule,
    UnwindContext as GimliUnwindContext, UnwindContextStorage, UnwindSection, UnwindTableRow,
};
use goblin::elf::{program_header::PT_LOAD, section_header::SHF_ALLOC, Elf};
use kernel_types::benchmark::{
    BENCH_FRAME_KIND_KERNEL_ELF, BENCH_FRAME_KIND_PE_X64, BENCH_FRAME_KIND_UNKNOWN,
    BENCH_UNWIND_STATUS_BAD_STACK_READ, BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
    BENCH_UNWIND_STATUS_KERNEL_ELF_FRAME, BENCH_UNWIND_STATUS_LEAF_FALLBACK,
    BENCH_UNWIND_STATUS_NO_UNWIND_INFO, BENCH_UNWIND_STATUS_PE_UNWIND,
    BENCH_UNWIND_STATUS_STACK_BOUNDS_MISSING, BENCH_UNWIND_STATUS_TRUNCATED,
    BENCH_UNWIND_STATUS_UNKNOWN_FRAME, BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE,
};
use kernel_types::memory::PeSectionInfo;
use spin::RwLock;

use crate::scheduling::state::State;
use crate::scheduling::task::TaskRef;
use crate::util::boot_info;

pub const MAX_CALLCHAIN_DEPTH: usize = 32;

const KERNEL_ELF_PREFIX_MASK: u64 = 0xffff_ff00_0000_0000;
const KERNEL_ELF_PREFIX: u64 = 0xffff_8500_0000_0000;
const PE_PREFIX_MASK: u64 = 0xffff_f000_0000_0000;
const PE_PREFIX: u64 = 0xffff_9000_0000_0000;

const X86_64_DWARF_REG_RBX: u16 = 3;
const X86_64_DWARF_REG_RSI: u16 = 4;
const X86_64_DWARF_REG_RDI: u16 = 5;
const X86_64_DWARF_REG_RBP: u16 = 6;
const X86_64_DWARF_REG_RSP: u16 = 7;
const X86_64_DWARF_REG_R12: u16 = 12;
const X86_64_DWARF_REG_R13: u16 = 13;
const X86_64_DWARF_REG_R14: u16 = 14;
const X86_64_DWARF_REG_R15: u16 = 15;
const X86_64_DWARF_REG_RIP: u16 = 16;

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

type GimliReader = EndianSlice<'static, LittleEndian>;

struct GimliUnwindStorage;

impl UnwindContextStorage<usize> for GimliUnwindStorage {
    type Rules = [(Register, GimliRegisterRule<usize>); 64];
    type Stack = [UnwindTableRow<usize, Self>; 8];
}

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

#[derive(Clone, Copy)]
enum KernelElfCfiKind {
    EhFrame,
    DebugFrame,
}

#[derive(Clone, Copy)]
struct KernelElfCfiSection {
    data: &'static [u8],
    kind: KernelElfCfiKind,
}

#[derive(Clone, Copy)]
struct ElfUnwindEntry {
    initial_location: u64,
    end: u64,
    fde_offset: usize,
    section: KernelElfCfiSection,
}

#[derive(Clone, Copy)]
struct ElfSectionData {
    data: &'static [u8],
    addr: u64,
    flags: u64,
}

struct KernelElfUnwindModule {
    image_base: u64,
    image_end: u64,
    bases: BaseAddresses,
    functions: Vec<ElfUnwindEntry>,
}

enum ElfUnwindError {
    NoInfo,
    BadStackRead,
    BadUnwindInfo,
    UnsupportedOpcode,
}

static PE_UNWIND_MODULES: RwLock<Vec<PeUnwindModule>> = RwLock::new(Vec::new());
static KERNEL_ELF_UNWIND_MODULE: RwLock<Option<KernelElfUnwindModule>> = RwLock::new(None);

pub fn register_pe_unwind_module(image_base: u64, image_size: u64, sections: &[PeSectionInfo]) {
    let Some(pdata) = sections.iter().find(|s| s.name == ".pdata") else {
        return;
    };

    let bytes = core::cmp::min(pdata.virtual_size, pdata.raw_size) as usize;
    if bytes < 12 {
        return;
    }

    let base = image_base.saturating_add(pdata.virtual_address as u64);
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

pub fn init_kernel_elf_unwind() {
    if KERNEL_ELF_UNWIND_MODULE.read().is_some() {
        return;
    }

    let module = build_kernel_elf_unwind_module();
    let mut slot = KERNEL_ELF_UNWIND_MODULE.write();
    if slot.is_none() {
        *slot = module;
    }
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
    if (pc & KERNEL_ELF_PREFIX_MASK) == KERNEL_ELF_PREFIX {
        BENCH_FRAME_KIND_KERNEL_ELF
    } else if (pc & PE_PREFIX_MASK) == PE_PREFIX {
        BENCH_FRAME_KIND_PE_X64
    } else {
        BENCH_FRAME_KIND_UNKNOWN
    }
}

fn unwind_one(ctx: &mut UnwindContext, bounds: StackBounds) -> u32 {
    let control_pc = ctx.control_pc();
    match classify_pc(control_pc) {
        BENCH_FRAME_KIND_PE_X64 => unwind_pe_x64(ctx, bounds, control_pc),
        BENCH_FRAME_KIND_KERNEL_ELF => unwind_kernel_elf(ctx, bounds, control_pc),
        _ => {
            let status = BENCH_UNWIND_STATUS_UNKNOWN_FRAME
                | BENCH_UNWIND_STATUS_NO_UNWIND_INFO
                | BENCH_UNWIND_STATUS_LEAF_FALLBACK;
            leaf_unwind(ctx, bounds).map_or(status | BENCH_UNWIND_STATUS_BAD_STACK_READ, |_| status)
        }
    }
}

fn unwind_kernel_elf(ctx: &mut UnwindContext, bounds: StackBounds, control_pc: u64) -> u32 {
    let status = BENCH_UNWIND_STATUS_KERNEL_ELF_FRAME;
    let Some(module_guard) = KERNEL_ELF_UNWIND_MODULE.try_read() else {
        return elf_leaf_fallback(ctx, bounds, status);
    };
    let Some(module) = module_guard.as_ref() else {
        return elf_leaf_fallback(ctx, bounds, status);
    };

    if control_pc < module.image_base || control_pc >= module.image_end {
        return elf_leaf_fallback(ctx, bounds, status);
    }

    let Some(entry) = lookup_elf_function(module, control_pc) else {
        return elf_leaf_fallback(ctx, bounds, status);
    };

    match unwind_elf_cfi(ctx, bounds, module, entry, control_pc) {
        Ok(()) => status,
        Err(ElfUnwindError::NoInfo) => elf_leaf_fallback(ctx, bounds, status),
        Err(ElfUnwindError::BadStackRead) => status | BENCH_UNWIND_STATUS_BAD_STACK_READ,
        Err(ElfUnwindError::BadUnwindInfo) => status | BENCH_UNWIND_STATUS_BAD_UNWIND_INFO,
        Err(ElfUnwindError::UnsupportedOpcode) => status | BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE,
    }
}

fn elf_leaf_fallback(ctx: &mut UnwindContext, bounds: StackBounds, status: u32) -> u32 {
    let status = status | BENCH_UNWIND_STATUS_NO_UNWIND_INFO | BENCH_UNWIND_STATUS_LEAF_FALLBACK;
    leaf_unwind(ctx, bounds).map_or(status | BENCH_UNWIND_STATUS_BAD_STACK_READ, |_| status)
}

fn lookup_elf_function(module: &KernelElfUnwindModule, pc: u64) -> Option<ElfUnwindEntry> {
    let mut lo = 0usize;
    let mut hi = module.functions.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let f = module.functions[mid];
        if pc < f.initial_location {
            hi = mid;
        } else if pc >= f.end {
            lo = mid + 1;
        } else {
            return Some(f);
        }
    }
    None
}

fn build_kernel_elf_unwind_module() -> Option<KernelElfUnwindModule> {
    let kernel_elf = kernel_elf_file_bytes()?;
    let elf = Elf::parse(kernel_elf).ok()?;
    if !elf.is_64 || !elf.little_endian {
        return None;
    }

    let (image_base, image_end) = kernel_elf_image_bounds(&elf)?;
    let text_base = find_elf_section(&elf, kernel_elf, ".text")
        .map(|s| s.addr)
        .unwrap_or(image_base);
    let eh_frame = find_elf_section(&elf, kernel_elf, ".eh_frame")
        .filter(|s| s.flags & SHF_ALLOC as u64 != 0 && s.addr != 0 && !s.data.is_empty());
    let eh_frame_hdr = find_elf_section(&elf, kernel_elf, ".eh_frame_hdr")
        .filter(|s| s.flags & SHF_ALLOC as u64 != 0 && s.addr != 0 && !s.data.is_empty());
    let debug_frame =
        find_elf_section(&elf, kernel_elf, ".debug_frame").filter(|s| !s.data.is_empty());

    let mut bases = BaseAddresses::default().set_text(text_base);
    if let Some(eh_frame) = eh_frame {
        bases = bases.set_eh_frame(eh_frame.addr);
    }
    if let Some(eh_frame_hdr) = eh_frame_hdr {
        bases = bases.set_eh_frame_hdr(eh_frame_hdr.addr);
    }

    let mut eh_functions = Vec::new();
    if let Some(eh_frame) = eh_frame {
        collect_eh_frame_entries(
            KernelElfCfiSection {
                data: eh_frame.data,
                kind: KernelElfCfiKind::EhFrame,
            },
            &bases,
            &mut eh_functions,
        );
    }

    let mut functions = if eh_functions.len() > 16 {
        eh_functions
    } else {
        let mut debug_functions = Vec::new();
        if let Some(debug_frame) = debug_frame {
            collect_debug_frame_entries(
                KernelElfCfiSection {
                    data: debug_frame.data,
                    kind: KernelElfCfiKind::DebugFrame,
                },
                &bases,
                &mut debug_functions,
            );
        }

        if debug_functions.is_empty() {
            eh_functions
        } else {
            debug_functions
        }
    };

    if functions.is_empty() {
        return None;
    }

    functions.sort_unstable_by(|a, b| {
        a.initial_location
            .cmp(&b.initial_location)
            .then(a.end.cmp(&b.end))
            .then(a.fde_offset.cmp(&b.fde_offset))
    });
    functions.dedup_by(|a, b| {
        a.initial_location == b.initial_location && a.end == b.end && a.fde_offset == b.fde_offset
    });

    Some(KernelElfUnwindModule {
        image_base,
        image_end,
        bases,
        functions,
    })
}

fn kernel_elf_file_bytes() -> Option<&'static [u8]> {
    let boot = boot_info();
    let kernel_addr = 0xFFFF_8500_0000_0000 + boot.kernel_image_offset;
    Some(unsafe { slice::from_raw_parts(kernel_addr as *const u8, boot.kernel_len as usize) })
}

fn kernel_elf_image_bounds(elf: &Elf<'_>) -> Option<(u64, u64)> {
    let mut image_base = u64::MAX;
    let mut image_end = 0u64;

    for header in &elf.program_headers {
        if header.p_type != PT_LOAD || header.p_memsz == 0 {
            continue;
        }
        image_base = image_base.min(header.p_vaddr);
        image_end = image_end.max(header.p_vaddr.checked_add(header.p_memsz)?);
    }

    if image_base == u64::MAX || image_end <= image_base {
        return None;
    }

    Some((image_base, image_end))
}

fn find_elf_section(elf: &Elf<'_>, bytes: &'static [u8], target: &str) -> Option<ElfSectionData> {
    for header in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(header.sh_name)?;
        if name != target {
            continue;
        }

        let offset = usize::try_from(header.sh_offset).ok()?;
        let size = usize::try_from(header.sh_size).ok()?;
        let end = offset.checked_add(size)?;
        let data = bytes.get(offset..end)?;
        return Some(ElfSectionData {
            data,
            addr: header.sh_addr,
            flags: header.sh_flags,
        });
    }

    None
}

fn make_eh_frame(data: &'static [u8]) -> EhFrame<GimliReader> {
    let mut frame = EhFrame::new(data, LittleEndian);
    frame.set_address_size(8);
    frame
}

fn make_debug_frame(data: &'static [u8]) -> DebugFrame<GimliReader> {
    let mut frame = DebugFrame::new(data, LittleEndian);
    frame.set_address_size(8);
    frame
}

fn collect_eh_frame_entries(
    section: KernelElfCfiSection,
    bases: &BaseAddresses,
    out: &mut Vec<ElfUnwindEntry>,
) {
    let frame = make_eh_frame(section.data);
    let mut entries = frame.entries(bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };

        let fde_offset = partial.offset();
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        push_gimli_fde(
            section,
            fde_offset,
            fde.initial_address(),
            fde.end_address(),
            out,
        );
    }
}

fn collect_debug_frame_entries(
    section: KernelElfCfiSection,
    bases: &BaseAddresses,
    out: &mut Vec<ElfUnwindEntry>,
) {
    let frame = make_debug_frame(section.data);
    let mut entries = frame.entries(bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };

        let fde_offset = partial.offset();
        let Ok(fde) = partial.parse(DebugFrame::cie_from_offset) else {
            continue;
        };
        push_gimli_fde(
            section,
            fde_offset,
            fde.initial_address(),
            fde.end_address(),
            out,
        );
    }
}

fn push_gimli_fde(
    section: KernelElfCfiSection,
    fde_offset: usize,
    initial_location: u64,
    end: u64,
    out: &mut Vec<ElfUnwindEntry>,
) {
    if initial_location == 0 || end <= initial_location {
        return;
    }

    out.push(ElfUnwindEntry {
        initial_location,
        end,
        fde_offset,
        section,
    });
}

fn unwind_elf_cfi(
    ctx: &mut UnwindContext,
    bounds: StackBounds,
    module: &KernelElfUnwindModule,
    entry: ElfUnwindEntry,
    control_pc: u64,
) -> Result<(), ElfUnwindError> {
    if control_pc < entry.initial_location || control_pc >= entry.end {
        return Err(ElfUnwindError::NoInfo);
    }

    match entry.section.kind {
        KernelElfCfiKind::EhFrame => unwind_eh_frame_cfi(ctx, bounds, module, entry, control_pc),
        KernelElfCfiKind::DebugFrame => {
            unwind_debug_frame_cfi(ctx, bounds, module, entry, control_pc)
        }
    }
}

fn unwind_eh_frame_cfi(
    ctx: &mut UnwindContext,
    bounds: StackBounds,
    module: &KernelElfUnwindModule,
    entry: ElfUnwindEntry,
    control_pc: u64,
) -> Result<(), ElfUnwindError> {
    let frame = make_eh_frame(entry.section.data);
    let fde = frame
        .fde_from_offset(
            &module.bases,
            EhFrameOffset(entry.fde_offset),
            EhFrame::cie_from_offset,
        )
        .map_err(map_gimli_error)?;
    let return_reg = fde.cie().return_address_register();
    let mut gimli_ctx = GimliUnwindContext::<usize, GimliUnwindStorage>::new_in();
    let row = fde
        .unwind_info_for_address(&frame, &module.bases, &mut gimli_ctx, control_pc)
        .map_err(map_gimli_error)?;
    apply_gimli_row(ctx, bounds, row, return_reg)
}

fn unwind_debug_frame_cfi(
    ctx: &mut UnwindContext,
    bounds: StackBounds,
    module: &KernelElfUnwindModule,
    entry: ElfUnwindEntry,
    control_pc: u64,
) -> Result<(), ElfUnwindError> {
    let frame = make_debug_frame(entry.section.data);
    let fde = frame
        .fde_from_offset(
            &module.bases,
            DebugFrameOffset(entry.fde_offset),
            DebugFrame::cie_from_offset,
        )
        .map_err(map_gimli_error)?;
    let return_reg = fde.cie().return_address_register();
    let mut gimli_ctx = GimliUnwindContext::<usize, GimliUnwindStorage>::new_in();
    let row = fde
        .unwind_info_for_address(&frame, &module.bases, &mut gimli_ctx, control_pc)
        .map_err(map_gimli_error)?;
    apply_gimli_row(ctx, bounds, row, return_reg)
}

fn map_gimli_error(error: gimli::Error) -> ElfUnwindError {
    match error {
        gimli::Error::NoUnwindInfoForAddress => ElfUnwindError::NoInfo,
        _ => ElfUnwindError::BadUnwindInfo,
    }
}

fn apply_gimli_row(
    ctx: &mut UnwindContext,
    bounds: StackBounds,
    row: &UnwindTableRow<usize, GimliUnwindStorage>,
    return_reg: Register,
) -> Result<(), ElfUnwindError> {
    let cfa = match row.cfa() {
        CfaRule::RegisterAndOffset { register, offset } => {
            let cfa_base = ctx
                .get_dwarf_reg(register.0)
                .ok_or(ElfUnwindError::BadUnwindInfo)?;
            add_signed(cfa_base, *offset).ok_or(ElfUnwindError::BadUnwindInfo)?
        }
        CfaRule::Expression(_) => return Err(ElfUnwindError::UnsupportedOpcode),
    };

    let mut next = *ctx;
    let return_address = gimli_rule_value(ctx, bounds, cfa, row.register(return_reg))?
        .ok_or(ElfUnwindError::BadUnwindInfo)?;

    for reg in [
        X86_64_DWARF_REG_RBX,
        X86_64_DWARF_REG_RBP,
        X86_64_DWARF_REG_RSI,
        X86_64_DWARF_REG_RDI,
        X86_64_DWARF_REG_R12,
        X86_64_DWARF_REG_R13,
        X86_64_DWARF_REG_R14,
        X86_64_DWARF_REG_R15,
    ] {
        if let Some(value) = gimli_rule_value(ctx, bounds, cfa, row.register(Register(reg)))? {
            next.set_dwarf_reg(reg, value);
        }
    }

    next.rip = return_address;
    next.rsp = cfa;
    next.rip_is_return_address = true;
    *ctx = next;
    Ok(())
}

fn gimli_rule_value(
    ctx: &UnwindContext,
    bounds: StackBounds,
    cfa: u64,
    rule: GimliRegisterRule<usize>,
) -> Result<Option<u64>, ElfUnwindError> {
    match rule {
        GimliRegisterRule::Undefined | GimliRegisterRule::SameValue => Ok(None),
        GimliRegisterRule::Offset(offset) => {
            let addr = add_signed(cfa, offset).ok_or(ElfUnwindError::BadUnwindInfo)?;
            read_stack_u64(bounds, addr)
                .map(Some)
                .ok_or(ElfUnwindError::BadStackRead)
        }
        GimliRegisterRule::ValOffset(offset) => add_signed(cfa, offset)
            .map(Some)
            .ok_or(ElfUnwindError::BadUnwindInfo),
        GimliRegisterRule::Register(reg) => ctx
            .get_dwarf_reg(reg.0)
            .map(Some)
            .ok_or(ElfUnwindError::BadUnwindInfo),
        GimliRegisterRule::Constant(value) => Ok(Some(value)),
        GimliRegisterRule::Expression(_)
        | GimliRegisterRule::ValExpression(_)
        | GimliRegisterRule::Architectural => Err(ElfUnwindError::UnsupportedOpcode),
        _ => Err(ElfUnwindError::UnsupportedOpcode),
    }
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

fn add_signed(value: u64, offset: i64) -> Option<u64> {
    if offset >= 0 {
        value.checked_add(offset as u64)
    } else {
        value.checked_sub(offset.unsigned_abs())
    }
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

    fn get_dwarf_reg(&self, reg: u16) -> Option<u64> {
        match reg {
            X86_64_DWARF_REG_RBX => Some(self.rbx),
            X86_64_DWARF_REG_RSI => Some(self.rsi),
            X86_64_DWARF_REG_RDI => Some(self.rdi),
            X86_64_DWARF_REG_RBP => Some(self.rbp),
            X86_64_DWARF_REG_RSP => Some(self.rsp),
            X86_64_DWARF_REG_R12 => Some(self.r12),
            X86_64_DWARF_REG_R13 => Some(self.r13),
            X86_64_DWARF_REG_R14 => Some(self.r14),
            X86_64_DWARF_REG_R15 => Some(self.r15),
            X86_64_DWARF_REG_RIP => Some(self.rip),
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

    fn set_dwarf_reg(&mut self, reg: u16, value: u64) {
        match reg {
            X86_64_DWARF_REG_RBX => self.rbx = value,
            X86_64_DWARF_REG_RSI => self.rsi = value,
            X86_64_DWARF_REG_RDI => self.rdi = value,
            X86_64_DWARF_REG_RBP => self.rbp = value,
            X86_64_DWARF_REG_RSP => self.rsp = value,
            X86_64_DWARF_REG_R12 => self.r12 = value,
            X86_64_DWARF_REG_R13 => self.r13 = value,
            X86_64_DWARF_REG_R14 => self.r14 = value,
            X86_64_DWARF_REG_R15 => self.r15 = value,
            X86_64_DWARF_REG_RIP => self.rip = value,
            _ => {}
        }
    }
}
