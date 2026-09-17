use core::arch::global_asm;

use crate::arch::aarch64::exception_handlers::{
    Aarch64ExceptionOrigin, dispatch_serror, dispatch_sync, handle_fiq,
};
use crate::arch::aarch64::scheduling::state::{FpuState, TaskContext};
use crate::idt::interrupt_impl::{InterruptGuard, irq_dispatch};
use crate::scheduling::scheduler::{ipi_handler_c, yield_handler_c};
use crate::structs::per_cpu::PERCPU_ACTIVE_EXCEPTION_FPU_OFF;

use super::super::timer;
use super::controller::{
    PANIC_STOP_SGI, SCHEDULER_SGI, TASK_YIELD_SGI, TLB_SHOOTDOWN_SGI, VIRTUAL_TIMER_PPI,
};
use super::init::controller;

pub type InterruptFrame = TaskContext;

const TASK_CONTEXT_SIZE: usize = core::mem::size_of::<InterruptFrame>();
const FPU_STATE_SIZE: usize = core::mem::size_of::<FpuState>();

const FPU_STATE_OFFSET: usize = TASK_CONTEXT_SIZE;
const FPCR_OFFSET: usize = FPU_STATE_OFFSET + 512;
const FPSR_OFFSET: usize = FPU_STATE_OFFSET + 520;
const PREVIOUS_FPU_FRAME_OFFSET: usize = FPU_STATE_OFFSET + FPU_STATE_SIZE;

/*
 * Keep the complete frame 16-byte aligned.
 *
 * Layout:
 *
 *   0x000 .. 0x10f    TaskContext       272 bytes
 *   0x110 .. 0x30f    q0..q31           512 bytes
 *   0x310 .. 0x317    FPCR                8 bytes
 *   0x318 .. 0x31f    FPSR                8 bytes
 *   0x320 .. 0x327    previous FPU ptr     8 bytes
 *   0x328 .. 0x32f    padding              8 bytes
 *
 * Total: 0x330 = 816 bytes.
 */
const EXCEPTION_FRAME_SIZE: usize = PREVIOUS_FPU_FRAME_OFFSET + 16;

const EXCEPTION_ORIGIN_CURRENT_EL_SP0: u64 = Aarch64ExceptionOrigin::CurrentElSp0 as u64;
const EXCEPTION_ORIGIN_CURRENT_EL_SPX: u64 = Aarch64ExceptionOrigin::CurrentElSpx as u64;
const EXCEPTION_ORIGIN_LOWER_EL_AARCH64: u64 = Aarch64ExceptionOrigin::LowerElAarch64 as u64;
const EXCEPTION_ORIGIN_LOWER_EL_AARCH32: u64 = Aarch64ExceptionOrigin::LowerElAarch32 as u64;

const _: () = {
    assert!(TASK_CONTEXT_SIZE == 272);
    assert!(FPU_STATE_SIZE == 528);

    assert!(FPU_STATE_OFFSET == 272);
    assert!(FPCR_OFFSET == 784);
    assert!(FPSR_OFFSET == 792);
    assert!(PREVIOUS_FPU_FRAME_OFFSET == 800);

    assert!(EXCEPTION_FRAME_SIZE == 816);
    assert!(EXCEPTION_FRAME_SIZE % 16 == 0);
};

#[derive(Clone, Copy)]
pub(super) struct InterruptToken {
    pub(super) raw: u32,
    pub(super) interrupt_id: u32,
}

global_asm!(
    r#"
    .macro SAVE_EXCEPTION_FRAME use_sp_el0
    sub sp, sp, #{frame_size}

    /*
     * Save every general-purpose register before using any of them as
     * exception-entry scratch registers.
     */
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]

    .if \use_sp_el0
    mrs x1, sp_el0
    .else
    add x1, sp, #{frame_size}
    .endif
    str x1, [sp, #248]

    mrs x1, elr_el1
    str x1, [sp, #256]

    mrs x1, spsr_el1
    str x1, [sp, #264]

    stp q0, q1, [sp, #272]
    stp q2, q3, [sp, #304]
    stp q4, q5, [sp, #336]
    stp q6, q7, [sp, #368]
    stp q8, q9, [sp, #400]
    stp q10, q11, [sp, #432]
    stp q12, q13, [sp, #464]
    stp q14, q15, [sp, #496]
    stp q16, q17, [sp, #528]
    stp q18, q19, [sp, #560]
    stp q20, q21, [sp, #592]
    stp q22, q23, [sp, #624]
    stp q24, q25, [sp, #656]
    stp q26, q27, [sp, #688]
    stp q28, q29, [sp, #720]
    stp q30, q31, [sp, #752]

    mrs x16, fpcr
    str x16, [sp, #{fpcr_offset}]

    mrs x16, fpsr
    str x16, [sp, #{fpsr_offset}]


    str xzr, [sp, #{previous_fpu_frame_offset}]

    mrs x16, tpidr_el1
    cbz x16, .Lno_percpu_fpu_frame\@

    ldr x17, [x16, #{active_fpu_off}]
    str x17, [sp, #{previous_fpu_frame_offset}]

    add x17, sp, #{fpu_state_offset}
    str x17, [x16, #{active_fpu_off}]

.Lno_percpu_fpu_frame\@:
    .endm

    .macro VECTOR_ENTRY label, handler, origin, use_sp_el0
    .balign 128
\label:
    SAVE_EXCEPTION_FRAME \use_sp_el0
    mov x0, sp
    mov x1, #\origin
    bl \handler
    b aarch64_exception_restore
    .endm

    .section .text.aarch64_vectors,"ax"
    .balign 2048
    .global aarch64_exception_vectors
aarch64_exception_vectors:
    b aarch64_current_sp0_sync
    .balign 128
    b aarch64_current_sp0_irq
    .balign 128
    b aarch64_current_sp0_fiq
    .balign 128
    b aarch64_current_sp0_serror
    .balign 128
    b aarch64_current_spx_sync
    .balign 128
    b aarch64_current_spx_irq
    .balign 128
    b aarch64_current_spx_fiq
    .balign 128
    b aarch64_current_spx_serror
    .balign 128
    b aarch64_lower_aarch64_sync
    .balign 128
    b aarch64_lower_aarch64_irq
    .balign 128
    b aarch64_lower_aarch64_fiq
    .balign 128
    b aarch64_lower_aarch64_serror
    .balign 128
    b aarch64_lower_aarch32_sync
    .balign 128
    b aarch64_lower_aarch32_irq
    .balign 128
    b aarch64_lower_aarch32_fiq
    .balign 128
    b aarch64_lower_aarch32_serror

    VECTOR_ENTRY aarch64_current_sp0_sync, aarch64_sync_handler, {origin_current_sp0}, 1
    VECTOR_ENTRY aarch64_current_sp0_irq, aarch64_irq_handler, {origin_current_sp0}, 1
    VECTOR_ENTRY aarch64_current_sp0_fiq, aarch64_fiq_handler, {origin_current_sp0}, 1
    VECTOR_ENTRY aarch64_current_sp0_serror, aarch64_serror_handler, {origin_current_sp0}, 1

    VECTOR_ENTRY aarch64_current_spx_sync, aarch64_sync_handler, {origin_current_spx}, 0
    VECTOR_ENTRY aarch64_current_spx_irq, aarch64_irq_handler, {origin_current_spx}, 0
    VECTOR_ENTRY aarch64_current_spx_fiq, aarch64_fiq_handler, {origin_current_spx}, 0
    VECTOR_ENTRY aarch64_current_spx_serror, aarch64_serror_handler, {origin_current_spx}, 0

    VECTOR_ENTRY aarch64_lower_aarch64_sync, aarch64_sync_handler, {origin_lower_aarch64}, 1
    VECTOR_ENTRY aarch64_lower_aarch64_irq, aarch64_irq_handler, {origin_lower_aarch64}, 1
    VECTOR_ENTRY aarch64_lower_aarch64_fiq, aarch64_fiq_handler, {origin_lower_aarch64}, 1
    VECTOR_ENTRY aarch64_lower_aarch64_serror, aarch64_serror_handler, {origin_lower_aarch64}, 1

    VECTOR_ENTRY aarch64_lower_aarch32_sync, aarch64_sync_handler, {origin_lower_aarch32}, 1
    VECTOR_ENTRY aarch64_lower_aarch32_irq, aarch64_irq_handler, {origin_lower_aarch32}, 1
    VECTOR_ENTRY aarch64_lower_aarch32_fiq, aarch64_fiq_handler, {origin_lower_aarch32}, 1
    VECTOR_ENTRY aarch64_lower_aarch32_serror, aarch64_serror_handler, {origin_lower_aarch32}, 1

aarch64_exception_restore:

    mrs x16, tpidr_el1
    cbz x16, .Lno_restore_fpu_frame_pointer

    ldr x17, [sp, #{previous_fpu_frame_offset}]
    str x17, [x16, #{active_fpu_off}]

.Lno_restore_fpu_frame_pointer:

    ldr x16, [sp, #{fpcr_offset}]
    msr fpcr, x16

    ldr x16, [sp, #{fpsr_offset}]
    msr fpsr, x16

    ldp q0, q1, [sp, #272]
    ldp q2, q3, [sp, #304]
    ldp q4, q5, [sp, #336]
    ldp q6, q7, [sp, #368]
    ldp q8, q9, [sp, #400]
    ldp q10, q11, [sp, #432]
    ldp q12, q13, [sp, #464]
    ldp q14, q15, [sp, #496]
    ldp q16, q17, [sp, #528]
    ldp q18, q19, [sp, #560]
    ldp q20, q21, [sp, #592]
    ldp q22, q23, [sp, #624]
    ldp q24, q25, [sp, #656]
    ldp q26, q27, [sp, #688]
    ldp q28, q29, [sp, #720]
    ldp q30, q31, [sp, #752]

    ldr x16, [sp, #256]
    msr elr_el1, x16

    ldr x16, [sp, #264]
    msr spsr_el1, x16

    tbnz x16, #4, .Lrestore_sp_el0
    tbz x16, #0, .Lrestore_sp_el0
    b .Lsp_restored

.Lrestore_sp_el0:
    ldr x17, [sp, #248]
    msr sp_el0, x17

.Lsp_restored:
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]

    /*
     * x16/x17 are restored last because they are used as scratch above.
     */
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]

    ldr x16, [sp, #128]
    ldr x17, [sp, #136]

    add sp, sp, #{frame_size}
    eret
"#,
    frame_size = const EXCEPTION_FRAME_SIZE,
    fpu_state_offset = const FPU_STATE_OFFSET,
    fpcr_offset = const FPCR_OFFSET,
    fpsr_offset = const FPSR_OFFSET,
    previous_fpu_frame_offset = const PREVIOUS_FPU_FRAME_OFFSET,
    active_fpu_off = const PERCPU_ACTIVE_EXCEPTION_FPU_OFF,
    origin_current_sp0 = const EXCEPTION_ORIGIN_CURRENT_EL_SP0,
    origin_current_spx = const EXCEPTION_ORIGIN_CURRENT_EL_SPX,
    origin_lower_aarch64 = const EXCEPTION_ORIGIN_LOWER_EL_AARCH64,
    origin_lower_aarch32 = const EXCEPTION_ORIGIN_LOWER_EL_AARCH32,
);

unsafe extern "C" {
    pub(crate) static aarch64_exception_vectors: u8;
}

#[unsafe(no_mangle)]
extern "C" fn aarch64_sync_handler(frame: &mut InterruptFrame, origin: u64) {
    dispatch_sync(frame, Aarch64ExceptionOrigin::from_raw(origin));
}

#[unsafe(no_mangle)]
extern "C" fn aarch64_irq_handler(frame: &mut InterruptFrame, _origin: u64) {
    let Some(token) = controller().acknowledge() else {
        return;
    };

    if token.interrupt_id == VIRTUAL_TIMER_PPI as u32 {
        unsafe { timer::handle_interrupt(frame) };
    } else if token.interrupt_id == SCHEDULER_SGI as u32 {
        unsafe { ipi_handler_c(frame) };
    } else if token.interrupt_id == TASK_YIELD_SGI as u32 {
        unsafe { yield_handler_c(frame) };
    } else if token.interrupt_id == TLB_SHOOTDOWN_SGI as u32 {
        let _interrupt_guard = InterruptGuard::new();
        crate::memory::paging::tlb::handle_remote_tlb_shootdown();
    } else if token.interrupt_id == PANIC_STOP_SGI as u32 {
        crate::platform::halt();
    } else {
        let _interrupt_guard = InterruptGuard::new();
        irq_dispatch(token.interrupt_id, frame);
    }

    controller().end_interrupt(token);
}

#[unsafe(no_mangle)]
extern "C" fn aarch64_fiq_handler(frame: &mut InterruptFrame, origin: u64) -> ! {
    handle_fiq(frame, Aarch64ExceptionOrigin::from_raw(origin))
}

#[unsafe(no_mangle)]
extern "C" fn aarch64_serror_handler(frame: &mut InterruptFrame, origin: u64) -> ! {
    dispatch_serror(frame, Aarch64ExceptionOrigin::from_raw(origin))
}
