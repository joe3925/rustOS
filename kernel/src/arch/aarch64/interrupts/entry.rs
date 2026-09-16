use core::arch::global_asm;

use crate::arch::aarch64::exception_handlers::{
    Aarch64ExceptionOrigin, dispatch_serror, dispatch_sync, handle_fiq,
};
use crate::arch::aarch64::scheduling::state::TaskContext;
use crate::idt::interrupt_impl::{InterruptGuard, irq_dispatch};
use crate::scheduling::scheduler::{ipi_handler_c, yield_handler_c};

use super::super::timer;
use super::controller::{
    PANIC_STOP_SGI, SCHEDULER_SGI, TASK_YIELD_SGI, TLB_SHOOTDOWN_SGI, VIRTUAL_TIMER_PPI,
};
use super::init::controller;

pub type InterruptFrame = TaskContext;

const EXCEPTION_FRAME_SIZE: usize = core::mem::size_of::<InterruptFrame>();
const EXCEPTION_ORIGIN_CURRENT_EL_SP0: u64 = Aarch64ExceptionOrigin::CurrentElSp0 as u64;
const EXCEPTION_ORIGIN_CURRENT_EL_SPX: u64 = Aarch64ExceptionOrigin::CurrentElSpx as u64;
const EXCEPTION_ORIGIN_LOWER_EL_AARCH64: u64 = Aarch64ExceptionOrigin::LowerElAarch64 as u64;
const EXCEPTION_ORIGIN_LOWER_EL_AARCH32: u64 = Aarch64ExceptionOrigin::LowerElAarch32 as u64;

const _: () = assert!(EXCEPTION_FRAME_SIZE == 272);

#[derive(Clone, Copy)]
pub(super) struct InterruptToken {
    pub(super) raw: u32,
    pub(super) interrupt_id: u32,
}

global_asm!(
    r#"
    .macro SAVE_EXCEPTION_FRAME use_sp_el0
    sub sp, sp, #{frame_size}

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
