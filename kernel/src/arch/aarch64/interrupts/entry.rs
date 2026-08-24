use core::arch::global_asm;

use crate::idt::{InterruptGuard, irq_dispatch};

use super::init::controller;

#[repr(C)]
pub struct InterruptFrame {
    pub x: [u64; 31],
    pub sp: u64,
    pub elr: u64,
    pub spsr: u64,
}

#[derive(Clone, Copy)]
pub(super) struct InterruptToken {
    pub(super) raw: u32,
    pub(super) interrupt_id: u32,
}

global_asm!(
    r#"
    .section .text.aarch64_vectors,"ax"
    .balign 2048
    .global aarch64_exception_vectors
aarch64_exception_vectors:
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception

    .balign 16
aarch64_irq_entry:
    sub sp, sp, #272
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
    add x1, sp, #272
    str x1, [sp, #248]
    mrs x1, elr_el1
    str x1, [sp, #256]
    mrs x1, spsr_el1
    str x1, [sp, #264]
    mov x0, sp
    bl aarch64_irq_handler
    ldr x1, [sp, #256]
    msr elr_el1, x1
    ldr x1, [sp, #264]
    msr spsr_el1, x1
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #272
    eret

aarch64_unhandled_exception:
    msr daifset, #0xf
1:
    wfi
    b 1b
"#
);

unsafe extern "C" {
    pub(super) static aarch64_exception_vectors: u8;
}

#[unsafe(no_mangle)]
extern "C" fn aarch64_irq_handler(frame: &mut InterruptFrame) {
    let Some(token) = controller().acknowledge() else {
        return;
    };
    let _interrupt_guard = InterruptGuard::new();
    irq_dispatch(token.interrupt_id, frame);
    controller().end_interrupt(token);
}
