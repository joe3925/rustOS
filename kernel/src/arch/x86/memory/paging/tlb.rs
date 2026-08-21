use core::arch::naked_asm;

use super::super::super::drivers::interrupt_index::send_eoi;
use super::super::super::idt::TLB_FLUSH_VECTOR;
use crate::idt::InterruptGuard;

extern "C" fn tlb_flush_ipi() {
    let _guard = InterruptGuard::new();
    crate::memory::paging::tlb::handle_remote_tlb_shootdown();
    send_eoi(TLB_FLUSH_VECTOR);
}

#[unsafe(naked)]
pub extern "C" fn tlb_flush_entry() {
    naked_asm!(
        "cli",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",

        "mov  rcx, rsp",
        "mov  rbx, rsp",
        "cld",
        "and  rsp, -16",
        "sub  rsp, 32",
        "call {handler}",
        "mov  rsp, rbx",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",
        handler = sym tlb_flush_ipi,
    );
}
