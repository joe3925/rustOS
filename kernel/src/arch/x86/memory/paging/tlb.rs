use core::arch::naked_asm;

use kernel_types::arch::VirtAddr;
use x86_64::instructions;
use x86_64::VirtAddr as X86VirtAddr;

use crate::arch::drivers::interrupt_index::{send_eoi, IpiDest, IpiKind, LocalApic, APIC};
use crate::idt::{InterruptGuard, TLB_FLUSH_VECTOR};

pub fn local_flush_tlb_all() {
    instructions::tlb::flush_all();
}

pub fn local_flush_tlb_range(start: VirtAddr, size: u64, stride: u64) {
    let stride = if stride == 0 { return } else { stride };
    let mut addr = start.as_u64() & !(stride - 1);
    let Some(end) = start
        .as_u64()
        .checked_add(size)
        .and_then(|value| value.checked_add(stride - 1))
        .map(|value| value & !(stride - 1))
    else {
        instructions::tlb::flush_all();
        return;
    };

    while addr < end {
        let Ok(virt) = X86VirtAddr::try_new(addr) else {
            instructions::tlb::flush_all();
            return;
        };
        instructions::tlb::flush(virt);
        let Some(next) = addr.checked_add(stride) else {
            instructions::tlb::flush_all();
            return;
        };
        addr = next;
    }
}

pub fn broadcast_tlb_shootdown() -> bool {
    unsafe {
        if let Some(apic) = APIC.lock().as_ref() {
            apic.lapic.send_ipi(
                IpiDest::AllExcludingSelf,
                IpiKind::Fixed {
                    vector: TLB_FLUSH_VECTOR,
                },
            );
            return true;
        }
    }
    false
}

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
