use core::arch::naked_asm;

use crate::scheduling::scheduler::{ipi_eoi_only, ipi_handler_c, kernel_task_end, yield_handler_c};
use crate::scheduling::task::{IDLE_MAGIC_LOWER, IDLE_UUID_UPPER};

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn ipi_entry() {
    naked_asm!(
        "/* {upper} {lower} {eoi_only} */",
        "cli",
        "push rax",
        "mov  rax, {upper}",
        "cmp  r10, rax",
        "jne  9f",
        "mov  rax, {lower}",
        "cmp  r11, rax",
        "jne  9f",
        "pop  rax",
        crate::x86_interrupt_call_template!("", "{handler}"),
        "9:",
        "pop  rax",
        crate::x86_interrupt_call_template!("", "{eoi_only}"),
        upper = const IDLE_UUID_UPPER,
        lower = const IDLE_MAGIC_LOWER,
        handler = sym ipi_handler_c,
        eoi_only = sym ipi_eoi_only,
    );
}

#[unsafe(naked)]
pub extern "C" fn yield_interrupt_entry() {
    naked_asm!(
        "cli",
        crate::x86_interrupt_call_template!("", "{handler}"),
        handler = sym yield_handler_c,
    );
}

#[unsafe(naked)]
pub extern "C" fn task_return_trampoline() -> ! {
    naked_asm!(
        "cld",
        "sub rsp, 8",
        "mov qword ptr [rsp], 0",
        "jmp {task_end}",
        task_end = sym kernel_task_end,
    );
}

#[unsafe(naked)]
pub(crate) extern "C" fn idle_task(_ctx: usize) {
    naked_asm!("3:", "hlt", "jmp 3b",);
}
