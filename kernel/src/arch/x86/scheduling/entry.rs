use core::arch::naked_asm;

use crate::scheduling::scheduler::{ipi_eoi_only, ipi_handler_c, kernel_task_end, yield_handler_c};

crate::x86_interrupt_entry!(
    #[unsafe(no_mangle)]
    pub ipi_entry,
    ipi_handler_c,
    idle_only = ipi_eoi_only
);

crate::x86_interrupt_entry!(pub yield_interrupt_entry, yield_handler_c);

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
