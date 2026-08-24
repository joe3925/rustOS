use core::arch::asm;

pub unsafe fn task_yield_interrupt() {
    unsafe {
        asm!("int 0x80");
    }
}
