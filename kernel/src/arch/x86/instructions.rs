use core::arch::asm;

pub fn invalid_opcode() -> ! {
    unsafe {
        asm!("ud2", options(noreturn));
    }
}
