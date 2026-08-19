#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __chkstk() {
    core::arch::naked_asm!(
        "mov x16, sp",
        "mov x17, x15",
        "lsl x17, x17, #4",
        "cmp x17, #0x1000",
        "b.lo 2f",
        "1:",
        "sub x16, x16, #0x1000",
        "ldr xzr, [x16]",
        "sub x17, x17, #0x1000",
        "cmp x17, #0x1000",
        "b.hs 1b",
        "2:",
        "sub x16, x16, x17",
        "ldr xzr, [x16]",
        "ret"
    );
}
