use core::arch::asm;

#[repr(C)]
pub struct State {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    pub(crate) rsp: u64,   // Stack pointer
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    pub(crate) rip: u64,   // Instruction pointer
    pub(crate) rflags: u64,
    pub(crate) cs: u64,    // Code segment register
    pub(crate) ss: u64,    // Stack segment register
}

impl State {
    pub fn new() -> Self {
        let mut state = State {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            cs: 0,    // Initialize with zero
            ss: 0,    // Initialize with zero
        };
        state.update();
        state
    }

    /// Save the current CPU context into this `State` struct
    pub fn update(&mut self) {
        unsafe {
            asm!(
            "mov {0}, rax",
            "mov {1}, rbx",
            "mov {2}, rcx",
            "mov {3}, rdx",
            "mov {4}, rsi",
            "mov {5}, rdi",
            "mov {6}, rbp",
            "mov {7}, rsp",
            "pushfq",
            "pop {8}",         // Save rflags
            out(reg) self.rax,
            out(reg) self.rbx,
            out(reg) self.rcx,
            out(reg) self.rdx,
            out(reg) self.rsi,
            out(reg) self.rdi,
            out(reg) self.rbp,
            out(reg) self.rsp,
            out(reg) self.rflags,
            );

            asm!(
            "mov {0}, r8",
            "mov {1}, r9",
            "mov {2}, r10",
            "mov {3}, r11",
            "mov {4}, r12",
            "mov {5}, r13",
            "mov {6}, r14",
            "mov {7}, r15",
            out(reg) self.r8,
            out(reg) self.r9,
            out(reg) self.r10,
            out(reg) self.r11,
            out(reg) self.r12,
            out(reg) self.r13,
            out(reg) self.r14,
            out(reg) self.r15,
            );

            asm!(
            "lea {0}, [rip]",    // Save the current RIP (instruction pointer)
            out(reg) self.rip,
            );

            // Save the segment registers (cs and ss)
            asm!(
            "mov {0}, cs",       // Save the current code segment
            "mov {1}, ss",       // Save the current stack segment
            out(reg) self.cs,
            out(reg) self.ss,
            );
        }
    }

    /// Function to restore the CPU context from this State struct
    pub unsafe fn restore(&self) {
        asm!(
        "mov rax, {0}",
        "mov rbx, {1}",
        "mov rcx, {2}",
        "mov rdx, {3}",
        "mov rsi, {4}",
        "mov rdi, {5}",
        "mov rbp, {6}",
        "mov rsp, {7}",
        in(reg) self.rax,
        in(reg) self.rbx,
        in(reg) self.rcx,
        in(reg) self.rdx,
        in(reg) self.rsi,
        in(reg) self.rdi,
        in(reg) self.rbp,
        in(reg) self.rsp,
        );

        asm!(
        "mov r8, {0}",
        "mov r9, {1}",
        "mov r10, {2}",
        "mov r11, {3}",
        "mov r12, {4}",
        "mov r13, {5}",
        "mov r14, {6}",
        "mov r15, {7}",
        in(reg) self.r8,
        in(reg) self.r9,
        in(reg) self.r10,
        in(reg) self.r11,
        in(reg) self.r12,
        in(reg) self.r13,
        in(reg) self.r14,
        in(reg) self.r15,
        );

        // Restore the segment registers (cs and ss)
        asm!(
        "push {0}",     // Push SS
        "push {1}",     // Push RSP (stack pointer)
        "push {2}",     // Push RFLAGS
        "push {3}",     // Push CS
        "push {4}",     // Push RIP (instruction pointer)
        "iretq",        // Return to user mode
        in(reg) self.ss,
        in(reg) self.rsp,
        in(reg) self.rflags,
        in(reg) self.cs,
        in(reg) self.rip,
        );
    }
}

