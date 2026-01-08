use core::arch::asm;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxState {
    pub data: [u8; 512],
}
impl FxState {
    #[inline(always)]
    pub unsafe fn save_fx(&mut self) {
        asm!("fxsave [{}]", in(reg) self.data.as_mut_ptr(), options(nostack));
    }

    #[inline(always)]
    pub unsafe fn restore_fx(&self) {
        asm!("fxrstor [{}]", in(reg) self.data.as_ptr(), options(nostack));
    }
}
impl core::fmt::Debug for FxState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FxState").finish_non_exhaustive()
    }
}

impl Default for FxState {
    fn default() -> Self {
        Self { data: [0u8; 512] }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct State {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}
impl State {
    #[inline(always)]
    pub fn new(rax: u64) -> Self {
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
            cs: 0, // Initialize with zero
            ss: 0, // Initialize with zero
        };
        state.update(rax);
        state
    }
    pub fn update_from_interrupt(&mut self, rip: u64, rsp: u64, rflags: u64, cs: u64, ss: u64) {
        self.rip = rip;
        self.rsp = rsp;
        self.rflags = rflags;
        self.cs = cs;
        self.ss = ss;
    }

    /// Save the current CPU context into this `State` struct
    #[inline(always)]
    pub fn update(&mut self, rax: u64) {
        unsafe {
            asm!(
            "mov {0}, rbx",
            "mov {1}, rcx",
            "mov {2}, rdx",
            "mov {3}, rsi",
            "mov {4}, rdi",
            "mov {5}, rbp",
            lateout(reg) self.rbx,
            lateout(reg) self.rcx,
            lateout(reg) self.rdx,
            lateout(reg) self.rsi,
            lateout(reg) self.rdi,
            lateout(reg) self.rbp,
            options(nostack, preserves_flags, pure, readonly),
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
            lateout(reg) self.r8,
            lateout(reg) self.r9,
            lateout(reg) self.r10,
            lateout(reg) self.r11,
            lateout(reg) self.r12,
            lateout(reg) self.r13,
            lateout(reg) self.r14,
            lateout(reg) self.r15,
            options(nostack, preserves_flags, pure, readonly),
            );
        }
        self.rax = rax;
    }

    #[inline(always)]
    pub unsafe extern "C" fn restore(&self, state: *mut State) {
        core::ptr::write(state, *self);
    }
}
fn function() {}
