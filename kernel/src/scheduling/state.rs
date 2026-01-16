use core::arch::asm;

/// Scheduling state for a task - stored atomically outside the Task RwLock
/// to allow lock-free checks in the scheduler hot path.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedState {
    /// Task is in a run queue and eligible to be scheduled
    Runnable = 0,
    /// Task is currently executing on a CPU
    Running = 1,
    /// Task is in the process of parking; still running on CPU
    Parking = 2,
    /// Task is blocked waiting for an event (mutex, channel, condvar, sleep)
    Blocked = 3,
    /// Task has finished execution and can be cleaned up
    Terminated = 4,
}

impl SchedState {
    /// Convert from raw u8 value
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => SchedState::Runnable,
            1 => SchedState::Running,
            2 => SchedState::Parking,
            3 => SchedState::Blocked,
            4 => SchedState::Terminated,
            _ => SchedState::Terminated, // Invalid values treated as terminated
        }
    }
}

/// Reason why a task is blocked - for diagnostics and debugging.
/// Stored as AtomicU32 for efficient atomic access.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Not blocked
    None = 0,
    /// Waiting to acquire a mutex
    MutexLock = 1,
    /// Waiting to receive from a channel
    ChannelRecv = 2,
    /// Waiting to send to a channel (backpressure)
    ChannelSend = 3,
    /// Waiting on a condition variable
    CondvarWait = 4,
    /// Sleeping for a duration
    Sleep = 5,
    /// Waiting for I/O completion
    IoWait = 6,
    /// Waiting for a futex
    FutexWait = 7,
    /// Waiting to join another task
    TaskJoin = 8,
    /// Waiting for an IRQ/interrupt
    IrqWait = 9,
}

impl BlockReason {
    /// Convert from raw u32 value
    #[inline]
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => BlockReason::None,
            1 => BlockReason::MutexLock,
            2 => BlockReason::ChannelRecv,
            3 => BlockReason::ChannelSend,
            4 => BlockReason::CondvarWait,
            5 => BlockReason::Sleep,
            6 => BlockReason::IoWait,
            7 => BlockReason::FutexWait,
            8 => BlockReason::TaskJoin,
            9 => BlockReason::IrqWait,
            _ => BlockReason::None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
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
            cs: 0,
            ss: 0,
        };
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
