use crate::platform::{ActivePlatform, TaskPlatform};

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

pub type State = <ActivePlatform as TaskPlatform>::TaskContext;
pub type FpuState = <ActivePlatform as TaskPlatform>::FpuState;
