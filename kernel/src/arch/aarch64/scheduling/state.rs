#[derive(Clone, Copy, Debug)]
pub struct TaskContext {
    pub rip: u64,
    pub sp: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub fp: u64,
    pub lr: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FpuState;

pub type TaskEntry = extern "C" fn(usize);
