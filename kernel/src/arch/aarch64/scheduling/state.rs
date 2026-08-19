#[derive(Clone, Copy, Debug)]
pub struct TaskContext {
    pub rip: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FpuState;

pub type TaskEntry = extern "C" fn(usize);
