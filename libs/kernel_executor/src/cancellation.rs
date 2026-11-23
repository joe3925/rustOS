#[repr(C)]
pub struct TaskCancellationGuard {
    pub(crate) token: usize,
    pub(crate) cancelled: extern "C" fn(usize) -> bool,
    pub(crate) release: extern "C" fn(usize),
}

impl TaskCancellationGuard {
    pub fn is_cancelled(&self) -> bool {
        (self.cancelled)(self.token)
    }
}

impl Drop for TaskCancellationGuard {
    fn drop(&mut self) {
        (self.release)(self.token);
    }
}
