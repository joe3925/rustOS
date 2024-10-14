use crate::executor::state::State;

pub struct Task {
    pub(crate) stack_pointer: usize,  // Pointer to the task's stack
    pub(crate) context: State,
    is_running: bool,      // Simple flag to track if the task is currently running
}

impl Task {
    pub fn new(stack_pointer: usize) -> Self {
        Self {
            stack_pointer,
            context: State::new(),
            is_running: false,
        }
    }
}
