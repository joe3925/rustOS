use core::arch::asm;
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
    pub fn new_user_task(entry_point: usize, user_stack_top: usize) -> Self {
        let mut state = State::new();
        state.rip = entry_point as u64;   // Set the instruction pointer to the user function
        state.rsp = user_stack_top as u64; // Set the stack pointer for the task
        state.rflags = 0x202;              // Set default rflags (interrupt enable)

        // Set segment selectors to user-mode (ring 3) values
        // These values need to be appropriate for your GDT setup
        state.cs = USER_CODE_SEGMENT;
        state.ss = USER_DATA_SEGMENT;

        Self {
            stack_pointer: user_stack_top,
            context: state,
            is_running: false,
        }
    }
}
pub(crate) fn idle_task() {
    loop {
        // The idle task does nothing but loop indefinitely
        unsafe { asm!("hlt"); } // Halt the CPU until the next interrupt
    }
}
