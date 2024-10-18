use core::arch::asm;
use crate::executor::state::State;
use crate::gdt::GDT;
use crate::println;

pub struct Task {
    pub(crate) context: State,  // The CPU state for this task
    pub(crate) isUserMode: bool,
}

impl Task {
    // Create a new task for user mode or kernel mode
    pub fn new(entry_point: usize, stack_top: usize, is_user_mode: bool) -> Self {
        let mut state = State::new();
        state.rip = entry_point as u64;    // Set the instruction pointer to the task entry point
        state.rsp = stack_top as u64;      // Set the stack pointer

        if is_user_mode {
            // Set up user mode segment selectors
            state.cs = GDT.1.user_code_selector.0 as u64;
            state.ss = GDT.1.user_data_selector.0 as u64;
        } else {
            // Set up kernel mode segment selectors
            state.cs = GDT.1.kernel_code_selector.0 as u64;
            state.ss = GDT.1.kernel_data_selector.0 as u64;
        }

        Self {
            context: state,
            isUserMode: is_user_mode,
        }
    }
}

pub(crate) const extern "C" fn idle_task() {
    loop {
        // The idle task does nothing but loop indefinitely
        panic!();
    }
}
