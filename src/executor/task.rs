use core::arch::asm;
use crate::executor::state::State;
use crate::gdt::GDT;
use crate::memory::paging::{allocate_kernel_stack, allocate_user_stack};
use crate::{panic, println};
use crate::memory::paging;

pub struct Task {
    pub(crate) context: State,  // The CPU state for this task
    pub(crate) isUserMode: bool,
}

impl Task {
    pub fn new(
        entry_point: usize,
        stack_size: u64,
        is_user_mode: bool,
    ) -> Self {
        // Allocate the stack depending on the task mode
        let stack_top = if is_user_mode {
            // Allocate a user-mode stack and map it
            unsafe { allocate_user_stack(stack_size) }
                .expect("Failed to allocate user-mode stack")
        } else {
            // Allocate a kernel-mode stack
            unsafe { allocate_kernel_stack(stack_size) }
                .expect("Failed to allocate kernel-mode stack")
        };

        // Initialize the state with the entry point and the allocated stack top
        let mut state = State::new();
        state.rip = entry_point as u64;    // Set the instruction pointer to the task entry point
        state.rsp = stack_top.as_u64();    // Set the stack pointer to the top of the allocated stack

        // Set up segment selectors based on the task mode
        if is_user_mode {
            // Set user mode segment selectors
            state.cs = GDT.1.user_code_selector.0 as u64 | 3;
            state.ss = GDT.1.user_data_selector.0 as u64 | 3;
            println!("User-mode task created with CS: {}, SS: {}", state.cs, state.ss);

        } else {
            // Set kernel mode segment selectors
            state.cs = GDT.1.kernel_code_selector.0 as u64;
            state.ss = GDT.1.kernel_data_selector.0 as u64;
        }

        // Create and return the new task
        Self {
            context: state,
            isUserMode: is_user_mode,
        }
    }
}


pub(crate) extern "C" fn idle_task() {
    loop {
        // The idle task does nothing but loop indefinitely
        println!("hello world")
    }
}
