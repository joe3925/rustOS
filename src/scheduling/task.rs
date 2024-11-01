use crate::drivers::timer_driver::TIMER;
use crate::gdt::GDT;
use crate::memory::paging::{allocate_kernel_stack, allocate_user_stack};
use crate::println;
use crate::scheduling::state::State;
use core::arch::asm;

#[derive(Debug)]
pub struct Task {
    pub(crate) context: State,  // The CPU state for this task
    pub(crate) is_user_mode: bool,
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
            println!("User-mode task created with RIP {:X}, STACK {:X}", state.rip, state.rsp);
        } else {
            // Set kernel mode segment selectors
            state.cs = GDT.1.kernel_code_selector.0 as u64;
            state.ss = GDT.1.kernel_data_selector.0 as u64;
            println!("Kernel-mode task created with RIP {:X}, STACK {:X}", state.rip, state.rsp);
        }

        // Create and return the new task
        Self {
            context: state,
            is_user_mode: is_user_mode,
        }
    }
    pub fn update_from_context(&mut self, context: State) {
        self.context = context;
    }
}


pub(crate) extern "C" fn idle_task() {
    loop {
        // The idle task does nothing but loop indefinitely
        unsafe { println!("Timer Tick:{}", TIMER.get_current_tick()); }
        x86_64::instructions::hlt();
    }
}
pub unsafe fn test_syscall() -> u64 {
    let syscall_number: u64 = 1; // replace with your syscall number
    let arg1: u64 = 0x0;         // replace with any argument if needed
    let result: u64;
    asm!(
    "mov rax, {0}",          // Move syscall number into rax
    "mov rdi, {1}",          // First argument
    "syscall",               // Execute syscall
    "mov {2}, rax",          // Store result in `result`
    in(reg) syscall_number,
    in(reg) arg1,
    out(reg) result,
    );
    result
}
