use crate::gdt::GDT;
use crate::memory::paging::{allocate_kernel_stack, allocate_user_stack, KERNEL_STACK_ALLOCATOR, USER_STACK_ALLOCATOR};
use crate::println;
use crate::scheduling::state::State;
use core::arch::asm;
use x86_64::VirtAddr;
use crate::scheduling::scheduler::kernel_task_end;
use crate::util::KERNEL_INITIALIZED;

#[derive(Debug)]
pub struct Task {
    pub(crate) context: State,  // The CPU state for this task
    pub(crate) stack_start: u64,
    pub(crate) id: u64,
    pub(crate) terminated: bool,
    pub(crate) is_user_mode: bool,
}

impl Task {
    pub fn new(
        entry_point: usize,
        is_user_mode: bool,
    ) -> Self {
        // Allocate the stack depending on the task mode
        static mut ID: u64 = 0;
        let stack_top = if is_user_mode {
            // Allocate a user-mode stack and map it
            unsafe { allocate_user_stack() }
                .expect("Failed to allocate user-mode stack")
        } else {
            // Allocate a kernel-mode stack
            unsafe { allocate_kernel_stack() }
                .expect("Failed to allocate kernel-mode stack")
        };

        // Initialize the state with the entry point and the allocated stack top
        let mut state = State::new(0);
        state.rip = entry_point as u64;    // Set the instruction pointer to the task entry point
        state.rsp = (stack_top.as_u64() - 8) as u64; // Reserve 8 bytes for the return address
        state.rflags = 0x00000202;

        // Push the return address onto the stack
        unsafe {
            let stack_ptr = state.rsp as *mut u64;
            *stack_ptr = kernel_task_end as u64; // Store the return address at the current top of the stack
        }

        // Set up segment selectors based on the task mode
        if is_user_mode {
            // Set user mode segment selectors
            state.cs = GDT.1.user_code_selector.0 as u64 | 3;
            state.ss = GDT.1.user_data_selector.0 as u64 | 3;
            unsafe { println!("User-mode task created with RIP {:X}, STACK {:X}, ID {}", state.rip, state.rsp, ID); }
        } else {
            // Set kernel mode segment selectors
            state.cs = GDT.1.kernel_code_selector.0 as u64;
            state.ss = GDT.1.kernel_data_selector.0 as u64;
            unsafe { println!("Kernel-mode task created with RIP {:X}, STACK {:X}, ID {}", state.rip, state.rsp, ID); }
        }

        // Create and return the new task
        unsafe {
            ID += 1;
            Self {
                context: state,
                stack_start: stack_top.as_u64(),
                id: ID,
                terminated: false,
                is_user_mode,
            }
        }
    }

    pub fn update_from_context(&mut self, context: State) {
        self.context = context;
    }
    pub fn destroy(&mut self){
        if(self.is_user_mode){
            unsafe { USER_STACK_ALLOCATOR.lock().deallocate(VirtAddr::new(self.stack_start)); }
        }else{
            unsafe { KERNEL_STACK_ALLOCATOR.lock().deallocate(VirtAddr::new(self.stack_start)); }
        }
    }
    /// Prints the task's RIP, RSP, and ID in one line.
    pub fn print(&self) {
        unsafe {
            println!(
                "Task ID: {}, RIP: {:X}, RSP: {:X}",
                self.id, self.context.rip, self.context.rsp
            );
        }
    }

}


pub(crate) fn idle_task() -> ! {
    //x86_64::instructions::bochs_breakpoint();
    let mut i = 0;
    loop {
      println!("hello world, {}", i);
        i += 1;

    }
}
pub unsafe fn test_syscall() {
    let syscall_number: u64 = 1; // replace with your syscall number
    let arg1: *const u8 = "syscall!".as_ptr();         // replace with any argument if needed
    let result: u64;
    asm!(
    "mov rax, {0}",          // Move syscall number into rax
    "mov r8, {1}",          // First argument
    "int 0x80",               // Execute syscall
    in(reg) syscall_number,
    in(reg) arg1,
    );
}
