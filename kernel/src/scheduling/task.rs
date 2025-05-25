use crate::gdt::GDT;
use crate::memory::paging::{
     allocate_kernel_stack, KERNEL_STACK_ALLOCATOR
};
use crate::scheduling::scheduler::kernel_task_end;
use crate::scheduling::state::State;
use crate::{function, println};
use alloc::boxed::Box;
use alloc::string::String;
use core::arch::asm;
use spin::Mutex;
use x86_64::VirtAddr;
use crate::memory::paging::RangeTracker;

#[derive(Debug)]
pub struct Task {
    pub(crate) name: String,
    pub(crate) context: State, // The CPU state for this task
    pub(crate) stack_start: u64,
    pub(crate) id: u64,
    pub(crate) terminated: bool,
    pub(crate) is_user_mode: bool,
    pub range_allocator: Option<RangeTracker>,
}
static ID: Mutex<u64> = Mutex::new(0);

impl Task {
pub fn new_usermode(entry_point: usize, stack_size: u64, name: String, stack_pointer: u64, allocator: RangeTracker) -> Self {
    let stack_top = stack_pointer;

    let mut state = State::new(0);
    state.rip = entry_point as u64;
    state.rsp = stack_top - 8;
    state.rflags = 0x00000202;

    unsafe {
        let stack_ptr = state.rsp as *mut u64;
        *stack_ptr = kernel_task_end as u64;
    }

    state.cs = GDT.1.user_code_selector.0 as u64 | 3;
    state.ss = GDT.1.user_data_selector.0 as u64 | 3;

    println!(
        "User-mode task created with RIP {:X}, STACK {:X}, ID {}",
        state.rip,
        state.rsp,
        *ID.lock()
    );

    let id = {
        let mut id_guard = ID.lock();
        *id_guard += 1;
        *id_guard
    };

    Self {
        name,
        context: state,
        stack_start: stack_top,
        id,
        terminated: false,
        is_user_mode: true,
        range_allocator: Some(allocator),
    }
}
pub fn new_kernelmode(entry_point: usize, stack_size: u64, name: String) -> Self {
    let stack_top = unsafe { allocate_kernel_stack(stack_size) }
        .expect("Failed to allocate kernel-mode stack");

    let mut state = State::new(0);
    state.rip = entry_point as u64;
    state.rsp = stack_top.as_u64() - 8;
    state.rflags = 0x00000202;

    unsafe {
        let stack_ptr = state.rsp as *mut u64;
        *stack_ptr = kernel_task_end as u64;
    }

    state.cs = GDT.1.kernel_code_selector.0 as u64;
    state.ss = GDT.1.kernel_data_selector.0 as u64;

    println!(
        "Kernel-mode task created with RIP {:X}, STACK {:X}, ID {}",
        state.rip,
        state.rsp,
        *ID.lock()
    );

    let id = {
        let mut id_guard = ID.lock();
        *id_guard += 1;
        *id_guard
    };

    Self {
        name,
        context: state,
        stack_start: stack_top.as_u64(),
        id,
        terminated: false,
        is_user_mode: false,
        range_allocator: None,
    }
}



    pub fn update_from_context(&mut self, context: State) {
        self.context = context;
    }
    pub fn destroy(&mut self) {
        if (self.is_user_mode) {
            todo!();
        } else {
            KERNEL_STACK_ALLOCATOR
                .lock()
                .deallocate(VirtAddr::new(self.stack_start));
        }
    }
    /// Prints the task's RIP, RSP, and ID in one line.
    pub fn print(&self) {
        println!(
            "Task ID: {}, RIP: {:X}, RSP: {:X}",
            self.id, self.context.rip, self.context.rsp
        );
    }
}

//Idle task to prevent return
pub(crate) extern "C" fn idle_task() {
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
pub unsafe fn test_syscall() {
    let syscall_number: u64 = 8;
    let boxed_id = Box::new(0);
    let id_addr: *mut u64 = Box::into_raw(boxed_id);

    unsafe {
        asm!(
        "mov r8, {1}",
        "mov rax, {0}",
        "int 0x80",
        in(reg) syscall_number,
        in(reg) id_addr,
        );
    }

    let boxed_id = Box::from_raw(id_addr);

    println!("Updated ID: {}", *boxed_id);
    //let arg1: *const u8 = "syscall!".as_ptr();

    /*let id_string = id.to_string(); // Store the String in a variable
    let arg1: *const u8 = id_string.as_ptr();
    asm!(
    "mov rax, {0}",
    "mov r8, {1}",
    "int 0x80",
    in(reg) syscall_number,
    in(reg) arg1,
    );*/
}
