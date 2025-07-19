use crate::cpu::get_cpu_info;
use crate::gdt::PER_CPU_GDT;
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

#[derive(Debug, Clone)]
pub struct Task {
    pub name: String,
    pub context: State, // The CPU state for this task
    pub stack_start: u64,
    pub id: u64,
    pub terminated: bool,
    pub is_user_mode: bool,
    pub parent_pid: u64
}
impl Task {
pub fn new_usermode(entry_point: usize, stack_size: u64, name: String, stack_pointer: VirtAddr, parent_pid: u64) -> Self {
    let gdt = PER_CPU_GDT.lock();
    let id = get_cpu_info().get_feature_info().expect("NO CPUID").initial_local_apic_id();

    let stack_top = stack_pointer.as_u64();

    let mut state = State::new(0);
    state.rip = entry_point as u64;
    state.rsp = stack_top - 8;
    state.rflags = 0x00000202;

    unsafe {
        let stack_ptr = state.rsp as *mut u64;
        *stack_ptr = kernel_task_end as u64;
    }

    state.cs = gdt.selectors_per_cpu.get(id as usize).expect("").user_code_selector.0 as u64 | 3;
    state.ss = gdt.selectors_per_cpu.get(id as usize).expect("").user_data_selector.0 as u64 as u64 | 3;

    println!(
        "User-mode task created with RIP {:X}, STACK {:X}",
        state.rip,
        state.rsp,
    );

    Self {
        name,
        context: state,
        stack_start: stack_top,
        id: 0,
        terminated: false,
        is_user_mode: true,
        parent_pid
    }
}
pub fn new_kernelmode(entry_point: usize, stack_size: u64, name: String, parent_pid: u64) -> Self {
    let gdt = PER_CPU_GDT.lock();
    let id = get_cpu_info().get_feature_info().expect("NO CPUID").initial_local_apic_id();
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

    state.cs = gdt.selectors_per_cpu.get(id as usize).expect("").kernel_code_selector.0 as u64;
    state.ss = gdt.selectors_per_cpu.get(id as usize).expect("").kernel_data_selector.0 as u64;

    println!(
        "Kernel-mode task created with RIP {:X}, STACK {:X}",
        state.rip,
        state.rsp,
    );



    Self {
        name,
        context: state,
        stack_start: stack_top.as_u64(),
        id: 0,
        terminated: false,
        is_user_mode: false,
        parent_pid
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
