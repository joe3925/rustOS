use crate::drivers::interrupt_index::get_current_logical_id;

use crate::executable::program::{Message, UserHandle};
use crate::file_system::file::{File, OpenFlags};
use crate::gdt::PER_CPU_GDT;
use crate::println;
use crate::syscalls::syscall_impl::*;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::naked_asm;
use core::slice;
use x86_64::registers::control::{Efer, EferFlags};
use x86_64::registers::model_specific::{LStar, Star};
use x86_64::VirtAddr;

pub fn syscall_init() {
    let gdt = PER_CPU_GDT.lock();
    unsafe { Efer::update(|e| e.set(EferFlags::SYSTEM_CALL_EXTENSIONS, true)) };
    LStar::write(VirtAddr::new(syscall_entry as u64));
    let id = get_current_logical_id();
    let kernel_cs = gdt
        .selectors_per_cpu
        .get(id as usize)
        .expect("")
        .kernel_code_selector;
    let kernel_ss = gdt
        .selectors_per_cpu
        .get(id as usize)
        .expect("")
        .kernel_data_selector;
    let user_cs = gdt
        .selectors_per_cpu
        .get(id as usize)
        .expect("")
        .user_code_selector;
    let user_ss = gdt
        .selectors_per_cpu
        .get(id as usize)
        .expect("")
        .user_data_selector;

    Star::write(user_cs, user_ss, kernel_cs, kernel_ss).expect("Bad STAR segment selectors");
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rax: u64,
}
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() -> ! {
    naked_asm!(
        "push rax",
        "push rbp",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        "mov  rax, rsp",
        "and  rsp, -16",
        "sub  rsp, 8",
        "mov  [rsp], rax",
        "mov  rdi, rax",
        "call {handler}",
        "mov  rsp, [rsp]",

        "pop  r15",
        "pop  r14",
        "pop  r13",
        "pop  r12",
        "pop  r11",
        "pop  r10",
        "pop  r9",
        "pop  r8",
        "pop  rdi",
        "pop  rsi",
        "pop  rdx",
        "pop  rcx",
        "pop  rbx",
        "pop  rbp",
        "pop  rax",

        "sysretq",

        handler = sym syscall_handler,
    );
}
type Handler = unsafe fn(u64, u64, u64, u64, *const u64) -> u64;

macro_rules! make_wrapper {
    ($wrap:ident, $real:path $(, $t:ty )* $(,)?) => {
        #[inline(always)]
        unsafe fn $wrap(rcx: u64, rdx: u64, r8: u64, r9: u64,
                        rest: *const u64) -> u64 {
            let regs = [rcx, rdx, r8, r9];
            let mut idx = 0usize;
            #[inline(always)]
            unsafe fn next(regs: &[u64;4], rest: *const u64, idx: &mut usize) -> u64 {
                let v = if *idx < 4 { regs[*idx] } else { *rest.add(*idx - 4) };
                *idx += 1;
                v
            }
            $real(
                $( next(&regs, rest, &mut idx) as $t ),*
            ) as u64
        }
    };
}

make_wrapper!(wrap_print, sys_print, *const u8);
make_wrapper!(wrap_destroy, sys_destroy_task, u64);
make_wrapper!(wrap_create, sys_create_task, usize);
make_wrapper!(
    wrap_file_open,
    sys_file_open,
    *const u8,
    *const OpenFlags,
    usize,
    *mut File
);
make_wrapper!(wrap_file_read, sys_file_read, *mut File, usize);
make_wrapper!(wrap_file_write, sys_file_write, *mut File, *const u8, usize);
make_wrapper!(wrap_file_delete, sys_file_delete, *mut File);
make_wrapper!(wrap_get_thread, sys_get_thread,);
make_wrapper!(wrap_mq_request, sys_mq_request, UserHandle, *mut Message);
make_wrapper!(wrap_mq_route_add, sys_rule_add, *const UserRoutingRule);
make_wrapper!(wrap_mq_route_clear, sys_rule_clear, *const UserRoutingRule);
make_wrapper!(wrap_mq_peek, sys_mq_peek, UserHandle, *mut Message);
make_wrapper!(
    wrap_mq_receive,
    sys_mq_receive,
    UserHandle,
    *mut Message,
    u32
);
make_wrapper!(wrap_get_default_mq_handle, sys_get_default_mq_handle,);
make_wrapper!(wrap_create_mq, sys_create_mq,);

const SYSCALL_TABLE: &[Handler] = &[
    wrap_print,                 // 0
    wrap_destroy,               // 1
    wrap_create,                // 2
    wrap_file_open,             // 3
    wrap_file_read,             // 4
    wrap_file_write,            // 5
    wrap_file_delete,           // 6
    wrap_get_thread,            // 7
    wrap_mq_request,            // 8
    wrap_mq_route_add,          // 9
    wrap_mq_route_clear,        // 10
    wrap_mq_peek,               // 11
    wrap_mq_receive,            // 12
    wrap_get_default_mq_handle, // 13
    wrap_create_mq,             // 14
];

#[no_mangle]
pub extern "C" fn syscall_handler(frame: &mut SyscallFrame) {
    let num = frame.rax as usize;
    // stack args start immediately after the pushed register block
    let rest_ptr = unsafe { (frame as *const SyscallFrame).add(1) } as *const u64;

    frame.rax = if let Some(h) = SYSCALL_TABLE.get(num) {
        unsafe { h(frame.r10, frame.rdx, frame.r8, frame.r9, rest_ptr) }
    } else {
        0
    };
}
