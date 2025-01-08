use crate::drivers::interrupt_index::send_eoi;
use crate::drivers::interrupt_index::InterruptIndex::SysCall;
use crate::file_system::file::{File, OpenFlags};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::slice;
use x86_64::structures::idt::InterruptStackFrame;

fn println_wrapper(message_ptr: String) {
    let message = &*message_ptr;
    println!("{}", message);
}
fn u64_to_str_ptr(value: u64) -> Option<String> {
    // Convert u64 to a raw pointer
    let ptr = value as *const u8;

    if ptr.is_null() {
        return None;
    }

    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }

        let slice = slice::from_raw_parts(ptr, len);
        String::from_utf8(Vec::from(slice)).ok()
    }
}

pub extern "x86-interrupt" fn syscall_handler(_stack_frame: InterruptStackFrame) {
    let mut rax: u64;
    let mut param1: u64;
    let mut param2: u64;
    let mut param3: u64;
    let mut extra_params: u64;

    unsafe { asm!("mov {0}, rax", lateout(reg) rax); }
    unsafe { asm!("mov {0}, r8", lateout(reg) param1); }
    unsafe { asm!("mov {0}, r9", lateout(reg) param2); }
    unsafe { asm!("mov {0}, r10", lateout(reg) param3); }
    unsafe { asm!("mov {0}, r11", lateout(reg) extra_params); }
    let return_value: usize = 0;
    let params = unsafe { (extra_params as *mut SyscallParams).as_mut() };
    //all returns are buffers because im lazy
    match rax {
        //print syscall
        1 => {
            if let Some(string) = u64_to_str_ptr(param1) {
                println_wrapper(string)
            }
        }
        //destroy task syscall
        2 => {
            let mut scheduler = SCHEDULER.lock();
            scheduler.delete_task(param1).ok();
        }
        //create task
        3 => unsafe {
            SCHEDULER.lock().add_task(Task::new(param1 as usize, (*(param2 as *const String)).clone(), true));
        }
        //file open syscall 1st file path, 2nd ptr to flags array, 3rd sizeof flags, return buffer
        4 => {
            if let Some(path) = u64_to_str_ptr(param1) {
                let flags_ptr = param2 as *const OpenFlags;
                let flags: &[OpenFlags] = unsafe {
                    slice::from_raw_parts(flags_ptr, param3 as usize)
                };

                let result = File::open(path.as_str(), flags);
                if let Ok(file) = result {
                    unsafe {
                        *(param3 as *mut File) = file;
                    }
                }
            }
        }

        // File Read
        5 => {
            unsafe {
                let file_ptr = param1 as *mut File;
                let buffer_ptr = param2 as *mut u8;
                let buffer_len = param3 as usize;

                if file_ptr.is_null() || buffer_ptr.is_null() {
                    return;
                }

                let file = &mut *file_ptr;
                if let Ok(data) = file.read() {
                    let len = core::cmp::min(data.len(), buffer_len);
                    core::ptr::copy_nonoverlapping(data.as_ptr(), buffer_ptr, len);
                }
            }
        }

        // File Write
        6 => {
            unsafe {
                let file_ptr = param1 as *mut File;
                let buffer_ptr = param2 as *const u8;
                let buffer_len = param3 as usize;

                if file_ptr.is_null() || buffer_ptr.is_null() {
                    return;
                }

                let file = &mut *file_ptr;
                let data = slice::from_raw_parts(buffer_ptr, buffer_len);
                let _ = file.write(data);
            }
        }

        // File Delete
        7 => {
            unsafe {
                let file_ptr = param1 as *mut File;

                if file_ptr.is_null() {
                    return;
                }

                let file = &mut *file_ptr;
                let _ = file.delete();
            }
        }
        //get current task id, param 1 buffer to place id in
        8 => {
            {
                unsafe { *(param1 as *mut usize) = SCHEDULER.lock().get_current_task().id as usize; }
            }
        }
        //get task id by name
        9 => {}
        _ => {
            println!("Unknown syscall number: {}", rax);
        }
    }
    send_eoi(SysCall.as_u8());
}
///r8 - r10 first 3 params extra params in Syscallparams passed by a ptr in r11
#[derive(Clone)]
struct SyscallParams {
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
    extra_params: Vec<u64>,
}
impl SyscallParams {
    fn new() -> Self {
        SyscallParams {
            param1: 0,
            param2: 0,
            param3: 0,
            param4: 0,
            extra_params: vec![],
        }
    }
}