use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::slice;
use crate::println;
use x86_64::structures::idt::InterruptStackFrame;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::file_system::file::{File, OpenFlags};

// Define the MSR addresses
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_SYSCALL_MASK: u32 = 0xC000_0084;
fn println_wrapper(message_ptr: String) {
    // Safety: We assume the caller guarantees that message_ptr is valid.
    let message = unsafe { &*message_ptr };
    println!("{}", message);
}
fn u64_to_str_ptr(value: u64) -> Option<String> {
    // Convert u64 to a raw pointer
    let ptr = value as *const u8;

    // Check if the pointer is null or not (to avoid dereferencing a null pointer)
    if ptr.is_null() {
        return None;
    }

    // Calculate the length of the string by scanning for a null terminator
    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }

        // Attempt to create a slice and then convert it to a str
        let slice = slice::from_raw_parts(ptr, len);
        String::from_utf8(Vec::from(slice)).ok()
    }
}

pub extern "x86-interrupt" fn syscall_handler(_stack_frame: InterruptStackFrame){
    let mut rax:u64;
    let mut param1:u64;
    let mut param2:u64;
    let mut param3:u64;
    let mut extra_params: u64;

    unsafe { asm!("mov {0}, rax", lateout(reg) rax); }
    unsafe { asm!("mov {0}, r8", lateout(reg) param1); }
    unsafe { asm!("mov {0}, r9", lateout(reg) param2); }
    unsafe { asm!("mov {0}, r10", lateout(reg) param3); }
    unsafe { asm!("mov {0}, r11", lateout(reg) extra_params); }
    let mut params = extra_params as *mut SyscallParams;
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
        3 =>{
            let mut scheduler = SCHEDULER.lock();
            scheduler.add_task(Task::new(param1 as usize, true));
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
                        *((*params).param1 as *mut File) = file;
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
        _ => {
            println!("Unknown syscall number: {}", rax);
        }
    }
}
///r8 - r10 first 3 params extra params in Syscallparams passed by a ptr in r11
struct SyscallParams{
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
    extra_params: Vec<u64>,

}
impl SyscallParams{
    fn new() -> Self{
        SyscallParams{
            param1: 0,
            param2: 0,
            param3: 0,
            param4: 0,
            extra_params: vec![],
        }
    }
}