use alloc::string::String;
use alloc::vec::Vec;
use core::slice;
use crate::gdt::GDT;
use crate::println;
use crate::scheduling::state::State;
use x86_64::registers::model_specific::Msr;

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
pub unsafe fn set_syscall_handler() {
    // Create Msr objects for each MSR
    let mut lstar = Msr::new(MSR_LSTAR);
    let mut star = Msr::new(MSR_STAR);
    let mut syscall_mask = Msr::new(MSR_SYSCALL_MASK);

    // Set the `LSTAR` MSR to the address of your custom handler
    lstar.write(syscall_handler as u64);

    // Set up `STAR` for code segment configuration (example values)
    let kernel_cs = GDT.1.kernel_code_selector.0 as u64;   // Kernel code segment
    let user_cs = GDT.1.user_code_selector.0 as u64;     // User code segment with RPL=3
    let star_value = (user_cs << 48) | (kernel_cs << 32);
    star.write(star_value as u64);

    // Set the syscall flag mask, clearing certain flags
    syscall_mask.write(0x3F4);  // Example: clear DF, TF, IF, AC, and RF
}
extern "x86-interrupt" fn syscall_handler() {
    let mut state = State::new();

    // Syscall number rax
    // First argument rdi
    // Second argument rsi
    // Third argument rdx
    // Fourth argument r10
    // Fifth argument r8
    // Sixth argument r9

    // Use rax to match on syscall numbers

    match state.rax {
        1 => {
            println!("Syscall");
            /*let param = state.rdi;
            if let Some(string) = u64_to_str_ptr(param) {
                println_wrapper(string)
            }*/
        }
        _ => {
            println!("Unknown syscall number: {}", state.rax);
        }
    }
}