use crate::drivers::interrupt_index::send_eoi;
use crate::drivers::interrupt_index::InterruptIndex::Timer;
use crate::scheduling::scheduler::SCHEDULER;
use core::arch::asm;
use x86_64::registers::rflags::RFlags;
use x86_64::registers::segmentation::CS;
use x86_64::structures::gdt::SegmentSelector;
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::VirtAddr;
use crate::println;

#[repr(C)]
#[derive(Debug)]
pub(crate) struct State {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rbp: u64,
    pub(crate) rsp: u64,   // Stack pointer
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rip: u64,   // Instruction pointer
    pub(crate) rflags: u64,
    pub(crate) cs: u64,    // Code segment register
    pub(crate) ss: u64,    // Stack segment register
}
impl State {
    #[inline(always)]
    #[no_mangle]
    pub fn new() -> Self {
        let mut state = State {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            cs: 0,    // Initialize with zero
            ss: 0,    // Initialize with zero
        };
        state.update();
        state
    }
    pub fn update_from_interrupt(&mut self, rip: u64, rsp: u64, rflags: u64, cs: u64, ss: u64) {
        self.rip = rip;
        self.rsp = rsp;
        self.rflags = rflags;
        self.cs = cs;
        self.ss = ss;
    }

    /// Save the current CPU context into this `State` struct
    #[inline(always)]
    #[no_mangle]
    pub fn update(&mut self) {
        unsafe {
            asm!(
            "mov {0}, rax",
            "mov {1}, rbx",
            "mov {2}, rcx",
            "mov {3}, rdx",
            "mov {4}, rsi",
            "mov {5}, rdi",
            "mov {6}, rbp",
            out(reg) self.rax,
            out(reg) self.rbx,
            out(reg) self.rcx,
            out(reg) self.rdx,
            out(reg) self.rsi,
            out(reg) self.rdi,
            out(reg) self.rbp,
            );

            asm!(
            "mov {0}, r8",
            "mov {1}, r9",
            "mov {2}, r10",
            "mov {3}, r11",
            "mov {4}, r12",
            "mov {5}, r13",
            "mov {6}, r14",
            "mov {7}, r15",
            out(reg) self.r8,
            out(reg) self.r9,
            out(reg) self.r10,
            out(reg) self.r11,
            out(reg) self.r12,
            out(reg) self.r13,
            out(reg) self.r14,
            out(reg) self.r15,
            );
        }
    }
    pub fn restore_stack_frame(&mut self, mut _stack_frame: InterruptStackFrame) {
        unsafe {
            self.rflags |= 1 << 9; // Set the interrupt flag in `rflags`
           // self.rflags = 0x00000202;
            // Cast the read-only stack frame into a mutable raw pointer
            let mut new_stack_frame = InterruptStackFrame::new(VirtAddr::new(self.rip),
                                                               SegmentSelector(self.cs as u16),
                                                               RFlags::from_bits_retain(self.rflags),
                                                               VirtAddr::new(self.rsp),
                                                               SegmentSelector(self.ss as u16));
            // Update the stack frame fields
            _stack_frame.as_mut().write(*new_stack_frame);
        }
    }
    #[inline(always)]
    #[no_mangle]
    pub unsafe extern "C" fn restore(&mut self){
        asm!(
        "mov rax, {0}",
        "mov rbx, {1}",
        "mov rcx, {2}",
        "mov rdx, {3}",
        "mov rsi, {4}",
        "mov rdi, {5}",
        "mov rbp, {6}",
        in(reg) self.rax,
        in(reg) self.rbx,
        in(reg) self.rcx,
        in(reg) self.rdx,
        in(reg) self.rsi,
        in(reg) self.rdi,
        in(reg) self.rbp,
        );

        asm!(
        "mov r8, {0}",
        "mov r9, {1}",
        "mov r10, {2}",
        "mov r11, {3}",
        "mov r12, {4}",
        "mov r13, {5}",
        "mov r14, {6}",
        "mov r15, {7}",
        in(reg) self.r8,
        in(reg) self.r9,
        in(reg) self.r10,
        in(reg) self.r11,
        in(reg) self.r12,
        in(reg) self.r13,
        in(reg) self.r14,
        in(reg) self.r15,
        );
        SCHEDULER.force_unlock();
        /*
        self.rflags |= 1 << 9; // Set the interrupt flag in `rflags`

        asm!(
        "push {0}",     // Push SS
        "push {1}",     // push rsp
        "push {2}",     // Push RFLAGS
        "push {3}",     // Push CS
        "push {4}",     // Push RIP (instruction pointer)
        in(reg) self.ss,
        in(reg) self.rsp,
        in(reg) self.rflags,
        in(reg) self.cs,
        in(reg) self.rip,
        );
        send_eoi(Timer.as_u8());
        x86_64::instructions::bochs_breakpoint();
        asm!("iretq", options(noreturn));
 */
    }
    #[inline]
    #[no_mangle]
    pub unsafe extern "C" fn sysret_restore(&self) {
        // Restore general-purpose registers that sysret does not handle
        asm!(
        "mov rax, {0}",
        "mov rbx, {1}",
        "mov rdx, {2}",
        "mov rsi, {3}",
        "mov rdi, {4}",
        "mov rbp, {5}",
        "mov r8, {6}",
        "mov r9, {7}",
        "mov r10, {8}",
        "mov r12, {9}",
        "mov r13, {10}",
        "mov r14, {11}",
        "mov r15, {12}",
        in(reg) self.rax,
        in(reg) self.rbx,
        in(reg) self.rdx,
        in(reg) self.rsi,
        in(reg) self.rdi,
        in(reg) self.rbp,
        in(reg) self.r8,
        in(reg) self.r9,
        in(reg) self.r10,
        in(reg) self.r12,
        in(reg) self.r13,
        in(reg) self.r14,
        in(reg) self.r15,
        );

        // Ensure the stack pointer is correctly set for `sysret`
        asm!("mov rsp, {}", in(reg) self.rsp);

        // Use `sysret` to return to user mode
        asm!("sysretq", options(noreturn));
    }
}
fn function() {}

