use core::arch::asm;
use core::arch::x86_64::__cpuid;
use x86_64::structures::idt::InterruptStackFrame;
use crate::cpu::wait_cycle;
use crate::drivers::interrupt_index::{send_eoi, InterruptIndex};
use crate::drivers::interrupt_index::InterruptIndex::Timer;
use crate::executor::scheduler::SCHEDULER;
use crate::executor::state;
use crate::executor::state::State;
use crate::println;
use crate::util::{init, KERNEL_INITIALIZED};

pub static mut TIMER:SystemTimer = SystemTimer::new();
pub struct SystemTimer {
    tick: u128,
}
impl SystemTimer{
    pub const fn new() -> Self{
        SystemTimer{tick: 0}
    }
    pub fn increment(&mut self){
        self.tick += 1;
    }
    pub fn get_current_tick(&self) -> u128{
        self.tick
    }
}
pub(crate) extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {

    let (r12_val, r13_val, r14_val, r15_val, rbp_val): (u64, u64, u64, u64, u64);

    unsafe {
        asm!(
        "mov {0}, r12",
        "mov {1}, r13",
        "mov {2}, r14",
        "mov {3}, r15",
        "mov {4}, rbp",
        out(reg) r12_val,
        out(reg) r13_val,
        out(reg) r14_val,
        out(reg) r15_val,
        out(reg) rbp_val,
        options(nostack)
        );
    }
    let rip = _stack_frame.instruction_pointer.as_u64();
    let cs = _stack_frame.code_segment;
    let rflags = _stack_frame.cpu_flags;
    let rsp = _stack_frame.stack_pointer.as_u64();
    let ss = _stack_frame.stack_segment;
    // Check if the kernel has finished initializing
    //unsafe { println!("kernel init: {}", KERNEL_INITIALIZED) }
    //unsafe{println!("timer tick: {}, Kernel init: {}", TIMER.get_current_tick(), KERNEL_INITIALIZED)};

    if unsafe { KERNEL_INITIALIZED } {
        // Proceed with task scheduling if initialized
        let mut scheduler = SCHEDULER.lock();
        unsafe { TIMER.increment(); }
        unsafe { scheduler.create_idle(); }

        if(!scheduler.isEmpty()){
            scheduler.get_current_task().context.update_from_interrupt(rip, rsp, rflags.bits(), cs.0 as u64, ss.0 as u64, r12_val, r13_val, r14_val, r15_val, rbp_val);
            unsafe { scheduler.schedule_next(); }
            unsafe { scheduler.get_current_task().context.restore(); }
        }

    } else {
        // Kernel is not initialized yet, just send EOI and return to kernel

        send_eoi(Timer.as_u8());
    }
}
