use core::arch::asm;
use core::arch::x86_64::__cpuid;
use x86_64::structures::idt::InterruptStackFrame;
use crate::cpu::wait_cycle;
use crate::drivers::interrupt_index::{send_eoi, InterruptIndex};
use crate::drivers::interrupt_index::InterruptIndex::Timer;
use crate::executor::scheduler::SCHEDULER;
use crate::println;
use crate::util::KERNEL_INITIALIZED;

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
    //these variables are on the stack and must be captured before any other function is called
    let rip = _stack_frame.instruction_pointer.as_u64();
    let cs = _stack_frame.code_segment;
    let rflags = _stack_frame.cpu_flags;
    let rsp = _stack_frame.stack_pointer.as_u64();
    let ss = _stack_frame.stack_segment;

    unsafe { TIMER.increment(); }

    // Check if the kernel has finished initializing
    //unsafe { println!("kernel init: {}", KERNEL_INITIALIZED) }
    //unsafe{println!("timer tick: {}, Kernel init: {}", TIMER.get_current_tick(), KERNEL_INITIALIZED)};

    if unsafe { KERNEL_INITIALIZED } {

        // Proceed with task scheduling if initialized
        let mut scheduler = SCHEDULER.lock();
        if(!scheduler.isEmpty()){
            scheduler.get_current_task().context.update_from_interrupt(rip, rsp, rflags.bits(), cs.0 as u64, ss.0 as u64);
        }
        wait_cycle(1000000000);
        scheduler.schedule_next();

        send_eoi(Timer.as_u8());

        unsafe { scheduler.get_current_task().context.restore(); }

    } else {
        // Kernel is not initialized yet, just send EOI and return to kernel
        send_eoi(Timer.as_u8());
    }
}
