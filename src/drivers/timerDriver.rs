use core::arch::asm;
use x86_64::structures::idt::InterruptStackFrame;
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
    unsafe { TIMER.increment(); }

    // Check if the kernel has finished initializing
    //unsafe { println!("kernel init: {}", KERNEL_INITIALIZED) }
    //unsafe{println!("timer tick: {}, Kernel init: {}", TIMER.get_current_tick(), KERNEL_INITIALIZED)};
    if unsafe { KERNEL_INITIALIZED } {
        // Proceed with task scheduling if initialized
        let mut scheduler = SCHEDULER.lock();
        scheduler.schedule_next();
        println!("here");
        unsafe { if(scheduler.get_current_task().isUserMode == true){asm!("iret");} }
        send_eoi(Timer.as_u8());

    } else {
        // Kernel is not initialized yet, just send EOI and return to kernel
        send_eoi(Timer.as_u8());
    }
}
