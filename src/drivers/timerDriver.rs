use core::arch::asm;
use x86_64::structures::idt::InterruptStackFrame;
use crate::drivers::interrupt_index::{send_eoi, InterruptIndex};
use crate::drivers::interrupt_index::InterruptIndex::Timer;
use crate::executor::scheduler::SCHEDULER;

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
pub(crate) extern "x86-interrupt"  fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    unsafe { TIMER.increment(); }
    SCHEDULER.lock().schedule_next();
    send_eoi(Timer.as_u8());
}
