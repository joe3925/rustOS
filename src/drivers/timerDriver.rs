use x86_64::structures::idt::InterruptStackFrame;
use crate::drivers::interrupt_index::{send_eoi};
use crate::drivers::interrupt_index::InterruptIndex::Timer;

pub static mut TIMER:SystemTimer = SystemTimer::new();
pub struct SystemTimer {
    tick: i128,
}
impl SystemTimer{
    pub const fn new() -> Self{
        SystemTimer{tick:0}
    }
    pub fn increment(&mut self){
        self.tick += 1;
    }
    pub fn get_current_tick(&self) -> i128{
        self.tick
    }
}
pub(crate) extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    unsafe{TIMER.increment();}
    send_eoi(Timer.as_u8());
}