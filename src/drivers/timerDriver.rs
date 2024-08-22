use x86_64::structures::idt::InterruptStackFrame;
use crate::drivers::interrupt_index::{send_eoi};
use crate::drivers::interrupt_index::InterruptIndex::Timer;

pub(crate) extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    send_eoi(Timer.as_u8());
}