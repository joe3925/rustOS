use x86_64::structures::idt::InterruptStackFrame;
use crate::drivers::interrupt_index::{send_eoi, InterruptIndex};
use crate::drivers::interrupt_index::InterruptIndex::Timer;
use crate::{print, println};

pub(crate) extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    send_eoi(Timer.as_u8());
}