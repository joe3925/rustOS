use core::arch::asm;
use crate::drivers::interrupt_index::send_eoi;
use crate::drivers::interrupt_index::InterruptIndex::Timer;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::State;
use crate::{println, util};
use crate::util::KERNEL_INITIALIZED;
use x86_64::structures::idt::InterruptStackFrame;
use crate::console::{print_queue, CONSOLE};
use crate::scheduling::state;

pub static mut TIMER: SystemTimer = SystemTimer::new();
pub struct SystemTimer {
    tick: u128,
}
impl SystemTimer {
    pub const fn new() -> Self {
        SystemTimer { tick: 0 }
    }
    pub fn increment(&mut self) {
        self.tick += 1;
    }
    pub fn get_current_tick(&self) -> u128 {
        self.tick
    }
}
pub(crate) extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    let mut state = State::new();
    state.rip = _stack_frame.instruction_pointer.as_u64();
    state.cs = _stack_frame.code_segment.0 as u64;
    state.rflags = _stack_frame.cpu_flags.bits().clone();
    state.rsp = _stack_frame.stack_pointer.as_u64();
    state.ss = _stack_frame.stack_segment.0 as u64;

    unsafe { TIMER.increment(); }

    // Check if the kernel has finished initializing
    //unsafe { println!("kernel init: {}", KERNEL_INITIALIZED) }
unsafe{
        if  (KERNEL_INITIALIZED)  {
            util::unlock_statics();
            //unsafe { println!("timer tick: {}, Kernel init: {}", TIMER.get_current_tick(), KERNEL_INITIALIZED) };

            //unsafe { print_queue(); }

            // Proceed with task scheduling if initialized
        {
            SCHEDULER.force_unlock();
            let mut scheduler = SCHEDULER.lock();
            if (!scheduler.is_empty()) {
                scheduler.get_current_task().update_from_context(state);
            }
            unsafe { scheduler.schedule_next(); }

            unsafe {
                scheduler.get_current_task().context.restore_stack_frame(_stack_frame);
                scheduler.get_current_task().context.restore();
                send_eoi(Timer.as_u8());
            }
        }

    }
        else {
            // Kernel is not initialized yet, just send EOI and return to kernel
            send_eoi(Timer.as_u8());

        }
    }
}
