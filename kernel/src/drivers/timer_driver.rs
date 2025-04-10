use crate::console::print_queue;
use crate::drivers::interrupt_index::{send_eoi, InterruptIndex};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::State;
use crate::util::KERNEL_INITIALIZED;
use core::arch::asm;
use core::sync::atomic::Ordering;
use spin::Mutex;
use x86_64::structures::idt::InterruptStackFrame;

pub static TIMER: Mutex<SystemTimer> = Mutex::new(SystemTimer::new());
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
    let mut rax: u64;
    unsafe { asm!("mov {0}, rax", lateout(reg) rax ); }
    let mut state = State::new(rax);
    state.rip = _stack_frame.instruction_pointer.as_u64();
    state.cs = _stack_frame.code_segment.0 as u64;
    state.rflags = _stack_frame.cpu_flags.bits().clone();
    state.rsp = _stack_frame.stack_pointer.as_u64();
    state.ss = _stack_frame.stack_segment.0 as u64;
    let mut timer = TIMER.lock();
    timer.increment();

    //force unlocks are used as the timer and scheduler can not be allowed to spin lock on a resource
    unsafe {
        if KERNEL_INITIALIZED.load(Ordering::SeqCst) {
            if (timer.get_current_tick() % 1000 == 0) {
                unsafe { println!("timer tick: {}", timer.get_current_tick()) };
            }

            print_queue();
            // Proceed with task scheduling if initialized
            {
                SCHEDULER.force_unlock();
                let mut scheduler = SCHEDULER.lock();
                if (!scheduler.is_empty()) {
                    scheduler.get_current_task().update_from_context(state);
                }
                scheduler.schedule_next();

                scheduler.get_current_task().context.restore_stack_frame(_stack_frame);
                scheduler.get_current_task().context.restore();
                send_eoi(InterruptIndex::Timer.as_u8());
            }
        } else {
            // Kernel is not initialized yet, just send EOI and return to kernel
            send_eoi(InterruptIndex::Timer.as_u8());
        }
    }
}
