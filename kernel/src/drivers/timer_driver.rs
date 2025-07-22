
use crate::console::print_queue;
use crate::drivers::interrupt_index::{get_current_logical_id, send_eoi, InterruptIndex};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::State;
use crate::structs::stopwatch::Stopwatch;
use crate::util::KERNEL_INITIALIZED;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::structures::idt::InterruptStackFrame;

pub static TIMER: AtomicUsize = AtomicUsize::new(0);
pub static TIMER_TIME: AtomicUsize = AtomicUsize::new(0);

pub(crate) extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    let mut rax: u64;
    unsafe {
        asm!("mov {0}, rax", lateout(reg) rax );
    }
    let mut state = State::new(rax);
    state.rip = _stack_frame.instruction_pointer.as_u64();
    state.cs = _stack_frame.code_segment.0 as u64;
    state.rflags = _stack_frame.cpu_flags.bits().clone();
    state.rsp = _stack_frame.stack_pointer.as_u64();
    state.ss = _stack_frame.stack_segment.0 as u64;
    let ticks = TIMER.fetch_add(1, Ordering::SeqCst);

    // Force unlocks are used as the timer and scheduler can not be allowed to spin lock on a resource
unsafe {
    if KERNEL_INITIALIZED.load(Ordering::SeqCst) && !SCHEDULER.is_locked() {
        let mut scheduler = SCHEDULER.lock();
        let stopwatch = Stopwatch::start();
        print_queue();

        if !scheduler.is_empty() && scheduler.has_core_init() {
            scheduler.get_current_task().update_from_context(&state);
        }

        scheduler.schedule_next();
        send_eoi(InterruptIndex::Timer.as_u8());

        let needs_restore = {
            let task = scheduler.get_current_task();  
            let restore = task.parent_pid != 0;

            task.context.restore_stack_frame(_stack_frame);
            task.context.restore();

            restore                               
        };

        if needs_restore {
            scheduler.restore_page_table();
        }

        TIMER_TIME.fetch_add(stopwatch.elapsed_micros() as usize, Ordering::Relaxed);
    } else {
        send_eoi(InterruptIndex::Timer.as_u8());
    }
}
}
