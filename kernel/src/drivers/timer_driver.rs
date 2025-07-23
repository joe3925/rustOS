use crate::console::print_queue;
use crate::drivers::interrupt_index::{get_current_logical_id, send_eoi, InterruptIndex};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::State;
use crate::structs::per_core_storage::PCS;
use crate::structs::stopwatch::Stopwatch;
use crate::util::KERNEL_INITIALIZED;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::structures::idt::InterruptStackFrame;

pub static TIMER: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    pub static ref TIMER_TIME: Mutex<PCS<AtomicUsize>> = Mutex::new(PCS::new());
}

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

    unsafe {
        // it gets the job done
        // try to reduce the chance of the worst case where we spin on the mutex locks
        unsafe {
            // Fast‑exit if the kernel is not up yet.
            if !KERNEL_INITIALIZED.load(Ordering::SeqCst) {
                send_eoi(InterruptIndex::Timer.as_u8());
                return;
            }

            let (mut scheduler, mut timer_time) =
                match (SCHEDULER.try_lock(), TIMER_TIME.try_lock()) {
                    (Some(s), Some(t)) => (s, t), 
                    _ => {
                        send_eoi(InterruptIndex::Timer.as_u8()); 
                        return;
                    }
                };

            let stopwatch = Stopwatch::start();
            let cpu_id = get_current_logical_id();

            if !scheduler.has_core_init() {
                timer_time.set(cpu_id as usize, AtomicUsize::new(0));
            }

            TIMER.fetch_add(1, Ordering::SeqCst);
            print_queue();

            if !scheduler.is_empty() && scheduler.has_core_init() {
                scheduler.get_current_task().update_from_context(&state);
            }

            scheduler.schedule_next();
            send_eoi(InterruptIndex::Timer.as_u8());

            let task = scheduler.get_current_task();
            let needs_restore = task.parent_pid != 0;
            let ctx_ptr: *mut State = &mut task.context;

            drop(scheduler);
            drop(timer_time);

            if needs_restore {
                if let Some(mut sch) = SCHEDULER.try_lock() {
                    sch.restore_page_table();
                } else {
                    return;
                }
            }

            (*ctx_ptr).restore_stack_frame(_stack_frame);

            if let Some(mut tt) = TIMER_TIME.try_lock() {
                tt.get(cpu_id as usize)
                    .unwrap()
                    .fetch_add(stopwatch.elapsed_millis() as usize, Ordering::SeqCst);
            }

            (*ctx_ptr).restore();
        }
    }
}
