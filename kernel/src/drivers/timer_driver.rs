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
use spin::Mutex;
use x86_64::structures::idt::InterruptStackFrame;
use lazy_static::lazy_static;

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
        if KERNEL_INITIALIZED.load(Ordering::SeqCst) && !SCHEDULER.is_locked() && !TIMER_TIME.is_locked() {
            let stopwatch = Stopwatch::start();
            let timer_time = TIMER_TIME.lock();
            let cpu_id = get_current_logical_id();
            
            let (ctx_ptr, needs_restore) = {
                let mut scheduler = SCHEDULER.lock();

                if(!scheduler.has_core_init()){
                    timer_time.set(cpu_id as usize, AtomicUsize::new(0));
                }

                let ticks = TIMER.fetch_add(1, Ordering::SeqCst);
                print_queue();

                if !scheduler.is_empty() && scheduler.has_core_init() {
                    scheduler.get_current_task().update_from_context(&state);
                }

                scheduler.schedule_next();
                send_eoi(InterruptIndex::Timer.as_u8());

                let task = scheduler.get_current_task();
                let restore = task.parent_pid != 0;
                let ctx_ptr: *mut State = &mut task.context as *mut State;

                (ctx_ptr, restore)
            };

            if needs_restore {
                SCHEDULER.lock().restore_page_table();
            }


            (*ctx_ptr).restore_stack_frame(_stack_frame);
            timer_time.get(cpu_id as usize).unwrap().fetch_add(stopwatch.elapsed_millis() as usize, Ordering::SeqCst);
            (*ctx_ptr).restore(); 
        } else {
            send_eoi(InterruptIndex::Timer.as_u8());
        }
    }
}
