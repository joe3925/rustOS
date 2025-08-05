use crate::drivers::interrupt_index::{get_current_logical_id, send_eoi, InterruptIndex};
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::State;
use crate::structs::per_core_storage::PCS;
use crate::structs::stopwatch::Stopwatch;
use crate::util::KERNEL_INITIALIZED;
use core::arch::naked_asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

pub static TIMER: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    pub static ref TIMER_TIME: Mutex<PCS<AtomicUsize>> = Mutex::new(PCS::new());
}

const STATE_BYTES: usize = 15 * 8;

extern "C" fn timer_interrupt_handler_c(state: *mut State) {
    unsafe {
        if !KERNEL_INITIALIZED.load(Ordering::SeqCst) {
            send_eoi(InterruptIndex::Timer.as_u8());
            return;
        }

        let (mut scheduler, timer_time) = match (SCHEDULER.try_lock(), TIMER_TIME.try_lock()) {
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

        if !scheduler.is_empty() && scheduler.has_core_init() {
            scheduler
                .get_current_task()
                .write()
                .update_from_context(state.as_mut().unwrap());
        }

        scheduler.schedule_next();

        let task_handle = scheduler.get_current_task();

        let (needs_restore, ctx_ptr): (bool, *mut State) = {
            let task = task_handle.read();
            (
                task.parent_pid != 0,
                &task.context as *const _ as *mut State,
            )
        };

        if needs_restore {
            scheduler.restore_page_table();
        }

        timer_time
            .get(cpu_id as usize)
            .unwrap()
            .fetch_add(stopwatch.elapsed_millis() as usize, Ordering::SeqCst);

        send_eoi(InterruptIndex::Timer.as_u8());

        (*ctx_ptr).restore(state);
    }
}
#[naked]
pub extern "x86-interrupt" fn timer_interrupt_entry() -> ! {
    unsafe {
        naked_asm!(
            "cli",
            /* save GPRs … */                          /* as you already had */
            "push r15","push r14","push r13","push r12",
            "push r11","push r10","push r9","push r8",
            "push rdi","push rsi","push rbp","push rbx",
            "push rdx","push rcx","push rax",

            /* prepare arguments */
            "mov  rdi, rsp",        // &State
            "cld",                  // DF = 0
            "sub  rsp, 8",          // align stack
            "call {handler}",
            "add  rsp, 8",

            /* restore GPRs … */
            "pop  rax","pop  rcx","pop  rdx","pop  rbx",
            "pop  rbp","pop  rsi","pop  rdi","pop  r8",
            "pop  r9","pop  r10","pop  r11","pop  r12",
            "pop  r13","pop  r14","pop  r15",
            "sti",
            "iretq",
            handler = sym timer_interrupt_handler_c,
        );
    }
}
