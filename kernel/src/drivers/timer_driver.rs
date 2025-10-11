use crate::drivers::interrupt_index::{
    get_current_logical_id, send_eoi, send_eoi_timer, InterruptIndex,
};
use crate::scheduling::scheduler::{self, SCHEDULER};
use crate::scheduling::state::State;
use crate::structs::per_core_storage::PCS;
use crate::structs::stopwatch::Stopwatch;
use crate::util::KERNEL_INITIALIZED;
use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

pub static TIMER: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    pub static ref TIMER_TIME: Mutex<PCS<AtomicUsize>> = Mutex::new(PCS::new());
    pub static ref PER_CORE_SWITCHES: Mutex<PCS<AtomicUsize>> = Mutex::new(PCS::new());
}

const STATE_BYTES: usize = 15 * 8;
// A little more fair bad average time
#[repr(align(64))]
struct Al64<T>(T);

pub static NUM_CORES: AtomicUsize = AtomicUsize::new(1);
static ROT_TICKET: Al64<AtomicUsize> = Al64(AtomicUsize::new(0));

#[no_mangle]
pub extern "C" fn timer_interrupt_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    let n = NUM_CORES.load(Ordering::Relaxed).max(1);
    let cpu = get_current_logical_id() as usize % n;

    let claimed = ROT_TICKET
        .0
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
            if t % n == cpu {
                Some(t.wrapping_add(1))
            } else {
                None
            }
        })
        .is_ok();

    if !claimed {
        return;
    }

    // Only the claimer reaches here.
    let mut sched = SCHEDULER.lock();
    sched.on_timer_tick(state, cpu);
}

// Decent Average time, a little less fair

// static ROT_STATE: AtomicU64 = AtomicU64::new(0);
// static ALLOW_MASK: AtomicUsize = AtomicUsize::new(1);

// #[inline(always)]
// fn make_mask(head: usize, win: usize, n: usize) -> usize {
//     let w = win.min(n);
//     let mut m = 0usize;
//     for i in 0..w {
//         m |= 1usize << ((head + i) % n);
//     }
//     m
// }

// #[no_mangle]
// pub extern "C" fn timer_interrupt_handler_c(state: *mut State) {
//     if !KERNEL_INITIALIZED.load(Ordering::SeqCst) {
//         return;
//     }

//     let n = NUM_CORES.load(Ordering::Relaxed).max(1);
//     let cpu = get_current_logical_id() as usize;

//     let mask = ALLOW_MASK.load(Ordering::Relaxed);
//     if ((mask >> cpu) & 1) == 0 {
//         return;
//     }

//     let mut sched = SCHEDULER.lock();
//     sched.on_timer_tick(state, cpu);
//     drop(sched);

//     loop {
//         let s = ROT_STATE.load(Ordering::Relaxed);
//         let h = (s >> 32) as usize;
//         let w0 = (s & 0xFFFF_FFFF) as usize;

//         let w2 = (w0 % n) + 1;
//         let h2 = (h + (w0 / n)) % n;

//         let ns = ((h2 as u64) << 32) | (w2 as u64);
//         if ROT_STATE
//             .compare_exchange(s, ns, Ordering::Release, Ordering::Relaxed)
//             .is_ok()
//         {
//             ALLOW_MASK.store(make_mask(h2, w2, n), Ordering::Release);
//             break;
//         }
//     }
// }

// pub fn set_num_cores(n: usize) {
//     let n = n.max(1);
//     NUM_CORES.store(n, Ordering::Relaxed);
//     ROT_STATE.store(((0u64) << 32) | 1, Ordering::Relaxed);
//     ALLOW_MASK.store(make_mask(0, 1, n), Ordering::Relaxed);
// }

pub fn set_num_cores(n: usize) {
    let n = n.max(1);
    NUM_CORES.store(n, Ordering::Relaxed);
    ROT_TICKET.0.store(0, Ordering::Relaxed);
}
#[unsafe(naked)]
pub extern "x86-interrupt" fn timer_interrupt_entry() -> ! {
    naked_asm!(
        "cli",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",

        "mov  rdi, rsp",
        "cld",
        "sub  rsp, 8",
        "call {handler}",
        "add  rsp, 8",

        "sub  rsp, 8",
        "call {eoi}",
        "add  rsp, 8",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "sti",
        "iretq",
        handler = sym timer_interrupt_handler_c,
        eoi     = sym send_eoi_timer,
    );
}
