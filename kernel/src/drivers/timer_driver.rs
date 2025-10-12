use crate::cpu;
use crate::drivers::interrupt_index::{
    current_cpu_id, get_current_logical_id, send_eoi, send_eoi_timer, InterruptIndex,
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

const STATE_BYTES: usize = 15 * 8;

#[repr(align(64))]
pub struct Al64<T>(pub T);

pub static NUM_CORES: AtomicUsize = AtomicUsize::new(1);
pub static ROT_TICKET: Al64<AtomicUsize> = Al64(AtomicUsize::new(0));

lazy_static! {
    pub static ref TIMER_TIME_FAST: PCS<AtomicUsize> = PCS::new();
    pub static ref TIMER_TIME_SCHED: PCS<AtomicUsize> = PCS::new();
    pub static ref PER_CORE_SWITCHES: PCS<AtomicUsize> = PCS::new();
}

#[inline(always)]
fn add_time(pcs: &PCS<AtomicUsize>, cpu: usize, v: usize) {
    match pcs.get(cpu) {
        Some(a) => {
            a.fetch_add(v, Ordering::Relaxed);
        }
        None => {
            let a = pcs.set(cpu, AtomicUsize::new(0));
            a.fetch_add(v, Ordering::Relaxed);
        }
    }
}

#[derive(Copy, Clone)]
pub struct TimerDebug {
    pub cpu: usize,
    pub claimed: bool,
    pub did_sched: bool,
}
#[inline(always)]
fn timer_wrapper(state: *mut State, cpu_idx: usize, n: usize) -> TimerDebug {
    let mut claimed = false;
    let mut did_sched = false;

    let t = ROT_TICKET.0.load(core::sync::atomic::Ordering::Acquire);
    if (t as usize % n) != cpu_idx {
        return TimerDebug {
            cpu: cpu_idx,
            claimed,
            did_sched,
        };
    }

    let guard = if let Some(g) = SCHEDULER.try_lock() {
        g
    } else {
        return TimerDebug {
            cpu: cpu_idx,
            claimed,
            did_sched,
        };
    };

    if ROT_TICKET
        .0
        .compare_exchange(
            t,
            t + 1,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        claimed = true;
        let mut sched = guard;
        sched.on_timer_tick(state, cpu_idx);
        did_sched = true;
    }

    TimerDebug {
        cpu: cpu_idx,
        claimed,
        did_sched,
    }
}

#[no_mangle]
pub extern "C" fn timer_interrupt_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    let n = NUM_CORES.load(Ordering::Relaxed).max(1);
    TIMER.fetch_add(1, Ordering::Relaxed);

    let cpu_idx = current_cpu_id() as usize; // dense index
    let sw = Stopwatch::start();
    let dbg = timer_wrapper(state, cpu_idx, n);
    let dt = sw.elapsed_nanos() as usize;

    if dbg.did_sched {
        add_time(&TIMER_TIME_SCHED, cpu_idx, dt);
    } else {
        add_time(&TIMER_TIME_FAST, cpu_idx, dt);
    }
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

// #[derive(Copy, Clone)]
// pub struct TimerDebug {
//     pub cpu: usize,
//     pub allowed: bool,
//     pub did_sched: bool,
// }

// #[inline(always)]
// fn timer_wrapper_mask(state: *mut State, cpu: usize, n: usize) -> TimerDebug {
//     if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
//         return TimerDebug { cpu, allowed: false, did_sched: false };
//     }

//     let allowed = ((ALLOW_MASK.load(Ordering::Relaxed) >> cpu) & 1) != 0;
//     if !allowed {
//         return TimerDebug { cpu, allowed, did_sched: false };
//     }

//     {
//         let mut sched = SCHEDULER.lock();
//         sched.on_timer_tick(state, cpu);
//     }

//     loop {
//         let s  = ROT_STATE.load(Ordering::Relaxed);
//         let h  = (s >> 32) as usize;
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

//     TimerDebug { cpu, allowed: true, did_sched: true }
// }

// #[no_mangle]
// pub extern "C" fn timer_interrupt_handler_c(state: *mut State) {
//     let n   = NUM_CORES.load(Ordering::Relaxed).max(1);
//     let cpu = (get_current_logical_id() as usize) % n;

//     let sw  = Stopwatch::start();
//     let dbg = timer_wrapper_mask(state, cpu, n);
//     let dt  = sw.elapsed_millis() as usize;

//     if dbg.did_sched { add_time(&TIMER_TIME_SCHED, cpu, dt); }
//     else             { add_time(&TIMER_TIME_FAST,  cpu, dt); }
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

    for id in 0..n {
        let _ = TIMER_TIME_FAST.set(id, AtomicUsize::new(0));
        let _ = TIMER_TIME_SCHED.set(id, AtomicUsize::new(0));
        let _ = PER_CORE_SWITCHES.set(id, AtomicUsize::new(0));
    }
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
