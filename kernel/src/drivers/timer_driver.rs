use crate::benchmarking::bench_submit_rip_sample_current_core;
use crate::cpu;
use crate::drivers::interrupt_index::{
    current_cpu_id, get_current_logical_id, send_eoi, send_eoi_timer, InterruptIndex,
};
use crate::scheduling::scheduler::{self, SCHEDULER};
use crate::scheduling::state::State;
use crate::structs::per_cpu_vec::PerCpuVec;
use crate::drivers::interrupt_index::APIC_TICKS_PER_NS;
use crate::structs::stopwatch::Stopwatch;
use crate::util::KERNEL_INITIALIZED;
use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub static TIMER: AtomicUsize = AtomicUsize::new(0);

const STATE_BYTES: usize = 15 * 8;

#[repr(align(64))]
pub struct Al64<T>(pub T);

pub static NUM_CORES: AtomicUsize = AtomicUsize::new(1);
pub static ROT_TICKET: Al64<AtomicUsize> = Al64(AtomicUsize::new(0));

pub static TIMER_TIME_SCHED: PerCpuVec<AtomicUsize> = PerCpuVec::new();
pub static PER_CORE_SWITCHES: PerCpuVec<AtomicUsize> = PerCpuVec::new();

#[derive(Copy, Clone)]
pub struct TimerDebug {
    pub cpu: usize,
    pub claimed: bool,
    pub did_sched: bool,
}
#[no_mangle]
pub extern "C" fn timer_interrupt_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    TIMER.fetch_add(1, Ordering::Relaxed);
    let cpu_id = current_cpu_id() as usize;
    let sw = Stopwatch::start();

    SCHEDULER.on_timer_tick(state, cpu_id);
    unsafe { bench_submit_rip_sample_current_core((*state).rip, ((*state).rsp as *const u64), 8) };
    let dt = sw.elapsed_nanos() as usize;
    TIMER_TIME_SCHED.get().fetch_add(dt, Ordering::Relaxed);
}

pub fn set_num_cores(n: usize) {
    let n = n.max(1);
    NUM_CORES.store(n, Ordering::Relaxed);
    ROT_TICKET.0.store(0, Ordering::Relaxed);

    TIMER_TIME_SCHED.init(n, || AtomicUsize::new(0));
    PER_CORE_SWITCHES.init(n, || AtomicUsize::new(0));
    APIC_TICKS_PER_NS.init(n, || AtomicU64::new(0));
}

#[unsafe(naked)]
pub extern "win64" fn timer_interrupt_entry() {
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
