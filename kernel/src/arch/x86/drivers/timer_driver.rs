use crate::idt::interrupt_impl::InterruptGuard;
use kernel_routing::println;

use crate::benchmarking::bench_submit_interrupt_sample_current_core;

use super::super::cpu::{current_cpu_id, current_is_in_interrupt};
use super::super::interrupts::apic::local::send_eoi as send_eoi_timer;
use super::super::timer::APIC_TICKS_PER_NS;
use crate::scheduling::scheduler::scheduler;
use crate::scheduling::state::State;
use crate::structs::per_cpu_vec::PerCpuVec;
use crate::structs::stopwatch::Stopwatch;
use crate::util::KERNEL_INITIALIZED;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub static TIMER: AtomicUsize = AtomicUsize::new(0);

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
#[unsafe(no_mangle)]
#[cfg_attr(irq_check, irq::context)]
pub unsafe extern "C" fn timer_interrupt_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    if current_is_in_interrupt() {
        return;
    }

    let _guard = InterruptGuard::new();
    let Some(mut scheduling) = scheduler().try_local_scheduler() else {
        return;
    };
    TIMER.fetch_add(1, Ordering::Relaxed);
    bench_submit_interrupt_sample_current_core(unsafe { &*state });

    let sw = Stopwatch::start();
    unsafe { scheduling.on_timer_tick(state) };
    let dt = sw.elapsed_nanos() as usize;
    unsafe { TIMER_TIME_SCHED.get() }.fetch_add(dt, Ordering::Relaxed);
}

pub fn set_num_cores(n: usize) {
    let n = n.max(1);
    NUM_CORES.store(n, Ordering::Relaxed);
    ROT_TICKET.0.store(0, Ordering::Relaxed);

    unsafe {
        TIMER_TIME_SCHED.init(n, || AtomicUsize::new(0));
        PER_CORE_SWITCHES.init(n, || AtomicUsize::new(0));
        APIC_TICKS_PER_NS.init(n, || AtomicU64::new(0));
    }
}

crate::x86_interrupt_entry!(
    pub timer_interrupt_entry,
    timer_interrupt_handler_c,
    eoi = send_eoi_timer
);
