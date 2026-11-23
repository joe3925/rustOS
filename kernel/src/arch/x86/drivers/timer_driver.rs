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
    #[cfg(feature = "kernel-bench")]
    {
        use crate::benchmarking::scheduler_wake::TRIGGER;
        let pointer = TRIGGER.load(Ordering::Acquire);
        if current_cpu_id() == 0 && !pointer.is_null() {
            let sample = unsafe { &*pointer };
            if crate::platform::ordered_cycle_counter() >= sample.deadline.load(Ordering::Relaxed)
                && TRIGGER.compare_exchange(pointer, core::ptr::null_mut(), Ordering::AcqRel, Ordering::Relaxed).is_ok()
            {
                let gate = if sample.mode == 4 {
                    Some(scheduler().try_core_scheduler(0).expect("scheduler probe cannot acquire gate"))
                } else { None };
                let before = scheduler().try_get_current_task(0).map(|task| task.task_id());
                sample.requested.store(crate::platform::ordered_cycle_counter(), Ordering::Release);
                assert!(crate::platform::send_ipi(sample.target.load(Ordering::Relaxed) as u32, sample.vector.load(Ordering::Relaxed) as u8));
                if sample.mode == 3 || sample.mode == 4 {
                    let deadline = crate::platform::ordered_cycle_counter() + crate::platform::cycle_counter_frequency_hz();
                    crate::platform::enable_interrupts();
                    while sample.finished.load(Ordering::Acquire) == 0 {
                        if crate::platform::ordered_cycle_counter() >= deadline {
                            crate::platform::disable_interrupts();
                            panic!("nested IRQ wake did not complete");
                        }
                        core::hint::spin_loop();
                    }
                    crate::platform::disable_interrupts();
                    assert!(current_is_in_interrupt());
                    assert_eq!(scheduler().try_get_current_task(0).map(|task| task.task_id()), before, "nested IRQ switched the outer task");
                    sample.nested_completed.store(true, Ordering::Release);
                }
                drop(gate);
            }
        }
    }
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
