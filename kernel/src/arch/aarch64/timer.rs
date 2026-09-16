use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;

use aarch64_cpu::asm::barrier::{SY, isb};

use crate::benchmarking::bench_submit_interrupt_sample_current_core;
use crate::idt::interrupt_impl::InterruptGuard;
use crate::platform::{self, TimerPlatform};
use crate::scheduling::scheduler::{KernelFpuGuard, SCHEDULER};
use crate::scheduling::state::State;
use crate::structs::stopwatch::Stopwatch;
use crate::util::KERNEL_INITIALIZED;

use super::platform::Aarch64Platform;

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const TIMER_PERIOD_NS: u64 = 500_000;
const CNTV_CTL_ENABLE: u64 = 1 << 0;
const CNTV_CTL_IMASK: u64 = 1 << 1;

static COUNTER_FREQUENCY_HZ: AtomicU64 = AtomicU64::new(0);
static TIMER_TICKS: AtomicUsize = AtomicUsize::new(0);
static TIMER_TIME_SCHED: [AtomicUsize; platform::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; platform::MAX_CPUS];
static PER_CORE_SWITCHES: [AtomicUsize; platform::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; platform::MAX_CPUS];

fn counter_frequency_hz() -> u64 {
    let cached = COUNTER_FREQUENCY_HZ.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let frequency: u64;
    unsafe {
        asm!("mrs {frequency}, cntfrq_el0", frequency = out(reg) frequency, options(nomem, nostack, preserves_flags));
    }
    assert!(frequency != 0);
    COUNTER_FREQUENCY_HZ.store(frequency, Ordering::Release);
    frequency
}

fn duration_ticks(time: Duration) -> u64 {
    let ticks = time
        .as_nanos()
        .saturating_mul(counter_frequency_hz() as u128)
        .saturating_add(NANOS_PER_SECOND - 1)
        / NANOS_PER_SECOND;
    ticks.min(u64::MAX as u128) as u64
}

fn program_period() {
    let ticks = duration_ticks(Duration::from_nanos(TIMER_PERIOD_NS)).max(1);
    unsafe {
        asm!("msr cntv_tval_el0, {ticks}", ticks = in(reg) ticks, options(nomem, nostack, preserves_flags));
        asm!("msr cntv_ctl_el0, {control}", control = in(reg) CNTV_CTL_ENABLE, options(nomem, nostack, preserves_flags));
    }
    isb(SY);
}

pub(super) unsafe fn handle_interrupt(state: *mut State) {
    program_period();
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) || platform::current_is_in_interrupt() {
        return;
    }

    let _interrupt_guard = InterruptGuard::new();
    let Some(_fpu_guard) = KernelFpuGuard::try_new() else {
        return;
    };
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    let cpu_id = platform::current_cpu_id();
    bench_submit_interrupt_sample_current_core(unsafe { &*state });

    let stopwatch = Stopwatch::start();
    let previous = unsafe { SCHEDULER.on_timer_tick(state, cpu_id) };
    TIMER_TIME_SCHED[cpu_id].fetch_add(stopwatch.elapsed_nanos() as usize, Ordering::Relaxed);
    if previous.is_some() {
        PER_CORE_SWITCHES[cpu_id].fetch_add(1, Ordering::Relaxed);
    }
}

impl TimerPlatform for Aarch64Platform {
    fn wait_duration(time: Duration) {
        let start = Self::cycle_counter();
        let ticks = duration_ticks(time);
        while Self::cycle_counter().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }

    fn calibrate_boot_timer() {
        let _ = counter_frequency_hz();
    }

    fn init_periodic_timer() {
        unsafe {
            asm!("msr cntv_ctl_el0, {control}", control = in(reg) CNTV_CTL_IMASK, options(nomem, nostack, preserves_flags));
        }
        program_period();
    }

    fn cycle_counter() -> u64 {
        let value: u64;
        unsafe {
            asm!("mrs {value}, cntvct_el0", value = out(reg) value, options(nomem, nostack, preserves_flags));
        }
        value
    }

    fn ordered_cycle_counter() -> u64 {
        isb(SY);
        Self::cycle_counter()
    }

    fn cycle_counter_frequency_hz() -> u64 {
        counter_frequency_hz()
    }

    fn timer_tick_count() -> usize {
        TIMER_TICKS.load(Ordering::Relaxed)
    }

    fn scheduler_time_ns(cpu_id: usize) -> u64 {
        TIMER_TIME_SCHED
            .get(cpu_id)
            .map(|value| value.load(Ordering::SeqCst) as u64)
            .unwrap_or(0)
    }

    fn context_switch_count(cpu_id: usize) -> u64 {
        PER_CORE_SWITCHES
            .get(cpu_id)
            .map(|value| value.load(Ordering::SeqCst) as u64)
            .unwrap_or(0)
    }
}
