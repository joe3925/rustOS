use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use x86_64::instructions::port::Port;

use crate::platform::TimerPlatform;

use super::cpu;
use super::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER, TIMER_TIME_SCHED};
use super::interrupts::{APICOffset, LAPIC_BASE_VA};
use super::platform::X86Platform;
use crate::structs::per_cpu_vec::PerCpuVec;

const PIT_FREQUENCY_HZ: u32 = 1_193_182;
const PIT_CONTROL_PORT: u16 = 0x43;
const PIT_CHANNEL2_PORT: u16 = 0x42;
const PIT_MODE_PORT: u16 = 0x61;
pub(crate) const APIC_START_PERIOD: u64 = 500000;
pub(crate) static TSC_HZ: AtomicU64 = AtomicU64::new(0);
pub(crate) static APIC_TICKS_PER_NS: PerCpuVec<AtomicU64> = PerCpuVec::new();
pub(crate) const TIMER_FREQ: u64 = 300;

pub fn wait_duration(d: Duration) {
    let tsc_hz = TSC_HZ.load(Ordering::SeqCst);
    if tsc_hz == 0 {
        panic!("TSC not calibrated");
    }

    let nanos = d.as_nanos();
    let hz = tsc_hz as u128;

    let target_delta = nanos.saturating_mul(hz).saturating_add(999_999_999) / 1_000_000_000;

    cpu::wait_cycle(target_delta);
}

pub fn wait_duration_idle(d: Duration) {
    let tsc_hz = TSC_HZ.load(Ordering::SeqCst);
    if tsc_hz == 0 {
        panic!("TSC not calibrated");
    }

    let nanos = d.as_nanos();
    let hz = tsc_hz as u128;

    let target_delta = nanos.saturating_mul(hz).saturating_add(999_999_999) / 1_000_000_000;

    cpu::wait_cycle_idle(target_delta);
}
pub(crate) fn duration_to_tsc_cycles(d: Duration) -> u128 {
    let tsc_hz = TSC_HZ.load(Ordering::SeqCst);
    if tsc_hz == 0 {
        panic!("TSC not calibrated");
    }

    d.as_nanos()
        .saturating_mul(tsc_hz as u128)
        .saturating_add(999_999_999)
        / 1_000_000_000
}

#[inline]
fn lapic() -> *mut u32 {
    LAPIC_BASE_VA.load(Ordering::SeqCst) as *mut u32
}
#[inline]
fn rd(off: APICOffset) -> u32 {
    unsafe { lapic().add(off as usize / 4).read_volatile() }
}
#[inline]
fn wr(off: APICOffset, v: u32) {
    unsafe { lapic().add(off as usize / 4).write_volatile(v) }
}

pub fn apic_calibrate_ticks_per_ns_via_wait(window_ms: u64) -> u64 {
    assert!(window_ms > 0);
    let saved_lvt = rd(APICOffset::LvtT);
    let saved_ticr = rd(APICOffset::Ticr);

    wr(APICOffset::LvtT, saved_lvt | (1 << 16));
    wr(APICOffset::Ticr, u32::MAX);

    wait_duration(Duration::from_millis(window_ms));

    let cur = rd(APICOffset::Tccr) as u64;
    let dec = (u32::MAX as u64).saturating_sub(cur);

    let elapsed_ns = (window_ms as u128) * 1_000_000u128;
    let q32 = if dec == 0 {
        0
    } else {
        (((dec as u128) << 32) / elapsed_ns) as u64
    };

    unsafe { APIC_TICKS_PER_NS.get() }.store(q32, Ordering::Relaxed);

    wr(APICOffset::Ticr, saved_ticr);
    wr(APICOffset::LvtT, saved_lvt);

    q32
}

#[inline]
pub fn apic_ticr_for_ns(ns: u64) -> u32 {
    let fp = unsafe { APIC_TICKS_PER_NS.get() }.load(Ordering::Relaxed);

    if fp == 0 || ns == 0 {
        return 0;
    }
    let prod = ((ns as u128) * (fp as u128) + ((1u128 << 32) - 1)) >> 32; // ceil
    core::cmp::min(prod as u64, u32::MAX as u64) as u32
}

pub fn apic_program_period_ns(ns: u64) {
    let lvt = rd(APICOffset::LvtT);
    wr(APICOffset::Ticr, apic_ticr_for_ns(ns));
    wr(APICOffset::LvtT, lvt & !(1 << 16));
}
pub fn apic_program_period_ms(ms: u64) {
    if ms == 0 {
        return;
    }
    let ns = ms.saturating_mul(1_000_000);
    apic_program_period_ns(ns);
}

impl TimerPlatform for X86Platform {
    fn wait_duration(time: Duration) {
        wait_duration(time);
    }

    fn calibrate_boot_timer() {
        let tsc_start = super::cpu::get_cycles();
        let counts_for_50ms: u16 = (PIT_FREQUENCY_HZ / 20) as u16;

        unsafe {
            let mut control = Port::new(PIT_CONTROL_PORT);
            let mut ch2 = Port::new(PIT_CHANNEL2_PORT);
            let mut mode = Port::new(PIT_MODE_PORT);

            control.write(0b1011_0000u8);
            ch2.write((counts_for_50ms & 0xFF) as u8);
            ch2.write((counts_for_50ms >> 8) as u8);

            let mut value: u8 = mode.read();
            value = (value & !0b11) | 0b01;
            mode.write(value);

            loop {
                let status: u8 = mode.read();
                if (status & 0b0010_0000) != 0 {
                    break;
                }
            }
        }

        let tsc_end = super::cpu::get_cycles();
        let tsc_freq = (tsc_end - tsc_start) * 1000 / 50;
        TSC_HZ.store(tsc_freq, core::sync::atomic::Ordering::SeqCst);
    }

    fn init_periodic_timer() {
        apic_calibrate_ticks_per_ns_via_wait(10);
        apic_program_period_ns(APIC_START_PERIOD);
    }

    fn cycle_counter() -> u64 {
        super::cpu::get_cycles()
    }

    fn ordered_cycle_counter() -> u64 {
        let low: u32;
        let high: u32;

        unsafe {
            asm!(
                "lfence",
                "rdtsc",
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags),
            );
        }

        ((high as u64) << 32) | low as u64
    }

    fn cycle_counter_frequency_hz() -> u64 {
        TSC_HZ.load(core::sync::atomic::Ordering::SeqCst)
    }

    fn timer_tick_count() -> usize {
        TIMER.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn scheduler_time_ns(cpu_id: usize) -> u64 {
        unsafe { TIMER_TIME_SCHED.iter() }
            .nth(cpu_id)
            .map(|value| value.load(core::sync::atomic::Ordering::SeqCst) as u64)
            .unwrap_or(0)
    }

    fn context_switch_count(cpu_id: usize) -> u64 {
        unsafe { PER_CORE_SWITCHES.iter() }
            .nth(cpu_id)
            .map(|value| value.load(core::sync::atomic::Ordering::SeqCst) as u64)
            .unwrap_or(0)
    }
}
