use core::arch::asm;
use core::time::Duration;
use x86_64::instructions::port::Port;

use crate::platform::TimerPlatform;

use super::drivers::interrupt_index::{
    APIC_START_PERIOD, TSC_HZ, apic_calibrate_ticks_per_ns_via_wait, apic_program_period_ns,
    wait_duration,
};
use super::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER, TIMER_TIME_SCHED};
use super::platform::X86Platform;

const PIT_FREQUENCY_HZ: u32 = 1_193_182;
const PIT_CONTROL_PORT: u16 = 0x43;
const PIT_CHANNEL2_PORT: u16 = 0x42;
const PIT_MODE_PORT: u16 = 0x61;

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
