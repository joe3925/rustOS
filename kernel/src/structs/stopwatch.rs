use core::time::Duration;

use crate::platform;
#[repr(C)]
pub struct Stopwatch {
    start_cycles: u64,
    cycle_counter_frequency_hz: u64,
}

impl Stopwatch {
    #[inline(always)]
    pub fn start() -> Self {
        let freq = platform::cycle_counter_frequency_hz();
        assert!(freq != 0, "platform cycle counter not calibrated");

        Stopwatch {
            start_cycles: platform::cycle_counter(),
            cycle_counter_frequency_hz: freq,
        }
    }
    #[inline(always)]
    pub fn from_cycles(cycles: u64) -> Duration {
        let freq = platform::cycle_counter_frequency_hz();
        assert!(freq != 0, "platform cycle counter not calibrated");

        let secs = cycles / freq;
        let rem_cycles = cycles % freq;
        let nanos = ((rem_cycles as u128 * 1_000_000_000) / freq as u128) as u32;

        Duration::new(secs, nanos)
    }
    #[inline(always)]
    pub fn reset(&mut self) {
        let freq = platform::cycle_counter_frequency_hz();
        assert!(freq != 0, "platform cycle counter not calibrated");

        self.start_cycles = platform::cycle_counter();
        self.cycle_counter_frequency_hz = freq;
    }
    #[inline(always)]
    pub fn elapsed(&self) -> Duration {
        let cycles = self.elapsed_cycles();
        let secs = cycles / self.cycle_counter_frequency_hz;
        let rem_cycles = cycles % self.cycle_counter_frequency_hz;
        let nanos =
            ((rem_cycles as u128 * 1_000_000_000) / self.cycle_counter_frequency_hz as u128) as u32;

        Duration::new(secs, nanos)
    }
    #[inline(always)]
    pub fn elapsed_cycles(&self) -> u64 {
        platform::cycle_counter() - self.start_cycles
    }

    #[inline(always)]
    pub fn elapsed_micros(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000_000 / self.cycle_counter_frequency_hz as u128) as u64
    }

    #[inline(always)]
    pub fn elapsed_millis(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000 / self.cycle_counter_frequency_hz as u128) as u64
    }

    #[inline(always)]
    pub fn elapsed_nanos(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000_000_000 / self.cycle_counter_frequency_hz as u128)
            as u64
    }
    #[inline(always)]
    pub fn elapsed_sec(&self) -> f64 {
        self.elapsed_cycles() as f64 / self.cycle_counter_frequency_hz as f64
    }
}
