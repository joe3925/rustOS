use core::time::Duration;

use crate::platform;
use kernel_types::runtime::Stopwatch as StopwatchState;
#[repr(C)]
pub struct Stopwatch {
    inner: StopwatchState,
}

impl Stopwatch {
    #[inline(always)]
    pub fn start() -> Self {
        let freq = platform::cycle_counter_frequency_hz();
        assert!(freq != 0, "platform cycle counter not calibrated");

        Stopwatch {
            inner: StopwatchState::new(platform::cycle_counter(), freq),
        }
    }
    #[inline(always)]
    pub fn from_cycles(cycles: u64) -> Duration {
        let freq = platform::cycle_counter_frequency_hz();
        assert!(freq != 0, "platform cycle counter not calibrated");

        StopwatchState::duration_from_cycles(cycles, freq)
    }
    #[inline(always)]
    pub fn reset(&mut self) {
        let freq = platform::cycle_counter_frequency_hz();
        assert!(freq != 0, "platform cycle counter not calibrated");

        self.inner = StopwatchState::new(platform::cycle_counter(), freq);
    }
    #[inline(always)]
    pub fn elapsed(&self) -> Duration {
        self.inner.elapsed_at(platform::cycle_counter())
    }
    #[inline(always)]
    pub fn elapsed_cycles(&self) -> u64 {
        platform::cycle_counter() - self.inner.start_cycles()
    }

    #[inline(always)]
    pub fn elapsed_micros(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000_000 / self.inner.cycle_counter_frequency_hz() as u128) as u64
    }

    #[inline(always)]
    pub fn elapsed_millis(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000 / self.inner.cycle_counter_frequency_hz() as u128) as u64
    }

    #[inline(always)]
    pub fn elapsed_nanos(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000_000_000 / self.inner.cycle_counter_frequency_hz() as u128)
            as u64
    }
    #[inline(always)]
    pub fn elapsed_sec(&self) -> f64 {
        self.elapsed_cycles() as f64 / self.inner.cycle_counter_frequency_hz() as f64
    }
}
