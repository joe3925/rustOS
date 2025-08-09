use core::sync::atomic::Ordering;

use crate::{cpu, drivers::interrupt_index::TSC_HZ};

/// Simple cycle‑counter stop‑watch.
///
/// # Example
/// ```rust
/// let sw = Stopwatch::start();
/// some_slow_work();
/// println!("elapsed = {} µs", sw.elapsed_micros());
/// ```
pub struct Stopwatch {
    start_cycles: u64,
    tsc_hz: u64,
}

impl Stopwatch {
    #[inline(always)]
    pub fn start() -> Self {
        let freq = TSC_HZ.load(Ordering::SeqCst);
        assert!(freq != 0, "TSC not calibrated");

        Stopwatch {
            start_cycles: cpu::get_cycles(),
            tsc_hz: freq,
        }
    }

    #[inline(always)]
    pub fn elapsed_cycles(&self) -> u64 {
        cpu::get_cycles() - self.start_cycles
    }

    #[inline(always)]
    pub fn elapsed_micros(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000_000 / self.tsc_hz as u128) as u64
    }

    #[inline(always)]
    pub fn elapsed_millis(&self) -> u64 {
        (self.elapsed_cycles() as u128 * 1_000 / self.tsc_hz as u128) as u64
    }

    #[inline(always)]
    pub fn elapsed_nanos(&self) -> u64 {
        // cycles × 1 000 00 000 / Hz
        (self.elapsed_cycles() as u128 * 1_000_000_000 / self.tsc_hz as u128) as u64
    }
    #[inline(always)]
    pub fn elapsed_sec(&self) -> f64 {
        self.elapsed_cycles() as f64 / self.tsc_hz as f64
    }
}
