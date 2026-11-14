use alloc::sync::Arc;
pub use kernel_executor::thread_state::BlockOnThreadState;
use core::task::Waker;
use core::time::Duration;

#[repr(C)]
pub struct BlockOnContext {
    pub state: Arc<BlockOnThreadState>,
    pub waker: Waker,
}

#[repr(C)]
pub struct Stopwatch {
    start_cycles: u64,
    cycle_counter_frequency_hz: u64,
}

impl Stopwatch {
    #[inline]
    pub fn new(start_cycles: u64, cycle_counter_frequency_hz: u64) -> Self {
        assert!(cycle_counter_frequency_hz != 0, "platform cycle counter not calibrated");
        Self { start_cycles, cycle_counter_frequency_hz }
    }

    #[inline]
    pub fn duration_from_cycles(cycles: u64, frequency_hz: u64) -> Duration {
        assert!(frequency_hz != 0, "platform cycle counter not calibrated");
        let secs = cycles / frequency_hz;
        let rem_cycles = cycles % frequency_hz;
        let nanos = ((rem_cycles as u128 * 1_000_000_000) / frequency_hz as u128) as u32;
        Duration::new(secs, nanos)
    }

    #[inline]
    pub fn elapsed_at(&self, cycles: u64) -> Duration {
        Self::duration_from_cycles(cycles - self.start_cycles, self.cycle_counter_frequency_hz)
    }

    #[inline(always)]
    pub fn start_cycles(&self) -> u64 {
        self.start_cycles
    }

    #[inline(always)]
    pub fn cycle_counter_frequency_hz(&self) -> u64 {
        self.cycle_counter_frequency_hz
    }
}
