use core::time::Duration;

use crate::platform::TimerPlatform;

use super::platform::Aarch64Platform;

impl TimerPlatform for Aarch64Platform {
    fn wait_duration(_time: Duration) { todo!() }
    fn calibrate_boot_timer() { todo!() }
    fn init_periodic_timer() { todo!() }
    fn cycle_counter() -> u64 { todo!() }
    fn ordered_cycle_counter() -> u64 { todo!() }
    fn cycle_counter_frequency_hz() -> u64 { todo!() }
    fn timer_tick_count() -> usize { todo!() }
    fn scheduler_time_ns(_cpu_id: usize) -> u64 { todo!() }
    fn context_switch_count(_cpu_id: usize) -> u64 { todo!() }
}
