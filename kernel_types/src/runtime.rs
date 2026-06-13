use core::sync::atomic::{AtomicBool, Ordering};

#[repr(C)]
pub struct BlockOnThreadState {
    ready: AtomicBool,
    active: AtomicBool,
}

impl BlockOnThreadState {
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            active: AtomicBool::new(false),
        }
    }

    #[inline(always)]
    pub fn try_enter(&self) -> bool {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[inline(always)]
    pub fn exit(&self) {
        self.active.store(false, Ordering::Release);
    }

    #[inline(always)]
    pub fn clear_ready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    #[inline(always)]
    pub fn take_ready(&self) -> bool {
        self.ready.swap(false, Ordering::AcqRel)
    }

    #[inline(always)]
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }
}
#[repr(C)]
pub struct Stopwatch {
    start_cycles: u64,
    cycle_counter_frequency_hz: u64,
}

impl Stopwatch {
    #[inline(always)]
    pub fn start_cycles(&self) -> u64 {
        self.start_cycles
    }

    #[inline(always)]
    pub fn cycle_counter_frequency_hz(&self) -> u64 {
        self.cycle_counter_frequency_hz
    }
}
