use kernel_sys::{
    bench_kernel_span_begin, bench_kernel_submit_rip_sample, bench_kernel_window_create,
    bench_kernel_window_destroy, bench_kernel_window_persist, bench_kernel_window_start,
    bench_kernel_window_stop, idle_tracking_start as sys_idle_tracking_start,
    idle_tracking_stop as sys_idle_tracking_stop, BenchSpanGuard,
};
use kernel_types::{
    async_ffi::FfiFuture,
    benchmark::{BenchCoreId, BenchObjectId, BenchTag, BenchWindowConfig, BenchWindowHandle},
};

use crate::util::get_current_cpu_id;
pub use kernel_types::benchmark::*;
#[inline]
pub const fn object_id(v: u64) -> BenchObjectId {
    BenchObjectId(v)
}
pub struct BenchWindow {
    handle: BenchWindowHandle,
}

impl BenchWindow {
    #[inline]
    pub fn new(cfg: BenchWindowConfig) -> Self {
        let handle = unsafe { bench_kernel_window_create(cfg) };
        BenchWindow { handle }
    }

    #[inline]
    pub fn handle(&self) -> BenchWindowHandle {
        self.handle
    }

    #[inline]
    pub fn start(&self) -> bool {
        unsafe { bench_kernel_window_start(self.handle) }
    }

    #[inline]
    pub fn stop(&self) -> bool {
        unsafe { bench_kernel_window_stop(self.handle) }
    }

    #[inline]
    pub fn persist(&self) -> FfiFuture<bool> {
        unsafe { bench_kernel_window_persist(self.handle) }
    }

    #[inline]
    pub fn span_guard(&self, tag: BenchTag, object_id: BenchObjectId) -> BenchSpanGuard {
        unsafe { bench_kernel_span_begin(tag, object_id) }
    }
}

impl Drop for BenchWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = bench_kernel_window_destroy(self.handle);
        }
    }
}

#[inline]
pub fn submit_rip_sample(core: BenchCoreId, rip: u64, stack: &[u64]) {
    unsafe {
        bench_kernel_submit_rip_sample(core, rip, stack.as_ptr(), stack.len());
    }
}

#[inline]
pub fn submit_rip_sample_current_core(rip: u64, stack: &[u64]) {
    let core = BenchCoreId(get_current_cpu_id() as u16);
    submit_rip_sample(core, rip, stack);
}

#[inline]
pub fn span(tag: BenchTag, object_id: BenchObjectId) -> BenchSpanGuard {
    unsafe { bench_kernel_span_begin(tag, object_id) }
}

/// Reset all idle tracking counters and enable tracking.
/// Call this right before starting a benchmark level for accurate measurement.
#[inline]
pub fn idle_tracking_start() {
    unsafe { sys_idle_tracking_start() }
}

/// Disable tracking and return aggregate idle percentage.
/// Returns the percentage of time CPUs spent idle since `idle_tracking_start()`.
#[inline]
pub fn idle_tracking_stop() -> f64 {
    unsafe { sys_idle_tracking_stop() }
}
