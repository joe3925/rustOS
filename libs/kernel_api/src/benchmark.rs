use alloc::string::String;
use kernel_sys::{
    bench_kernel_case_end, bench_kernel_case_fail, bench_kernel_case_start, bench_kernel_measure,
    bench_kernel_span_begin, bench_kernel_submit_rip_sample, bench_kernel_suite_register,
    bench_kernel_window_create, bench_kernel_window_destroy, bench_kernel_window_persist,
    bench_kernel_window_start, bench_kernel_window_stop, BenchSpanGuard,
};
use kernel_types::{
    async_ffi::AbiFuture,
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
    pub fn persist(&self) -> AbiFuture<bool> {
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

/// Registers a suite with the post-boot benchmark runner.
pub fn register_suite(descriptor: BenchSuiteDescriptor) -> bool {
    unsafe { bench_kernel_suite_register(descriptor) }
}

/// Driver-facing reporter passed to a registered suite callback.
#[derive(Clone, Copy, Debug)]
pub struct SuiteContext {
    handle: BenchRunHandle,
}

impl SuiteContext {
    pub const fn new(handle: BenchRunHandle) -> Self {
        Self { handle }
    }

    pub fn start_case(&self, name: impl Into<String>) -> bool {
        unsafe { bench_kernel_case_start(self.handle, name.into()) }
    }

    pub fn end_case(&self) -> bool {
        unsafe { bench_kernel_case_end(self.handle) }
    }

    pub fn fail(&self, reason: impl Into<String>) -> bool {
        unsafe { bench_kernel_case_fail(self.handle, reason.into()) }
    }

    pub fn measure(
        &self,
        metric: impl Into<String>,
        value: f64,
        unit: BenchMetricUnit,
        direction: BenchMetricDirection,
    ) -> bool {
        unsafe { bench_kernel_measure(self.handle, metric.into(), value, unit, direction) }
    }
}
