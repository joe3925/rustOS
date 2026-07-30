//! Kernel benchmarking services.
//!
//! Capture windows, suite orchestration, and concrete workloads deliberately
//! live in separate modules. The capture implementation remains the owner of
//! low-overhead span and sampling hooks used by drivers.

#[cfg(feature = "kernel-bench")]
mod boot_state;
mod capture;
#[cfg(feature = "kernel-bench")]
mod runner;
#[cfg(feature = "kernel-bench")]
mod suites;

pub use capture::{
    bench_log_span_end, bench_span_guard, bench_submit_interrupt_sample_current_core,
    bench_submit_rip_sample, bench_submit_rip_sample_current_core, used_memory, BenchSpanGuard,
    BenchWindow, BENCH_ENABLED,
};

#[cfg(feature = "kernel-bench")]
pub use runner::{
    bench_case_end, bench_case_fail, bench_case_start, bench_measure, bench_measure_with_threshold,
    register_builtin_suites, register_suite, run_configured_suites, run_selected_suites,
};

#[cfg(feature = "kernel-bench")]
pub fn exit_benchmark_vm(success: bool) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut port = x86_64::instructions::port::Port::<u32>::new(0xf4);
        port.write(if success { 0x10 } else { 0x11 });
    }

    loop {
        crate::platform::halt();
    }
}
