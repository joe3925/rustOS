pub(super) mod dispatch;
pub(super) mod handoff;
pub(super) mod lifecycle;

use alloc::{boxed::Box, vec::Vec};
use kernel_types::benchmark::{BenchMetricDirection, BenchMetricUnit, BenchRunHandle};

use crate::{
    memory::paging::stack::StackSize,
    platform,
    scheduling::{
        domain::TaskSchedBinding,
        runtime::runtime::yield_now,
        scheduler::scheduler,
        task::{Task, TaskHandle},
    },
};

use super::{bench_case_end, bench_case_start, bench_measure};

const TRIALS: usize = 5;
const SAMPLES: usize = 256;

fn clock_cost(handle: BenchRunHandle) {
    assert!(bench_case_start(handle, "clock".into()));
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let cpu = platform::current_cpu_id();
        let start = platform::ordered_cycle_counter();
        let end = platform::ordered_cycle_counter();
        if platform::current_cpu_id() == cpu && end >= start {
            samples.push(end - start);
        }
    }
    distribution(handle, "ordered_counter_pair", &mut samples);
    bench_case_end(handle);
}

extern "C" fn entry(context: usize) {
    let work = unsafe { Box::from_raw(context as *mut Box<dyn FnOnce() + Send>) };
    work();
}

fn thread(work: impl FnOnce() + Send + 'static, binding: TaskSchedBinding) -> TaskHandle {
    let work: Box<dyn FnOnce() + Send> = Box::new(work);
    Task::new_kernel_mode_with_sched_binding(
        entry,
        Box::into_raw(Box::new(work)) as usize,
        StackSize::Small,
        "scheduler-bench".into(),
        0,
        binding,
    )
}

fn retire(tasks: Vec<TaskHandle>) {
    let deadline = platform::ordered_cycle_counter() + 10 * platform::cycle_counter_frequency_hz();
    for task in &tasks {
        while scheduler().get_task_by_id(task.task_id()).is_some() {
            assert!(
                platform::ordered_cycle_counter() < deadline,
                "benchmark thread did not exit"
            );
            yield_now();
        }
    }
    drop(tasks);
    scheduler().reap_retired_tasks();
}

fn distribution(handle: BenchRunHandle, name: &str, cycles: &mut [u64]) {
    bench_measure(
        handle,
        alloc::format!("{name}.samples"),
        cycles.len() as f64,
        BenchMetricUnit::Count,
        BenchMetricDirection::Informational,
    );
    if cycles.is_empty() {
        return;
    }
    cycles.sort_unstable();
    let scale = 1e9 / platform::cycle_counter_frequency_hz() as f64;
    let sum: u128 = cycles.iter().map(|&value| value as u128).sum();
    for (statistic, value) in [
        ("min", cycles[0] as f64),
        ("mean", sum as f64 / cycles.len() as f64),
        ("p50", cycles[(cycles.len() * 50).div_ceil(100) - 1] as f64),
        ("p95", cycles[(cycles.len() * 95).div_ceil(100) - 1] as f64),
        ("p99", cycles[(cycles.len() * 99).div_ceil(100) - 1] as f64),
        ("max", cycles[cycles.len() - 1] as f64),
    ] {
        bench_measure(
            handle,
            alloc::format!("{name}.{statistic}"),
            value * scale,
            BenchMetricUnit::Nanoseconds,
            BenchMetricDirection::LowerIsBetter,
        );
    }
}
