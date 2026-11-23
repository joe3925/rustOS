use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::{
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
};
use kernel_executor::runtime::runtime::{
    JoinStorage, TaskOutcome, spawn, spawn_blocking, spawn_blocking_many, spawn_detached,
    spawn_join_owned,
};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{
        BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteStatus,
    },
};

use crate::{
    platform,
    scheduling::runtime::runtime::KernelExecutorPlatform,
    structs::stopwatch::Stopwatch,
};

use super::{
    bench_case_end, bench_case_fail, bench_case_start, bench_measure,
    bench_measure_with_tolerance, task_batch::yield_once,
};

const TASKS: usize = 256;
const TRIALS: usize = 15;
const TOLERANCE_PERCENT: f64 = 5.0;

pub(super) extern "C" fn suite<const LATENCY: bool>(
    handle: BenchRunHandle,
) -> AbiFuture<BenchSuiteStatus> {
    async move {
        let mut cases = [
            "spawn_to_run",
            "spawn",
            "spawn_join_owned",
            "spawn_detached",
            "spawn_blocking",
            "spawn_blocking_many",
        ];
        let cases = if LATENCY { &mut cases[..1] } else { &mut cases[1..] };
        let repetition = super::boot_state::current_repetition().await;
        let case_count = cases.len();
        cases.rotate_left(repetition.saturating_sub(1) as usize % case_count);

        for &case in cases.iter() {
            if !bench_case_start(handle, case.to_string()) {
                return BenchSuiteStatus::Failed;
            }

            let mut timer_ns = 0;
            for _ in 0..TASKS {
                timer_ns += if LATENCY {
                    let started = platform::ordered_cycle_counter();
                    let finished = platform::ordered_cycle_counter();
                    black_box(Stopwatch::from_cycles(finished - started).as_nanos() as u64)
                } else {
                    let timer = Stopwatch::start();
                    black_box(timer.elapsed_nanos())
                };
            }
            bench_measure(
                handle,
                "timer_ns_per_call".to_string(),
                timer_ns as f64 / TASKS as f64,
                BenchMetricUnit::Nanoseconds,
                BenchMetricDirection::Informational,
            );

            for trial in 0..=TRIALS {
                let mut elapsed = 0;
                let mut completed = 0;
                match case {
                    "spawn_to_run" => {
                        let mut storage = Box::pin(JoinStorage::new());
                        let mut samples = Vec::with_capacity(TASKS);
                        for _ in 0..TASKS {
                            let storage = storage.as_mut();
                            let future = async { platform::ordered_cycle_counter() };
                            let started = platform::ordered_cycle_counter();
                            let outcome =
                                spawn::<KernelExecutorPlatform, _, _>(storage, future).await;
                            let TaskOutcome::Completed(running) = outcome else {
                                bench_case_fail(handle, "spawn_to_run: task did not complete".into());
                                bench_case_end(handle);
                                return BenchSuiteStatus::Failed;
                            };
                            let Some(cycles) = running.checked_sub(started) else {
                                bench_case_fail(
                                    handle,
                                    "spawn_to_run: cycle counter moved backwards".into(),
                                );
                                bench_case_end(handle);
                                return BenchSuiteStatus::Failed;
                            };
                            let nanos = Stopwatch::from_cycles(cycles).as_nanos() as u64;
                            samples.push(nanos);
                            elapsed += nanos;
                            completed += 1;
                        }
                        if trial != 0 {
                            samples.sort_unstable();
                            for (metric, value) in [
                                (
                                    "spawn_to_run_p50_ns",
                                    (samples[TASKS / 2 - 1] as f64 + samples[TASKS / 2] as f64) / 2.0,
                                ),
                                (
                                    "spawn_to_run_p95_ns",
                                    samples[(TASKS * 95).div_ceil(100) - 1] as f64,
                                ),
                                (
                                    "spawn_to_run_p99_ns",
                                    samples[(TASKS * 99).div_ceil(100) - 1] as f64,
                                ),
                            ] {
                                bench_measure_with_tolerance(
                                    handle,
                                    metric.to_string(),
                                    value,
                                    BenchMetricUnit::Nanoseconds,
                                    BenchMetricDirection::LowerIsBetter,
                                    Some(TOLERANCE_PERCENT),
                                );
                            }
                        }
                    }
                    "spawn" => {
                        let mut storage: Vec<_> = (0..TASKS)
                            .map(|_| Box::pin(JoinStorage::new()))
                            .collect();
                        let mut joins = Vec::with_capacity(TASKS);
                        for (value, storage) in storage.iter_mut().enumerate() {
                            let future = async move { black_box(value) };
                            let storage = storage.as_mut();
                            let timer = Stopwatch::start();
                            let join = spawn::<KernelExecutorPlatform, _, _>(storage, future);
                            elapsed += timer.elapsed_nanos();
                            joins.push(join);
                        }
                        for (value, join) in joins.into_iter().enumerate() {
                            if matches!(join.await, TaskOutcome::Completed(result) if result == value) {
                                completed += 1;
                            }
                        }
                    }
                    "spawn_join_owned" => {
                        let mut joins = Vec::with_capacity(TASKS);
                        for value in 0..TASKS {
                            let future = async move { black_box(value) };
                            let timer = Stopwatch::start();
                            let join = spawn_join_owned::<KernelExecutorPlatform, _, _>(future);
                            elapsed += timer.elapsed_nanos();
                            joins.push(join);
                        }
                        for (value, join) in joins.into_iter().enumerate() {
                            if matches!(join.await, TaskOutcome::Completed(result) if result == value) {
                                completed += 1;
                            }
                        }
                    }
                    "spawn_detached" => {
                        let count = Arc::new(AtomicUsize::new(0));
                        for value in 0..TASKS {
                            let count = count.clone();
                            let future = async move {
                                black_box(value);
                                count.fetch_add(1, Ordering::Release);
                            };
                            let timer = Stopwatch::start();
                            spawn_detached::<KernelExecutorPlatform, _>(future);
                            elapsed += timer.elapsed_nanos();
                        }
                        while count.load(Ordering::Acquire) != TASKS {
                            yield_once().await;
                        }
                        completed = count.load(Ordering::Acquire);
                    }
                    "spawn_blocking" => {
                        let mut joins = Vec::with_capacity(TASKS);
                        for value in 0..TASKS {
                            let job = move || black_box(value);
                            let timer = Stopwatch::start();
                            let join = spawn_blocking::<KernelExecutorPlatform, _, _>(job);
                            elapsed += timer.elapsed_nanos();
                            joins.push(join);
                        }
                        for (value, join) in joins.into_iter().enumerate() {
                            if matches!(join.await, TaskOutcome::Completed(result) if result == value) {
                                completed += 1;
                            }
                        }
                    }
                    "spawn_blocking_many" => {
                        let jobs = (0..TASKS).map(|value| move || black_box(value)).collect();
                        let timer = Stopwatch::start();
                        let joins = spawn_blocking_many::<KernelExecutorPlatform, _, _>(jobs);
                        elapsed = timer.elapsed_nanos();
                        for (value, join) in joins.into_iter().enumerate() {
                            if matches!(join.await, TaskOutcome::Completed(result) if result == value) {
                                completed += 1;
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                if completed != TASKS || elapsed == 0 {
                    bench_case_fail(
                        handle,
                        alloc::format!("{case}: completed {completed}/{TASKS} tasks in {elapsed} ns"),
                    );
                    bench_case_end(handle);
                    return BenchSuiteStatus::Failed;
                }
                if trial != 0 {
                    bench_measure_with_tolerance(
                        handle,
                        if LATENCY { "spawn_to_run_ns" } else { "submit_ns_per_task" }.to_string(),
                        elapsed as f64 / TASKS as f64,
                        BenchMetricUnit::Nanoseconds,
                        BenchMetricDirection::LowerIsBetter,
                        Some(TOLERANCE_PERCENT),
                    );
                }
                yield_once().await;
            }
            bench_case_end(handle);
        }
        BenchSuiteStatus::Passed
    }
    .into_abi()
}
