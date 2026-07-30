use alloc::{string::ToString, vec, vec::Vec};
use core::{
    future::Future,
    hint::black_box,
    pin::Pin,
    task::{Context, Poll},
};
use kernel_executor::runtime::runtime::{JoinAll, spawn_join_owned};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{
        BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteDescriptor,
        BenchSuiteStatus,
    },
};

use crate::structs::stopwatch::Stopwatch;

use super::{
    bench_case_end, bench_case_fail, bench_case_start, bench_measure,
    capture::bench_c_drive_io_async,
};

const CORRECTNESS_TASKS_PER_CPU: usize = 2_048;
const QUEUE_TASKS_PER_CPU: usize = 4_096;
const QUEUE_TRIALS: usize = 8;

struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn yield_once() -> YieldOnce {
    YieldOnce(false)
}

pub fn descriptors() -> Vec<BenchSuiteDescriptor> {
    vec![
        BenchSuiteDescriptor::new(
            "executor.runtime",
            "Executor correctness and queue-pressure stress",
            vec!["ci".to_string(), "executor".to_string()],
            executor_suite,
        ),
        BenchSuiteDescriptor::new(
            "io.c-drive",
            "End-to-end C drive read/write workload",
            vec!["ci".to_string(), "io".to_string()],
            c_drive_suite,
        ),
    ]
}

extern "C" fn executor_suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        if !executor_correctness(handle).await {
            return BenchSuiteStatus::Failed;
        }
        if !executor_queue_stress(handle).await {
            return BenchSuiteStatus::Failed;
        }
        BenchSuiteStatus::Passed
    }
    .into_abi()
}

async fn executor_correctness(handle: BenchRunHandle) -> bool {
    if !bench_case_start(handle, "correctness".to_string()) {
        return false;
    }

    let cpu_count = crate::platform::processor_count().max(1);
    let task_count = CORRECTNESS_TASKS_PER_CPU.saturating_mul(cpu_count);
    let expected = (0..task_count as u64).fold(0u64, |sum, value| {
        sum.wrapping_add(value.wrapping_mul(0x9e37_79b9_7f4a_7c15))
    });

    let timer = Stopwatch::start();
    let mut tasks = Vec::with_capacity(task_count);
    for value in 0..task_count as u64 {
        tasks.push(spawn_join_owned(async move {
            yield_once().await;
            value.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        }));
    }
    let actual = JoinAll::new(tasks)
        .await
        .into_iter()
        .fold(0u64, u64::wrapping_add);
    let elapsed = timer.elapsed_nanos();

    if actual != expected {
        bench_case_fail(
            handle,
            alloc::format!(
                "executor checksum mismatch: expected={expected:#x}, actual={actual:#x}"
            ),
        );
    }
    bench_measure(
        handle,
        "duration".to_string(),
        elapsed as f64,
        BenchMetricUnit::Nanoseconds,
        BenchMetricDirection::Informational,
    );
    bench_measure(
        handle,
        "tasks".to_string(),
        task_count as f64,
        BenchMetricUnit::Count,
        BenchMetricDirection::Informational,
    );
    bench_case_end(handle);
    actual == expected
}

async fn executor_queue_stress(handle: BenchRunHandle) -> bool {
    if !bench_case_start(handle, "queue-stress".to_string()) {
        return false;
    }

    let task_count = QUEUE_TASKS_PER_CPU.saturating_mul(crate::platform::processor_count().max(1));
    run_queue_trial(task_count).await;

    for _ in 0..QUEUE_TRIALS {
        let timer = Stopwatch::start();
        let checksum = run_queue_trial(task_count).await;
        let elapsed = timer.elapsed_nanos();
        black_box(checksum);

        if elapsed == 0 {
            bench_case_fail(
                handle,
                "platform timer returned a zero duration".to_string(),
            );
            bench_case_end(handle);
            return false;
        }

        bench_measure(
            handle,
            "duration".to_string(),
            elapsed as f64,
            BenchMetricUnit::Nanoseconds,
            BenchMetricDirection::LowerIsBetter,
        );
        bench_measure(
            handle,
            "throughput".to_string(),
            task_count as f64 * 1_000_000_000.0 / elapsed as f64,
            BenchMetricUnit::OperationsPerSecond,
            BenchMetricDirection::HigherIsBetter,
        );
    }

    bench_case_end(handle);
    true
}

async fn run_queue_trial(task_count: usize) -> u64 {
    let mut tasks = Vec::with_capacity(task_count);
    for value in 0..task_count as u64 {
        tasks.push(spawn_join_owned(async move {
            yield_once().await;
            value.rotate_left(17)
        }));
    }
    JoinAll::new(tasks)
        .await
        .into_iter()
        .fold(0u64, u64::wrapping_add)
}

extern "C" fn c_drive_suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        if !bench_case_start(handle, "read-write".to_string()) {
            return BenchSuiteStatus::Failed;
        }

        // The retained workload is migrated first as a single end-to-end case.
        // Its per-size measurements will move behind a reporter in the same
        // module without coupling the capture runtime to filesystem code.
        let timer = Stopwatch::start();
        bench_c_drive_io_async(true).await;
        let elapsed = timer.elapsed_nanos();
        bench_measure(
            handle,
            "duration".to_string(),
            elapsed as f64,
            BenchMetricUnit::Nanoseconds,
            BenchMetricDirection::LowerIsBetter,
        );
        bench_case_end(handle);
        BenchSuiteStatus::Passed
    }
    .into_abi()
}
