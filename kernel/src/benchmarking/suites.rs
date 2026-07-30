use alloc::{string::ToString, sync::Arc, vec, vec::Vec};
use core::{
    future::{Future, poll_fn},
    hint::black_box,
    pin::Pin,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use kernel_executor::runtime::runtime::spawn_detached;
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{
        BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteDescriptor,
        BenchSuiteStatus,
    },
};
use spin::Mutex;

use crate::structs::stopwatch::Stopwatch;

use super::{
    bench_case_end, bench_case_fail, bench_case_start, bench_measure, bench_measure_with_threshold,
    capture::bench_c_drive_io_async,
};

const CORRECTNESS_TASKS_PER_CPU: usize = 2_048;
const CORRECTNESS_TRIALS: usize = 15;
const QUEUE_TASKS_PER_CPU: usize = 4_096;
const QUEUE_TRIALS: usize = 15;

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

    if run_task_batch(task_count, correctness_value).await != expected {
        bench_case_fail(handle, "executor warm-up checksum mismatch".to_string());
        bench_case_end(handle);
        return false;
    }

    for _ in 0..CORRECTNESS_TRIALS {
        let timer = Stopwatch::start();
        let actual = run_task_batch(task_count, correctness_value).await;
        let elapsed = timer.elapsed_nanos();

        if actual != expected {
            bench_case_fail(
                handle,
                alloc::format!(
                    "executor checksum mismatch: expected={expected:#x}, actual={actual:#x}"
                ),
            );
            bench_case_end(handle);
            return false;
        }
        bench_measure_with_threshold(
            handle,
            "duration".to_string(),
            elapsed as f64,
            BenchMetricUnit::Nanoseconds,
            BenchMetricDirection::LowerIsBetter,
            Some(3.0),
        );
    }
    bench_measure(
        handle,
        "tasks".to_string(),
        task_count as f64,
        BenchMetricUnit::Count,
        BenchMetricDirection::Informational,
    );
    bench_case_end(handle);
    true
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

        bench_measure_with_threshold(
            handle,
            "duration".to_string(),
            elapsed as f64,
            BenchMetricUnit::Nanoseconds,
            BenchMetricDirection::LowerIsBetter,
            Some(3.0),
        );
        bench_measure_with_threshold(
            handle,
            "throughput".to_string(),
            task_count as f64 * 1_000_000_000.0 / elapsed as f64,
            BenchMetricUnit::OperationsPerSecond,
            BenchMetricDirection::HigherIsBetter,
            Some(3.0),
        );
    }

    bench_case_end(handle);
    true
}

async fn run_queue_trial(task_count: usize) -> u64 {
    run_task_batch(task_count, queue_value).await
}

struct TaskBatch {
    completed: AtomicUsize,
    checksum: AtomicU64,
    waiter: Mutex<Option<Waker>>,
}

async fn run_task_batch(task_count: usize, operation: fn(u64) -> u64) -> u64 {
    let batch = Arc::new(TaskBatch {
        completed: AtomicUsize::new(0),
        checksum: AtomicU64::new(0),
        waiter: Mutex::new(None),
    });

    for value in 0..task_count as u64 {
        let batch = batch.clone();
        spawn_detached(async move {
            yield_once().await;
            batch
                .checksum
                .fetch_add(operation(value), Ordering::Relaxed);
            if batch.completed.fetch_add(1, Ordering::AcqRel) + 1 == task_count {
                if let Some(waiter) = batch.waiter.lock().take() {
                    waiter.wake();
                }
            }
        });
    }

    poll_fn(|cx| {
        if batch.completed.load(Ordering::Acquire) == task_count {
            Poll::Ready(())
        } else {
            *batch.waiter.lock() = Some(cx.waker().clone());
            if batch.completed.load(Ordering::Acquire) == task_count {
                batch.waiter.lock().take();
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    })
    .await;
    batch.checksum.load(Ordering::Relaxed)
}

fn correctness_value(value: u64) -> u64 {
    value.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn queue_value(value: u64) -> u64 {
    value.rotate_left(17)
}

extern "C" fn c_drive_suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        if !bench_case_start(handle, "read-write".to_string()) {
            return BenchSuiteStatus::Failed;
        }

        let Some(results) = bench_c_drive_io_async(true).await else {
            bench_case_fail(handle, "C drive workload failed".to_string());
            bench_case_end(handle);
            return BenchSuiteStatus::Failed;
        };
        for result in results.sizes {
            let size = alloc::format!("{}k", result.size_bytes / 1024);
            for value in result.write_ns_per_op {
                bench_measure_with_threshold(
                    handle,
                    alloc::format!("write_ns_per_op.{size}"),
                    value as f64,
                    BenchMetricUnit::Nanoseconds,
                    BenchMetricDirection::LowerIsBetter,
                    Some(3.0),
                );
            }
            for value in result.read_ns_per_op {
                bench_measure_with_threshold(
                    handle,
                    alloc::format!("read_ns_per_op.{size}"),
                    value as f64,
                    BenchMetricUnit::Nanoseconds,
                    BenchMetricDirection::LowerIsBetter,
                    Some(3.0),
                );
            }
        }
        bench_case_end(handle);
        BenchSuiteStatus::Passed
    }
    .into_abi()
}
