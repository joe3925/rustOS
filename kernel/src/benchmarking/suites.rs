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
    bench_case_end, bench_case_fail, bench_case_start, bench_measure, bench_measure_with_tolerance,
    capture::bench_c_drive_io_async,
};

/// Independent boots dominate confidence. More boots narrow uncertainty but increase CI time.
/// Ten is the practical minimum for xtask's 99% model; 8–12 is the recommended range.
const INDEPENDENT_BOOTS: u16 = 10;
const CORRECTNESS_TASKS_PER_CPU: usize = 2_048;
/// Trials within a boot smooth brief jitter but are not independent evidence. Raising this makes
/// each boot slower; 10–30 is generally useful.
const CORRECTNESS_TRIALS: usize = 15;
const QUEUE_TASKS_PER_CPU: usize = 4_096;
const QUEUE_TRIALS: usize = 15;
/// Executor correctness includes allocation and scheduling noise. 5–10% is recommended.
const CORRECTNESS_TOLERANCE_PERCENT: f64 = 8.0;
/// Queue duration is the most direct executor timing and is relatively stable. 2–5% is
/// recommended; lowering it detects smaller slowdowns but demands a quieter host.
const QUEUE_DURATION_TOLERANCE_PERCENT: f64 = 3.0;
/// Throughput is derived from duration and tends to amplify jitter. 5–10% is recommended.
const QUEUE_THROUGHPUT_TOLERANCE_PERCENT: f64 = 8.0;
/// Largest disk slowdown treated as practically unchanged. Lower values catch smaller changes but
/// warn more often; 5–10% is recommended for end-to-end virtual-disk benchmarks.
const DISK_TOLERANCE_PERCENT: f64 = 8.0;

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
        )
        .with_independent_boots(INDEPENDENT_BOOTS),
        BenchSuiteDescriptor::new(
            "io.c-drive",
            "End-to-end C drive read/write workload",
            vec!["ci".to_string(), "io".to_string()],
            c_drive_suite,
        )
        .with_independent_boots(INDEPENDENT_BOOTS),
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
    let expected = (0..task_count as u64)
        .fold(0u64, |sum, value| sum.wrapping_add(correctness_value(value)));

    let warmup = run_task_batch(task_count, correctness_value).await;
    if warmup.checksum != expected {
        bench_case_fail(handle, "executor warm-up checksum mismatch".to_string());
        bench_case_end(handle);
        return false;
    }
    for (cpu, tasks) in warmup.cpu_tasks.into_iter().enumerate() {
        bench_measure(
            handle,
            alloc::format!("warmup_tasks.cpu{cpu}"),
            tasks as f64,
            BenchMetricUnit::Count,
            BenchMetricDirection::Informational,
        );
    }

    for _ in 0..CORRECTNESS_TRIALS {
        let timer = Stopwatch::start();
        let actual = run_task_batch(task_count, correctness_value).await.checksum;
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
        bench_measure_with_tolerance(
            handle,
            "duration".to_string(),
            elapsed as f64,
            BenchMetricUnit::Nanoseconds,
            BenchMetricDirection::LowerIsBetter,
            Some(CORRECTNESS_TOLERANCE_PERCENT),
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
    let warmup = run_queue_trial(task_count).await;
    for (cpu, tasks) in warmup.cpu_tasks.into_iter().enumerate() {
        bench_measure(
            handle,
            alloc::format!("warmup_tasks.cpu{cpu}"),
            tasks as f64,
            BenchMetricUnit::Count,
            BenchMetricDirection::Informational,
        );
    }

    for _ in 0..QUEUE_TRIALS {
        let timer = Stopwatch::start();
        let checksum = run_queue_trial(task_count).await.checksum;
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

        bench_measure_with_tolerance(
            handle,
            "duration".to_string(),
            elapsed as f64,
            BenchMetricUnit::Nanoseconds,
            BenchMetricDirection::LowerIsBetter,
            Some(QUEUE_DURATION_TOLERANCE_PERCENT),
        );
        bench_measure_with_tolerance(
            handle,
            "throughput".to_string(),
            task_count as f64 * 1_000_000_000.0 / elapsed as f64,
            BenchMetricUnit::OperationsPerSecond,
            BenchMetricDirection::HigherIsBetter,
            Some(QUEUE_THROUGHPUT_TOLERANCE_PERCENT),
        );
    }

    bench_case_end(handle);
    true
}

async fn run_queue_trial(task_count: usize) -> TaskBatchResult {
    run_task_batch(task_count, queue_value).await
}

#[repr(align(64))]
struct AlignedAtomicUsize(AtomicUsize);

struct TaskBatch {
    results: Vec<AtomicU64>,
    completed_per_cpu: Vec<AlignedAtomicUsize>,
    waiters: Vec<Mutex<Option<Waker>>>,
}

struct TaskBatchResult {
    checksum: u64,
    cpu_tasks: Vec<usize>,
}

async fn run_task_batch(task_count: usize, operation: fn(u64) -> u64) -> TaskBatchResult {
    let cpu_count = crate::platform::processor_count().max(1);
    let batch = Arc::new(TaskBatch {
        results: (0..task_count).map(|_| AtomicU64::new(0)).collect(),
        completed_per_cpu: (0..cpu_count)
            .map(|_| AlignedAtomicUsize(AtomicUsize::new(0)))
            .collect(),
        waiters: (0..cpu_count).map(|_| Mutex::new(None)).collect(),
    });

    for value in 0..task_count as u64 {
        let batch = batch.clone();
        spawn_detached(async move {
            yield_once().await;
            let cpu = crate::platform::current_cpu_id();
            batch.results[value as usize].store(operation(value), Ordering::Relaxed);
            batch.completed_per_cpu[cpu]
                .0
                .fetch_add(1, Ordering::Release);
            if let Some(waiter) = batch.waiters[cpu].lock().as_ref() {
                waiter.wake_by_ref();
            }
        });
    }

    poll_fn(|cx| {
        let completed = batch
            .completed_per_cpu
            .iter()
            .map(|counter| counter.0.load(Ordering::Acquire))
            .sum::<usize>();
        if completed == task_count {
            Poll::Ready(())
        } else {
            for waiter in &batch.waiters {
                *waiter.lock() = Some(cx.waker().clone());
            }
            let completed = batch
                .completed_per_cpu
                .iter()
                .map(|counter| counter.0.load(Ordering::Acquire))
                .sum::<usize>();
            if completed == task_count {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    })
    .await;

    TaskBatchResult {
        checksum: batch.results.iter().fold(0u64, |checksum, result| {
            checksum.wrapping_add(result.load(Ordering::Relaxed))
        }),
        cpu_tasks: batch
            .completed_per_cpu
            .iter()
            .map(|tasks| tasks.0.load(Ordering::Relaxed))
            .collect(),
    }
}

fn correctness_value(value: u64) -> u64 {
    let mut result = value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for round in 0..1_024u64 {
        result = result
            .rotate_left(13)
            .wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ round.wrapping_mul(0x94d0_49bb_1331_11eb);
    }
    result
}

fn queue_value(value: u64) -> u64 {
    let mut result = value.rotate_left(17);
    for round in 0..1_024u64 {
        result = result
            .rotate_left(29)
            .wrapping_add(0x9e37_79b9_7f4a_7c15)
            ^ round;
    }
    result
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
                bench_measure_with_tolerance(
                    handle,
                    alloc::format!("write_ns_per_op.{size}"),
                    value as f64,
                    BenchMetricUnit::Nanoseconds,
                    BenchMetricDirection::LowerIsBetter,
                    Some(DISK_TOLERANCE_PERCENT),
                );
            }
            for value in result.read_ns_per_op {
                bench_measure_with_tolerance(
                    handle,
                    alloc::format!("read_ns_per_op.{size}"),
                    value as f64,
                    BenchMetricUnit::Nanoseconds,
                    BenchMetricDirection::LowerIsBetter,
                    Some(DISK_TOLERANCE_PERCENT),
                );
            }
        }
        bench_case_end(handle);
        BenchSuiteStatus::Passed
    }
    .into_abi()
}
