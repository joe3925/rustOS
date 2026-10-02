use alloc::{string::ToString, vec, vec::Vec};
use core::hint::black_box;
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{
        BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteDescriptor,
        BenchSuiteStatus,
    },
    dma::{
        IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc,
        IoBufferBackingScratch,
    },
};

use crate::structs::stopwatch::Stopwatch;

use super::{
    bench_case_end, bench_case_fail, bench_case_start, bench_measure, bench_measure_with_tolerance,
    capture::bench_c_drive_io_async, task_batch::run_task_batch,
};

/// Independent boots dominate confidence. More boots narrow uncertainty but increase CI time.
/// Ten is the practical minimum for xtask's 99% model; 8–12 is the recommended range.
const INDEPENDENT_BOOTS: u16 = 10;
const QUEUE_TASKS_PER_CPU: usize = 4_096;
const QUEUE_TRIALS: usize = 15;
/// Queue duration is the most direct executor timing and is relatively stable. 2–5% is
/// recommended; lowering it detects smaller slowdowns but demands a quieter host.
const QUEUE_DURATION_TOLERANCE_PERCENT: f64 = 3.0;
/// Throughput is derived from duration and tends to amplify jitter. 5–10% is recommended.
const QUEUE_THROUGHPUT_TOLERANCE_PERCENT: f64 = 8.0;
/// Largest disk slowdown treated as practically unchanged. Lower values catch smaller changes but
/// warn more often; 5–10% is recommended for end-to-end virtual-disk benchmarks.
const DISK_TOLERANCE_PERCENT: f64 = 8.0;
const IOBUFFER_TOLERANCE_PERCENT: f64 = 2.0;
const IOBUFFER_TRIALS: usize = 15;
const IOBUFFER_LEASE_OPS: usize = 20_000;
const IOBUFFER_SPLIT_OPS: usize = 1_000;

pub fn descriptors() -> Vec<BenchSuiteDescriptor> {
    vec![
        BenchSuiteDescriptor::new(
            "executor.runtime",
            "Executor queue-pressure performance",
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
        BenchSuiteDescriptor::new(
            "io.iobuffer",
            "I/O buffer lease and scratch performance",
            vec!["ci".to_string(), "io".to_string()],
            iobuffer_suite,
        )
        .with_independent_boots(INDEPENDENT_BOOTS),
    ]
}

extern "C" fn iobuffer_suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        if !bench_case_start(handle, "lease-create-drop".to_string()) {
            return BenchSuiteStatus::Failed;
        }

        let mut bytes = vec![0u8; 2 * 1024 * 1024];
        let backing = match IoBufferBacking::new(
            IoBufferBackingDesc::SliceMut(&mut bytes),
            IoBufferBackingConfig::worst_case_for_len(2 * 1024 * 1024),
        ) {
            Ok(backing) => backing,
            Err(error) => {
                bench_case_fail(
                    handle,
                    alloc::format!("backing construction failed: {error:?}"),
                );
                bench_case_end(handle);
                return BenchSuiteStatus::Failed;
            }
        };

        for _ in 0..1_000 {
            drop(black_box(backing.create_to_device(0, 16 * 1024).unwrap()));
        }

        for _ in 0..IOBUFFER_TRIALS {
            for (offset, len, metric) in [
                (0, 1024, "create_drop.1k"),
                (0, 16 * 1024, "create_drop.16k"),
                (0, 64 * 1024, "create_drop.64k"),
                (0, 256 * 1024, "create_drop.256k"),
                (0, 2 * 1024 * 1024, "create_drop.2m"),
                (128, 64 * 1024, "create_drop.unaligned_64k"),
            ] {
                let timer = Stopwatch::start();
                for _ in 0..IOBUFFER_LEASE_OPS {
                    drop(black_box(
                        backing
                            .create_to_device(black_box(offset), black_box(len))
                            .unwrap(),
                    ));
                }
                bench_measure_with_tolerance(
                    handle,
                    metric.to_string(),
                    timer.elapsed_nanos() as f64 / IOBUFFER_LEASE_OPS as f64,
                    BenchMetricUnit::Nanoseconds,
                    BenchMetricDirection::LowerIsBetter,
                    Some(IOBUFFER_TOLERANCE_PERCENT),
                );
            }
        }
        bench_case_end(handle);

        if !bench_case_start(handle, "split-drop".to_string()) {
            return BenchSuiteStatus::Failed;
        }
        for _ in 0..100 {
            let mut tail = backing.create_to_device(0, 2 * 1024 * 1024).unwrap();
            while tail.len() > 64 * 1024 {
                let (piece, rest) = tail.split_at(64 * 1024).unwrap();
                drop(piece);
                tail = rest;
            }
            drop(tail);
        }
        for _ in 0..IOBUFFER_TRIALS {
            let timer = Stopwatch::start();
            for _ in 0..IOBUFFER_SPLIT_OPS {
                let mut tail = backing.create_to_device(0, 2 * 1024 * 1024).unwrap();
                while tail.len() > 64 * 1024 {
                    let (piece, rest) = tail.split_at(black_box(64 * 1024)).unwrap();
                    drop(black_box(piece));
                    tail = rest;
                }
                drop(black_box(tail));
            }
            bench_measure_with_tolerance(
                handle,
                "split_drop.2m_by_64k".to_string(),
                timer.elapsed_nanos() as f64 / IOBUFFER_SPLIT_OPS as f64,
                BenchMetricUnit::Nanoseconds,
                BenchMetricDirection::LowerIsBetter,
                Some(IOBUFFER_TOLERANCE_PERCENT),
            );
        }
        drop(backing);
        bench_case_end(handle);

        if !bench_case_start(handle, "scratch-reuse".to_string()) {
            return BenchSuiteStatus::Failed;
        }
        let mut scratch_bytes = vec![0u8; 64 * 1024];
        let mut scratch = IoBufferBackingScratch::new();
        let high_water = IoBufferBacking::from_scratch(
            IoBufferBackingDesc::SliceMut(&mut scratch_bytes),
            IoBufferBackingConfig::worst_case_for_len(64 * 1024),
            scratch,
        )
        .unwrap();
        scratch = high_water.into_scratch();
        for _ in 0..1_000 {
            let backing = IoBufferBacking::from_scratch(
                IoBufferBackingDesc::SliceMut(&mut scratch_bytes[..4]),
                IoBufferBackingConfig::worst_case_for_len(4),
                scratch,
            )
            .unwrap();
            drop(backing.create_from_device(0, 4).unwrap());
            scratch = backing.into_scratch();
        }
        for _ in 0..IOBUFFER_TRIALS {
            let timer = Stopwatch::start();
            for _ in 0..IOBUFFER_LEASE_OPS {
                let backing = IoBufferBacking::from_scratch(
                    IoBufferBackingDesc::SliceMut(&mut scratch_bytes[..4]),
                    IoBufferBackingConfig::worst_case_for_len(4),
                    scratch,
                )
                .unwrap();
                drop(black_box(backing.create_from_device(0, 4).unwrap()));
                scratch = backing.into_scratch();
            }
            bench_measure_with_tolerance(
                handle,
                "high_water_64k_then_4b".to_string(),
                timer.elapsed_nanos() as f64 / IOBUFFER_LEASE_OPS as f64,
                BenchMetricUnit::Nanoseconds,
                BenchMetricDirection::LowerIsBetter,
                Some(IOBUFFER_TOLERANCE_PERCENT),
            );
        }
        bench_case_end(handle);

        if !bench_case_start(handle, "virtual-create-drop".to_string()) {
            return BenchSuiteStatus::Failed;
        }
        for _ in 0..IOBUFFER_TRIALS {
            let timer = Stopwatch::start();
            for _ in 0..IOBUFFER_LEASE_OPS {
                let mut buffer = unsafe {
                    IoBuffer::from_virt_from_device(
                        black_box(scratch_bytes.as_mut_ptr() as usize),
                        black_box(4),
                    )
                };
                black_box(buffer.try_as_mut_slice().unwrap());
                drop(black_box(buffer));
            }
            bench_measure_with_tolerance(
                handle,
                "create_drop.4b".to_string(),
                timer.elapsed_nanos() as f64 / IOBUFFER_LEASE_OPS as f64,
                BenchMetricUnit::Nanoseconds,
                BenchMetricDirection::LowerIsBetter,
                Some(IOBUFFER_TOLERANCE_PERCENT),
            );
        }
        bench_case_end(handle);
        BenchSuiteStatus::Passed
    }
    .into_abi()
}

extern "C" fn executor_suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        if !executor_queue_stress(handle).await {
            return BenchSuiteStatus::Failed;
        }
        BenchSuiteStatus::Passed
    }
    .into_abi()
}

async fn executor_queue_stress(handle: BenchRunHandle) -> bool {
    if !bench_case_start(handle, "queue-stress".to_string()) {
        return false;
    }

    let task_count = QUEUE_TASKS_PER_CPU.saturating_mul(crate::platform::processor_count().max(1));
    let warmup = run_task_batch(task_count, queue_value).await;
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
        let checksum = run_task_batch(task_count, queue_value).await.checksum;
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

fn queue_value(value: u64) -> u64 {
    let mut result = value.rotate_left(17);
    for round in 0..1_024u64 {
        result = result.rotate_left(29).wrapping_add(0x9e37_79b9_7f4a_7c15) ^ round;
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
