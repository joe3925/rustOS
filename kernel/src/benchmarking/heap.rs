mod workload;

use alloc::{
    alloc::{alloc, dealloc},
    boxed::Box,
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteStatus},
};

use super::{
    bench_case_end, bench_case_start, bench_measure, bench_measure_with_tolerance,
    suites::THROUGHPUT_TOLERANCE_PERCENT,
};
use crate::memory::heap::mimalloc::{MIMALLOC_INITIAL_COMMITTED, committed_heap_bytes};
use crate::memory::paging::stack::StackSize;
use crate::platform;
use crate::scheduling::{
    scheduler::scheduler,
    task::{Task, TaskHandle},
};
use crate::sync_platform::{MpmcSender, mpmc_channel};
use workload::{CASES, PAIRS_PER_WORKER, SAMPLES, Sample, run_worker, sample_window};

struct Run {
    workers: usize,
    sizes: &'static [usize],
    round: AtomicUsize,
    waiters: spin::Mutex<Vec<TaskHandle>>,
}

struct Worker {
    workload: Arc<Run>,
    index: usize,
    result: MpmcSender<[Sample; SAMPLES]>,
}

extern "C" fn worker_entry(context: usize) {
    let worker = unsafe { Box::from_raw(context as *mut Worker) };
    let run = &worker.workload;
    let task = scheduler().get_local_current_task().unwrap();
    let samples = unsafe {
        run_worker(
            worker.index,
            run.sizes,
            |trial| {
                let mut waiters = run.waiters.lock();
                if waiters.len() + 1 == run.workers {
                    run.round.store(trial + 1, Ordering::Release);
                    for peer in waiters.drain(..) {
                        scheduler().unpark(&peer);
                    }
                } else {
                    waiters.push(task.clone());
                    drop(waiters);
                    while run.round.load(Ordering::Acquire) == trial {
                        scheduler().park_current();
                    }
                }
            },
            |layout| alloc(layout),
            |ptr, layout| dealloc(ptr, layout),
            platform::ordered_cycle_counter,
            || platform::current_cpu_id() as u32,
        )
    };
    worker.result.send(samples).unwrap();
}

pub(super) extern "C" fn suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        let workers = platform::processor_count();
        let hz = platform::cycle_counter_frequency_hz();
        let before = committed_heap_bytes();
        bench_case_start(handle, "physical-heap".into());
        for (metric, bytes) in [
            (
                "at_mimalloc_init",
                MIMALLOC_INITIAL_COMMITTED.load(Ordering::Acquire),
            ),
            ("before_workers", before),
        ] {
            bench_measure(
                handle,
                metric.into(),
                bytes as f64,
                BenchMetricUnit::Bytes,
                BenchMetricDirection::LowerIsBetter,
            );
        }
        bench_case_end(handle);
        for (case, sizes) in CASES {
            bench_case_start(handle, case.into());
            let workload = Arc::new(Run {
                workers,
                sizes,
                round: 0.into(),
                waiters: spin::Mutex::new(Vec::with_capacity(workers - 1)),
            });
            let (result, receiver) = mpmc_channel();
            for index in 0..workers {
                let worker = Box::new(Worker {
                    workload: workload.clone(),
                    index,
                    result: result.clone(),
                });
                let task = Task::new_kernel_mode(
                    worker_entry,
                    Box::into_raw(worker) as usize,
                    StackSize::Large,
                    alloc::format!("heap-bench-{index}"),
                    0,
                );
                scheduler().add_task(task);
            }
            drop(result);
            let samples: Vec<_> = (0..workers).map(|_| receiver.recv().unwrap()).collect();
            let pairs = PAIRS_PER_WORKER as u64 * workers as u64;
            bench_measure(
                handle,
                "pairs".into(),
                pairs as f64,
                BenchMetricUnit::Count,
                BenchMetricDirection::HigherIsBetter,
            );
            for trial in 0..SAMPLES {
                let (ticks, cpus) = sample_window(&samples, trial);
                let ns = (u128::from(ticks) * 1_000_000_000 / u128::from(hz)) as u64;
                bench_measure(
                    handle,
                    "wall_ns".into(),
                    ns as f64,
                    BenchMetricUnit::Nanoseconds,
                    BenchMetricDirection::LowerIsBetter,
                );
                bench_measure_with_tolerance(
                    handle,
                    "pairs_per_second".into(),
                    pairs as f64 * 1e9 / ns as f64,
                    BenchMetricUnit::OperationsPerSecond,
                    BenchMetricDirection::HigherIsBetter,
                    Some(THROUGHPUT_TOLERANCE_PERCENT),
                );
                bench_measure(
                    handle,
                    "worker_cpus_at_start".into(),
                    cpus as f64,
                    BenchMetricUnit::Count,
                    BenchMetricDirection::HigherIsBetter,
                );
            }
            bench_case_end(handle);
        }
        BenchSuiteStatus::Passed
    }
    .into_abi()
}
