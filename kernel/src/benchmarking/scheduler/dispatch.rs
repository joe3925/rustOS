use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    hint::black_box,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteStatus},
};

use crate::{
    benchmarking::{bench_case_end, bench_case_start, bench_measure},
    platform,
    scheduling::{
        domain::{KERNEL_DOMAIN_ID, TaskSchedBinding, USER_DOMAIN_ID},
        fifo_scheduler::{FifoPriority, FifoTaskState},
        runtime::runtime::yield_now,
        scheduler::{kernel_task_sched_binding, scheduler},
    },
    sync_platform::bounded_mpmc_channel,
};

use super::{SAMPLES, TRIALS, clock_cost, distribution, retire, thread};

struct Gate {
    end: AtomicU64,
    open: AtomicBool,
}

struct Result {
    index: usize,
    operations: u64,
    first: u64,
    first_cpu: usize,
    last: u64,
    max_gap: u64,
    gaps: Vec<u64>,
    cpu_operations: Vec<u64>,
    migrations: usize,
}

pub(crate) extern "C" fn suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        clock_cost(handle);
        let cpus = platform::processor_count();
        let hz = platform::cycle_counter_frequency_hz();
        let workers = (cpus * 4).min(256);
        let mut cases = vec![
            ("yield.initial-cpu0.1", 1, true, 0),
            ("yield.initial-cpu0.2", 2, true, 0),
            ("yield.initial-cpu0.8", 8, true, 0),
            ("yield.initial-cpu0.32", 32, true, 0),
            ("yield.initial-cpu0.128", 128, true, 0),
            ("yield.initial-cpu0.512", 512, true, 0),
            ("yield.initial-cpu0.1024", 1024, true, 0),
            ("yield.spread", workers, true, 1),
            ("yield.automatic", workers, true, 2),
            ("yield.cache-64k.2", 2, true, 0),
            ("yield.cache-1m.2", 2, true, 0),
            ("compute.cache-64k.single", 1, false, 1),
            ("compute.cache-1m.single", 1, false, 1),
            ("compute.single", 1, false, 1),
            ("preempt.spread", workers, false, 1),
            ("nonpreempt.realtime", workers, false, 6),
            ("balance.initial-cpu0", workers, false, 0),
            ("priority.normal-low", workers, false, 3),
            ("domains.equal", workers, false, 4),
            ("domains.unequal", workers, false, 5),
        ];
        let repetition = super::super::boot_state::current_repetition().await;
        let count = cases.len();
        cases.rotate_left(repetition.saturating_sub(1) as usize % count);
        for (name, workers, voluntary, placement) in cases {
            let working_set_bytes = if name.contains("cache-64k") {
                64 * 1024
            } else if name.contains("cache-1m") {
                1024 * 1024
            } else {
                0
            };
            if !bench_case_start(handle, name.into()) {
                return BenchSuiteStatus::Failed;
            }
            for trial in 0..=TRIALS {
                let gate = Arc::new(Gate {
                    end: 0.into(),
                    open: false.into(),
                });
                let (ready, ready_rx) = bounded_mpmc_channel(workers, 1);
                let (finished, finished_rx) = bounded_mpmc_channel(workers, 1);
                let mut tasks = Vec::with_capacity(workers);
                for index in 0..workers {
                    let low = placement == 3 && index % 2 == 1;
                    let user = (placement == 4 && index % 2 == 1)
                        || (placement == 5 && index == workers - 1);
                    let binding = TaskSchedBinding::new(
                        if user {
                            USER_DOMAIN_ID
                        } else {
                            KERNEL_DOMAIN_ID
                        },
                        FifoTaskState::new(if low {
                            FifoPriority::Low
                        } else if placement == 6 {
                            FifoPriority::Realtime
                        } else {
                            FifoPriority::Normal
                        }),
                    );
                    let gate = gate.clone();
                    let ready = ready.clone();
                    let finished = finished.clone();
                    let mut result = Result {
                        index,
                        operations: 0,
                        first: 0,
                        first_cpu: 0,
                        last: 0,
                        max_gap: 0,
                        gaps: Vec::with_capacity(SAMPLES),
                        cpu_operations: vec![0; cpus],
                        migrations: 0,
                    };
                    let mut working_set = vec![index as u64; working_set_bytes / 8];
                    black_box(&mut working_set);
                    let cleanup_binding = low.then(kernel_task_sched_binding);
                    let task = thread(
                        move || {
                            ready.send(()).unwrap();
                            while !gate.open.load(Ordering::Acquire) {
                                scheduler().park_current();
                            }
                            let end = gate.end.load(Ordering::Relaxed);
                            result.first = platform::ordered_cycle_counter();
                            result.first_cpu = platform::current_cpu_id();
                            let mut previous = result.first;
                            let mut previous_cpu = result.first_cpu;
                            let mut random = (index as u64 + 1) * 0x9e37_79b9;
                            let mut value = index as u64;
                            let mut observed = 0;
                            while previous < end {
                                let call_cpu = platform::current_cpu_id();
                                let started = platform::ordered_cycle_counter();
                                if started >= end {
                                    previous = started;
                                    break;
                                }
                                for word in working_set.iter_mut().step_by(8) {
                                    *word = black_box(word.wrapping_add(value));
                                }
                                if voluntary {
                                    yield_now();
                                } else if working_set_bytes == 0 {
                                    for round in 0..256 {
                                        value = black_box(
                                            value.rotate_left(7).wrapping_add(0x9e37_79b9) ^ round,
                                        );
                                    }
                                }
                                let now = platform::ordered_cycle_counter();
                                let cpu = platform::current_cpu_id();
                                if now <= end {
                                    result.operations += 1;
                                    result.cpu_operations[cpu] += 1;
                                }
                                if cpu != previous_cpu {
                                    result.migrations += 1;
                                }
                                if cpu == call_cpu && now >= started {
                                    let gap = now - started;
                                    result.max_gap = result.max_gap.max(gap);
                                    observed += 1;
                                    if result.gaps.len() < SAMPLES {
                                        result.gaps.push(gap);
                                    } else {
                                        random ^= random << 13;
                                        random ^= random >> 7;
                                        random ^= random << 17;
                                        let slot = (random % observed) as usize;
                                        if slot < SAMPLES {
                                            result.gaps[slot] = gap;
                                        }
                                    }
                                }
                                previous = now;
                                previous_cpu = cpu;
                            }
                            black_box(value);
                            result.last = previous;
                            if let Some(binding) = cleanup_binding {
                                let current = scheduler().get_local_current_task().unwrap();
                                scheduler()
                                    .migrate_task_domain(current.task_id(), binding)
                                    .unwrap();
                                yield_now();
                            }
                            finished.send(result).ok().unwrap();
                        },
                        binding,
                    );
                    scheduler().add_task_on(
                        task.clone(),
                        match placement {
                            0 => Some(0),
                            2 => None,
                            3 | 4 => Some((index / 2) % cpus),
                            _ => Some(index % cpus),
                        },
                    );
                    tasks.push(task);
                }
                drop(ready);
                drop(finished);
                for _ in 0..workers {
                    ready_rx.recv().unwrap();
                }
                let mut targets = vec![0usize; cpus];
                for task in &tasks {
                    targets[task.target_cpu()] += 1;
                }
                let start = platform::ordered_cycle_counter();
                let ticks = platform::timer_tick_count();
                gate.end.store(start + hz / 4, Ordering::Relaxed);
                gate.open.store(true, Ordering::Release);
                for task in &tasks {
                    scheduler().unpark(task);
                }
                let mut results: Vec<_> =
                    (0..workers).map(|_| finished_rx.recv().unwrap()).collect();
                let wall = platform::ordered_cycle_counter().saturating_sub(start);
                let ticks = platform::timer_tick_count().wrapping_sub(ticks);
                retire(tasks);
                if trial == 0 {
                    continue;
                }
                results.sort_unstable_by_key(|result| result.index);
                let operations: u64 = results.iter().map(|result| result.operations).sum();
                let sum_squares: f64 = results
                    .iter()
                    .map(|result| result.operations as f64 * result.operations as f64)
                    .sum();
                let mut gaps: Vec<_> = results
                    .iter_mut()
                    .flat_map(|result| result.gaps.drain(..))
                    .collect();
                let mut first: Vec<_> = results
                    .iter()
                    .map(|result| result.first.saturating_sub(start))
                    .collect();
                distribution(
                    handle,
                    if voluntary && working_set_bytes != 0 {
                        "memory_scan_and_yield"
                    } else if voluntary {
                        "yield_return"
                    } else if working_set_bytes != 0 {
                        "memory_scan"
                    } else {
                        "compute_chunk_gap"
                    },
                    &mut gaps,
                );
                distribution(handle, "release_to_first_work", &mut first);
                for (metric, value, unit, direction) in [
                    (
                        "workers",
                        workers as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    ),
                    (
                        "working_set_bytes_per_worker",
                        working_set_bytes as f64,
                        BenchMetricUnit::Bytes,
                        BenchMetricDirection::Informational,
                    ),
                    (
                        "window",
                        250_000_000.0,
                        BenchMetricUnit::Nanoseconds,
                        BenchMetricDirection::Informational,
                    ),
                    (
                        "batch_wall",
                        wall as f64 * 1e9 / hz as f64,
                        BenchMetricUnit::Nanoseconds,
                        BenchMetricDirection::LowerIsBetter,
                    ),
                    (
                        "operations",
                        operations as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::HigherIsBetter,
                    ),
                    (
                        "operations_per_second",
                        operations as f64 * 4.0,
                        BenchMetricUnit::OperationsPerSecond,
                        BenchMetricDirection::HigherIsBetter,
                    ),
                    (
                        "jain_fairness",
                        if sum_squares > 0.0 {
                            operations as f64 * operations as f64 / (workers as f64 * sum_squares)
                        } else {
                            0.0
                        },
                        BenchMetricUnit::Ratio,
                        BenchMetricDirection::Informational,
                    ),
                    (
                        "workers_without_progress",
                        results
                            .iter()
                            .filter(|result| result.operations == 0)
                            .count() as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    ),
                    (
                        "cpu_migrations",
                        results
                            .iter()
                            .map(|result| result.migrations)
                            .sum::<usize>() as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    ),
                    (
                        "timer_ticks",
                        ticks as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    ),
                    (
                        "max_observed_gap",
                        results
                            .iter()
                            .map(|result| result.max_gap)
                            .max()
                            .unwrap_or(0) as f64
                            * 1e9
                            / hz as f64,
                        BenchMetricUnit::Nanoseconds,
                        BenchMetricDirection::LowerIsBetter,
                    ),
                    (
                        "worker_stop_after_deadline",
                        results
                            .iter()
                            .map(|result| result.last.saturating_sub(start + hz / 4))
                            .max()
                            .unwrap_or(0) as f64
                            * 1e9
                            / hz as f64,
                        BenchMetricUnit::Nanoseconds,
                        BenchMetricDirection::LowerIsBetter,
                    ),
                ] {
                    bench_measure(handle, metric.into(), value, unit, direction);
                }
                if (3..=5).contains(&placement) {
                    let second_group: u64 = results
                        .iter()
                        .filter(|result| {
                            if placement == 5 {
                                result.index == workers - 1
                            } else {
                                result.index % 2 == 1
                            }
                        })
                        .map(|result| result.operations)
                        .sum();
                    for (group, count) in if placement == 3 {
                        [("normal", operations - second_group), ("low", second_group)]
                    } else {
                        [
                            ("kernel-domain", operations - second_group),
                            ("user-domain", second_group),
                        ]
                    } {
                        bench_measure(
                            handle,
                            alloc::format!("operations.{group}"),
                            count as f64,
                            BenchMetricUnit::Count,
                            BenchMetricDirection::Informational,
                        );
                    }
                }
                for cpu in 0..cpus {
                    bench_measure(
                        handle,
                        alloc::format!("target_workers_at_release.cpu{cpu}"),
                        targets[cpu] as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    );
                    bench_measure(
                        handle,
                        alloc::format!("operations.cpu{cpu}"),
                        results
                            .iter()
                            .map(|result| result.cpu_operations[cpu])
                            .sum::<u64>() as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    );
                    bench_measure(
                        handle,
                        alloc::format!("first_workers.cpu{cpu}"),
                        results
                            .iter()
                            .filter(|result| result.first_cpu == cpu)
                            .count() as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    );
                }
                for result in &results {
                    bench_measure(
                        handle,
                        alloc::format!("operations.worker{}", result.index),
                        result.operations as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    );
                }
            }
            bench_case_end(handle);
        }
        BenchSuiteStatus::Passed
    }
    .into_abi()
}
