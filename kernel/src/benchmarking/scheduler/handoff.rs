use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    hint::black_box,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteStatus},
};
use spin::Once;

use crate::{
    benchmarking::{bench_case_end, bench_case_start, bench_measure},
    platform,
    scheduling::{
        domain::{KERNEL_DOMAIN_ID, TaskSchedBinding, USER_DOMAIN_ID},
        fifo_scheduler::{FifoPriority, FifoTaskState},
        runtime::runtime::yield_now,
        scheduler::{kernel_task_sched_binding, scheduler},
        state::SchedState,
        task::TaskHandle,
    },
    sync_platform::bounded_mpmc_channel,
};

use super::{SAMPLES, TRIALS, clock_cost, distribution, retire, thread};

struct Pair {
    tasks: Once<[TaskHandle; 2]>,
    request: AtomicUsize,
    completed: AtomicUsize,
    responder_cpu: AtomicUsize,
    stop: AtomicBool,
}

pub(crate) extern "C" fn suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        clock_cost(handle);
        let cpus = platform::processor_count();
        let hz = platform::cycle_counter_frequency_hz();
        let mut cases = vec![
            ("pair.initial-local", 0),
            ("pair.initial-remote", 1),
            ("pair.busy-remote", 2),
            ("pair.realtime-responder", 3),
            ("pair.cross-domain", 4),
            ("migration.blocked", 5),
        ];
        let repetition = super::super::boot_state::current_repetition().await;
        let count = cases.len();
        cases.rotate_left(repetition.saturating_sub(1) as usize % count);
        for (name, mode) in cases {
            if (mode == 1 || mode == 2) && cpus < 2 {
                continue;
            }
            if !bench_case_start(handle, name.into()) {
                return BenchSuiteStatus::Failed;
            }
            for trial in 0..=TRIALS {
                let pair = Arc::new(Pair {
                    tasks: Once::new(),
                    request: 0.into(),
                    completed: 0.into(),
                    responder_cpu: usize::MAX.into(),
                    stop: false.into(),
                });
                let (finished, rx) = bounded_mpmc_channel(1, 1);
                let responder_pair = pair.clone();
                let responder = thread(
                    move || {
                        let mut completed = 0;
                        while !responder_pair.stop.load(Ordering::Acquire) {
                            let request = responder_pair.request.load(Ordering::Acquire);
                            if request == completed {
                                scheduler().park_current();
                                continue;
                            }
                            responder_pair
                                .responder_cpu
                                .store(platform::current_cpu_id(), Ordering::Relaxed);
                            completed = request;
                            responder_pair.completed.store(completed, Ordering::Release);
                            scheduler().unpark(&responder_pair.tasks.get().unwrap()[0]);
                        }
                    },
                    TaskSchedBinding::new(
                        if mode == 4 {
                            USER_DOMAIN_ID
                        } else {
                            KERNEL_DOMAIN_ID
                        },
                        FifoTaskState::new(if mode == 3 {
                            FifoPriority::Realtime
                        } else {
                            FifoPriority::Normal
                        }),
                    ),
                );
                let initiator_pair = pair.clone();
                let initiator = thread(
                    move || {
                        let mut local = Vec::with_capacity(SAMPLES);
                        let mut remote = Vec::with_capacity(SAMPLES);
                        let mut idle_remote = Vec::with_capacity(SAMPLES);
                        let mut unpark = Vec::with_capacity(SAMPLES);
                        let mut migration = Vec::with_capacity(SAMPLES);
                        let mut moved = 0;
                        let responder = &initiator_pair.tasks.get().unwrap()[1];
                        for sample in 0..32 + SAMPLES {
                            let deadline = platform::ordered_cycle_counter() + 10 * hz;
                            while responder.sched_state() != SchedState::Blocked {
                                assert!(
                                    platform::ordered_cycle_counter() < deadline,
                                    "responder did not block"
                                );
                                yield_now();
                            }
                            if mode == 5 {
                                let binding = TaskSchedBinding::new(
                                    if sample % 2 == 0 {
                                        USER_DOMAIN_ID
                                    } else {
                                        KERNEL_DOMAIN_ID
                                    },
                                    FifoTaskState::new(FifoPriority::Normal),
                                );
                                let cpu = platform::current_cpu_id();
                                let start = platform::ordered_cycle_counter();
                                scheduler()
                                    .migrate_task_domain(responder.task_id(), binding)
                                    .unwrap();
                                let end = platform::ordered_cycle_counter();
                                if sample >= 32 && cpu == platform::current_cpu_id() && end >= start
                                {
                                    migration.push(end - start);
                                }
                            }
                            let cpu = platform::current_cpu_id();
                            let target = responder.target_cpu();
                            let idle = target != cpu && scheduler().cpu_is_idle(target);
                            initiator_pair.request.store(sample + 1, Ordering::Release);
                            let start = platform::ordered_cycle_counter();
                            scheduler().unpark(responder);
                            let unpark_end = platform::ordered_cycle_counter();
                            let unpark_cpu = platform::current_cpu_id();
                            while initiator_pair.completed.load(Ordering::Acquire) != sample + 1 {
                                scheduler().park_current();
                            }
                            let end = platform::ordered_cycle_counter();
                            if sample < 32 {
                                continue;
                            }
                            if unpark_cpu == cpu && unpark_end >= start {
                                unpark.push(unpark_end - start);
                            }
                            if platform::current_cpu_id() != cpu || end < start {
                                moved += 1;
                                continue;
                            }
                            if initiator_pair.responder_cpu.load(Ordering::Relaxed) == cpu {
                                local.push(end - start);
                            } else {
                                remote.push(end - start);
                                if idle
                                    && initiator_pair.responder_cpu.load(Ordering::Relaxed)
                                        == target
                                {
                                    idle_remote.push(end - start);
                                }
                            }
                        }
                        initiator_pair.stop.store(true, Ordering::Release);
                        scheduler().unpark(responder);
                        finished
                            .send((local, remote, idle_remote, unpark, migration, moved))
                            .ok()
                            .unwrap();
                    },
                    kernel_task_sched_binding(),
                );
                pair.tasks
                    .call_once(|| [initiator.clone(), responder.clone()]);
                let mut tasks = vec![initiator.clone(), responder.clone()];
                if mode == 2 {
                    let pair = pair.clone();
                    let busy = thread(
                        move || {
                            let deadline = platform::ordered_cycle_counter() + 30 * hz;
                            let mut value = 0u64;
                            while !pair.stop.load(Ordering::Acquire) {
                                for _ in 0..256 {
                                    value = black_box(value.rotate_left(7).wrapping_add(1));
                                }
                                assert!(
                                    platform::ordered_cycle_counter() < deadline,
                                    "busy wake workload timed out"
                                );
                            }
                        },
                        kernel_task_sched_binding(),
                    );
                    scheduler().add_task_on(busy.clone(), Some(1));
                    tasks.push(busy);
                }
                scheduler()
                    .add_task_on(responder, Some(if mode == 1 || mode == 2 { 1 } else { 0 }));
                scheduler().add_task_on(initiator, Some(0));
                let (mut local, mut remote, mut idle, mut unpark, mut migration, moved) =
                    rx.recv().unwrap();
                drop(pair);
                retire(tasks);
                if trial == 0 {
                    continue;
                }
                distribution(handle, "round_trip.observed-local", &mut local);
                distribution(handle, "round_trip.observed-remote", &mut remote);
                distribution(handle, "round_trip.observed-idle-remote", &mut idle);
                distribution(handle, "unpark_call", &mut unpark);
                if mode == 5 {
                    distribution(handle, "blocked_migration_call", &mut migration);
                }
                bench_measure(
                    handle,
                    "round_trip.discarded_cpu_change".into(),
                    moved as f64,
                    BenchMetricUnit::Count,
                    BenchMetricDirection::Informational,
                );
            }
            bench_case_end(handle);
        }

        for mode in [0, 1] {
            if !bench_case_start(
                handle,
                if mode == 0 {
                    "permit.already-running"
                } else {
                    "migration.running"
                }
                .into(),
            ) {
                return BenchSuiteStatus::Failed;
            }
            for trial in 0..=TRIALS {
                let (finished, rx) = bounded_mpmc_channel(1, 1);
                let task = thread(
                    move || {
                        let current = scheduler().get_local_current_task().unwrap();
                        let mut calls = Vec::with_capacity(SAMPLES);
                        let mut completion = Vec::with_capacity(SAMPLES);
                        let mut redundant = Vec::with_capacity(SAMPLES);
                        for sample in 0..32 + SAMPLES {
                            let binding = TaskSchedBinding::new(
                                if sample % 2 == 0 {
                                    USER_DOMAIN_ID
                                } else {
                                    KERNEL_DOMAIN_ID
                                },
                                FifoTaskState::new(FifoPriority::Normal),
                            );
                            let destination = binding.domain_id();
                            let cpu = platform::current_cpu_id();
                            let start = platform::ordered_cycle_counter();
                            if mode == 0 {
                                scheduler().unpark(&current);
                            } else {
                                scheduler()
                                    .migrate_task_domain(current.task_id(), binding)
                                    .unwrap();
                            }
                            let requested = platform::ordered_cycle_counter();
                            let request_cpu = platform::current_cpu_id();
                            if mode == 0 {
                                for _ in 0..8 {
                                    scheduler().unpark(&current);
                                }
                            }
                            let duplicated = platform::ordered_cycle_counter();
                            let duplicate_cpu = platform::current_cpu_id();
                            if mode == 0 {
                                scheduler().park_current();
                            } else {
                                let deadline = start + 10 * hz;
                                while current.domain_id() != destination {
                                    assert!(
                                        platform::ordered_cycle_counter() < deadline,
                                        "domain migration did not finish"
                                    );
                                    yield_now();
                                }
                            }
                            let end = platform::ordered_cycle_counter();
                            if sample >= 32
                                && platform::current_cpu_id() == cpu
                                && end >= duplicated
                                && duplicated >= requested
                                && requested >= start
                            {
                                if request_cpu == cpu {
                                    calls.push(requested - start);
                                }
                                if duplicate_cpu == cpu {
                                    completion.push(if mode == 0 {
                                        end - duplicated
                                    } else {
                                        end - start
                                    });
                                    if mode == 0 && request_cpu == cpu {
                                        redundant.push((duplicated - requested) / 8);
                                    }
                                }
                            }
                        }
                        finished.send((calls, completion, redundant)).ok().unwrap();
                    },
                    kernel_task_sched_binding(),
                );
                scheduler().add_task(task.clone());
                let (mut calls, mut completion, mut redundant) = rx.recv().unwrap();
                retire(vec![task]);
                if trial != 0 {
                    distribution(handle, "request_call", &mut calls);
                    distribution(
                        handle,
                        if mode == 0 {
                            "park_with_permit"
                        } else {
                            "request_to_active_domain"
                        },
                        &mut completion,
                    );
                    if mode == 0 {
                        distribution(handle, "redundant_unpark_per_call", &mut redundant);
                    }
                }
            }
            bench_case_end(handle);
        }

        for producers in [1, cpus.max(2), (cpus * 4).clamp(4, 256)] {
            if !bench_case_start(
                handle,
                alloc::format!("wake-contention.{producers}-producers"),
            ) {
                return BenchSuiteStatus::Failed;
            }
            for trial in 0..=TRIALS {
                let stop = Arc::new(AtomicBool::new(false));
                let open = Arc::new(AtomicBool::new(false));
                let (resumed, resumed_rx) = bounded_mpmc_channel(1, 1);
                let target_stop = stop.clone();
                let target = thread(
                    move || {
                        let mut resumes = 0;
                        while !target_stop.load(Ordering::Acquire) {
                            scheduler().park_current();
                            resumes += 1;
                        }
                        resumed.send(resumes).unwrap();
                    },
                    kernel_task_sched_binding(),
                );
                scheduler().add_task_on(target.clone(), Some(0));
                let (ready, ready_rx) = bounded_mpmc_channel(producers, 1);
                let (finished, rx) = bounded_mpmc_channel(producers, 1);
                let mut tasks = vec![target.clone()];
                for index in 0..producers {
                    let target = target.clone();
                    let open = open.clone();
                    let ready = ready.clone();
                    let finished = finished.clone();
                    let task = thread(
                        move || {
                            let mut costs = Vec::with_capacity(SAMPLES * 4);
                            ready.send(()).unwrap();
                            while !open.load(Ordering::Acquire) {
                                scheduler().park_current();
                            }
                            for _ in 0..SAMPLES * 4 {
                                let cpu = platform::current_cpu_id();
                                let start = platform::ordered_cycle_counter();
                                scheduler().unpark(&target);
                                let end = platform::ordered_cycle_counter();
                                if cpu == platform::current_cpu_id() && end >= start {
                                    costs.push(end - start);
                                }
                            }
                            finished.send(costs).ok().unwrap();
                        },
                        kernel_task_sched_binding(),
                    );
                    scheduler().add_task_on(task.clone(), Some(index % cpus));
                    tasks.push(task);
                }
                drop(ready);
                drop(finished);
                for _ in 0..producers {
                    ready_rx.recv().unwrap();
                }
                let start = platform::ordered_cycle_counter();
                open.store(true, Ordering::Release);
                for task in &tasks[1..] {
                    scheduler().unpark(task);
                }
                let mut costs: Vec<_> = (0..producers).flat_map(|_| rx.recv().unwrap()).collect();
                let elapsed = platform::ordered_cycle_counter().saturating_sub(start);
                stop.store(true, Ordering::Release);
                scheduler().unpark(&target);
                let resumes = resumed_rx.recv().unwrap();
                drop(target);
                retire(tasks);
                if trial != 0 {
                    distribution(handle, "unpark_call", &mut costs);
                    bench_measure(
                        handle,
                        "unpark_calls".into(),
                        (producers * SAMPLES * 4) as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    );
                    bench_measure(
                        handle,
                        "target_park_returns".into(),
                        resumes as f64,
                        BenchMetricUnit::Count,
                        BenchMetricDirection::Informational,
                    );
                    bench_measure(
                        handle,
                        "batch_wall".into(),
                        elapsed as f64 * 1e9 / hz as f64,
                        BenchMetricUnit::Nanoseconds,
                        BenchMetricDirection::LowerIsBetter,
                    );
                }
            }
            bench_case_end(handle);
        }
        BenchSuiteStatus::Passed
    }
    .into_abi()
}
