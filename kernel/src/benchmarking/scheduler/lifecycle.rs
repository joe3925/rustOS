use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteStatus},
};

use crate::{
    benchmarking::{bench_case_end, bench_case_start, bench_measure},
    memory::paging::stack::StackSize,
    platform,
    scheduling::{
        runtime::runtime::yield_now,
        scheduler::{kernel_task_sched_binding, scheduler},
        state::SchedState,
        task::Task,
    },
    sync_platform::bounded_mpmc_channel,
};

use super::{TRIALS, clock_cost, distribution, entry, retire, thread};

pub(crate) extern "C" fn suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        clock_cost(handle);
        let hz = platform::cycle_counter_frequency_hz();
        let cpus = platform::processor_count();
        let mut cases = [
            ("serial.stack-4k", 1, StackSize::Tiny, false),
            ("serial.stack-64k", 1, StackSize::Large, false),
            ("batch.32", 32, StackSize::Tiny, false),
            ("batch.256", 256, StackSize::Tiny, false),
            ("wake-fanout.8", 8, StackSize::Small, true),
            ("wake-fanout.64", 64, StackSize::Small, true),
            ("wake-fanout.256", 256, StackSize::Small, true),
        ];
        let repetition = super::super::boot_state::current_repetition().await;
        let count = cases.len();
        cases.rotate_left(repetition.saturating_sub(1) as usize % count);
        for (name, count, stack, fanout) in cases {
            if !bench_case_start(handle, name.into()) {
                return BenchSuiteStatus::Failed;
            }
            for trial in 0..=TRIALS {
                let mut construction = Vec::with_capacity(count.max(64));
                let mut admission = Vec::with_capacity(count.max(64));
                let mut first_dispatch = Vec::with_capacity(count.max(64));
                let mut completion = Vec::with_capacity(64);
                let mut retirement = Vec::with_capacity(64);
                let mut cpu_starts = vec![0usize; cpus];
                for _ in 0..if count == 1 { 64 } else { 1 } {
                    let open = Arc::new(AtomicBool::new(false));
                    let (ready, ready_rx) = bounded_mpmc_channel(count, 1);
                    let (finished, rx) = bounded_mpmc_channel(count, 1);
                    let mut tasks = Vec::with_capacity(count);
                    for index in 0..count {
                        let finished = finished.clone();
                        let ready = ready.clone();
                        let open = open.clone();
                        let work = move || {
                            if fanout {
                                ready.send(()).unwrap();
                                while !open.load(Ordering::Acquire) {
                                    scheduler().park_current();
                                }
                            }
                            let first = platform::ordered_cycle_counter();
                            let cpu = platform::current_cpu_id();
                            finished.send((first, cpu, index)).unwrap();
                        };
                        if fanout {
                            let task = thread(work, kernel_task_sched_binding());
                            scheduler().add_task_on(task.clone(), Some(index % cpus));
                            tasks.push(task);
                        } else {
                            let work: Box<dyn FnOnce() + Send> = Box::new(work);
                            let context = Box::into_raw(Box::new(work)) as usize;
                            let name = "scheduler-lifecycle".into();
                            let cpu = platform::current_cpu_id();
                            let start = platform::ordered_cycle_counter();
                            let task = Task::new_kernel_mode(entry, context, stack, name, 0);
                            let end = platform::ordered_cycle_counter();
                            if platform::current_cpu_id() == cpu && end >= start {
                                construction.push(end - start);
                            }
                            tasks.push(task);
                        }
                    }
                    drop(ready);
                    drop(finished);
                    if fanout {
                        for _ in 0..count {
                            ready_rx.recv().unwrap();
                        }
                        let deadline = platform::ordered_cycle_counter() + 10 * hz;
                        while tasks
                            .iter()
                            .any(|task| task.sched_state() != SchedState::Blocked)
                        {
                            assert!(
                                platform::ordered_cycle_counter() < deadline,
                                "fanout threads did not block"
                            );
                            yield_now();
                        }
                    }
                    let mut submitted = vec![(0, 0); count];
                    let cpu = platform::current_cpu_id();
                    let start = platform::ordered_cycle_counter();
                    open.store(true, Ordering::Release);
                    for (index, task) in tasks.iter().enumerate() {
                        let submit_cpu = platform::current_cpu_id();
                        let submit = platform::ordered_cycle_counter();
                        if fanout {
                            scheduler().unpark(task);
                        } else {
                            scheduler().add_task(task.clone());
                        }
                        let end = platform::ordered_cycle_counter();
                        if submit_cpu == platform::current_cpu_id() && end >= submit {
                            admission.push(end - submit);
                        }
                        submitted[index] = (submit, submit_cpu);
                    }
                    for _ in 0..count {
                        let (first, first_cpu, index) = rx.recv().unwrap();
                        cpu_starts[first_cpu] += 1;
                        let (submitted, submit_cpu) = submitted[index];
                        if first_cpu == submit_cpu && first >= submitted {
                            first_dispatch.push(first - submitted);
                        }
                    }
                    let end = platform::ordered_cycle_counter();
                    if platform::current_cpu_id() == cpu && end >= start {
                        completion.push(end - start);
                    }
                    let cpu = platform::current_cpu_id();
                    let start = platform::ordered_cycle_counter();
                    retire(tasks);
                    let end = platform::ordered_cycle_counter();
                    if platform::current_cpu_id() == cpu && end >= start {
                        retirement.push(end - start);
                    }
                }
                if trial == 0 {
                    continue;
                }
                if !fanout {
                    distribution(handle, "task_construction", &mut construction);
                }
                distribution(
                    handle,
                    if fanout {
                        "unpark_call"
                    } else {
                        "add_task_call"
                    },
                    &mut admission,
                );
                distribution(handle, "submit_to_entry.same-cpu", &mut first_dispatch);
                distribution(handle, "submit_batch_to_receipts", &mut completion);
                distribution(handle, "receipts_to_retire_and_reap_call", &mut retirement);
                bench_measure(
                    handle,
                    "tasks_per_batch".into(),
                    count as f64,
                    BenchMetricUnit::Count,
                    BenchMetricDirection::Informational,
                );
                bench_measure(
                    handle,
                    "stack_bytes_per_task".into(),
                    stack.as_bytes() as f64,
                    BenchMetricUnit::Bytes,
                    BenchMetricDirection::Informational,
                );
                for (cpu, starts) in cpu_starts.into_iter().enumerate() {
                    bench_measure(
                        handle,
                        alloc::format!("entries.cpu{cpu}"),
                        starts as f64,
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
