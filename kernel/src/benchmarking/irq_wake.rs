use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::{
    future::{Future, poll_fn},
    pin::pin,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use kernel_executor::runtime::runtime::{TaskOutcome, spawn_join_owned};
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteStatus},
    irq::{
        IrqBorrowedHandle, IrqFrame, IrqMeta, MSI_KIND_MSI, MsiBindingRequest, MsiRequest,
        MsiRequester, MsiTarget,
    },
};

use crate::{
    idt::interrupt_impl::{bind_msi_interrupt, irq_handle_unregister, irq_wait_future},
    platform,
    scheduling::runtime::runtime::KernelExecutorPlatform,
    structs::stopwatch::Stopwatch,
};

use super::{bench_case_end, bench_case_start, bench_measure, task_batch::yield_once};

const WARMUP: usize = 128;
const SAMPLES: usize = 1_024;
const BURST: usize = 32;

#[repr(align(64))]
struct Sample {
    requested: AtomicU64,
    started: AtomicU64,
    signaled: AtomicU64,
    finished: AtomicU64,
    resumed: AtomicU64,
    irq_cpu: AtomicUsize,
    waiter_cpu: AtomicUsize,
}

struct Run {
    samples: Vec<Sample>,
    sequence: Vec<AtomicUsize>,
    ready: AtomicUsize,
}

extern "C" fn interrupt(
    _: u32,
    cpu: u32,
    _: &mut IrqFrame,
    handle: IrqBorrowedHandle,
    ctx: usize,
) -> bool {
    let started = platform::ordered_cycle_counter();
    let run = unsafe { &*(ctx as *const Run) };
    let index = run.sequence[cpu as usize].load(Ordering::Acquire);
    let sample = &run.samples[index];
    sample.started.store(started, Ordering::Relaxed);
    sample.irq_cpu.store(cpu as usize, Ordering::Relaxed);
    let inner = unsafe { &*handle };
    let signaled = platform::ordered_cycle_counter();
    inner.signal_one(IrqMeta::with_tag(index as u64));
    let finished = platform::ordered_cycle_counter();
    sample.signaled.store(signaled, Ordering::Relaxed);
    sample.finished.store(finished, Ordering::Release);
    true
}

pub(super) extern "C" fn suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        let cpus = platform::processor_count();
        let targets: Vec<_> = (0..cpus)
            .map(|cpu| {
                let state = crate::structs::per_cpu::percpu_by_id(cpu).unwrap();
                (cpu, *state.platform_cpu_id.get().unwrap())
            })
            .collect();
        let mut cases = [("uncontended", 1), ("contended", BURST)];
        let repetition = super::boot_state::current_repetition().await;
        cases.rotate_left(repetition.saturating_sub(1) as usize % 2);

        for (case, waiters) in cases {
            if !bench_case_start(handle, case.to_string()) {
                return BenchSuiteStatus::Failed;
            }
            let run = Arc::new(Run {
                samples: (0..WARMUP + SAMPLES)
                    .map(|_| Sample {
                        requested: AtomicU64::new(0),
                        started: AtomicU64::new(0),
                        signaled: AtomicU64::new(0),
                        finished: AtomicU64::new(0),
                        resumed: AtomicU64::new(0),
                        irq_cpu: AtomicUsize::new(0),
                        waiter_cpu: AtomicUsize::new(0),
                    })
                    .collect(),
                sequence: (0..cpus).map(|_| AtomicUsize::new(usize::MAX)).collect(),
                ready: AtomicUsize::new(0),
            });
            let binding = bind_msi_interrupt(
                &MsiBindingRequest::new(
                    MsiRequest::new(MsiTarget::any(), MSI_KIND_MSI, 0),
                    MsiRequester::none(),
                    None,
                ),
                interrupt,
                Arc::as_ptr(&run) as usize,
            )
            .expect("cannot allocate benchmark interrupt");
            let vector = binding.message.data as u8;
            let mut joins = Vec::with_capacity(waiters);
            let mut target_cursor = 0;
            for base in (0..WARMUP + SAMPLES).step_by(waiters) {
                run.ready.store(0, Ordering::Relaxed);
                for _ in 0..waiters {
                    let run = run.clone();
                    let irq = binding.handle;
                    joins.push(spawn_join_owned::<KernelExecutorPlatform, _, _>(
                        async move {
                            let mut future = pin!(irq_wait_future(&irq));
                            let mut registered = false;
                            let result = poll_fn(|cx| {
                                let result = future.as_mut().poll(cx);
                                if result.is_pending() && !registered {
                                    registered = true;
                                    run.ready.fetch_add(1, Ordering::Release);
                                }
                                result
                            })
                            .await;
                            let resumed = platform::ordered_cycle_counter();
                            assert!(registered && result.is_ok() && result.count == 1);
                            assert!((base..base + waiters).contains(&(result.meta.tag as usize)));
                            let sample = &run.samples[result.meta.tag as usize];
                            assert_eq!(sample.resumed.swap(resumed, Ordering::Relaxed), 0);
                            sample
                                .waiter_cpu
                                .store(platform::current_cpu_id(), Ordering::Relaxed);
                        },
                    ));
                }
                while run.ready.load(Ordering::Acquire) != waiters {
                    yield_once().await;
                }
                for first in (base..base + waiters).step_by(cpus) {
                    let end = (first + cpus).min(base + waiters);
                    for index in first..end {
                        let (cpu, target) = targets[target_cursor % cpus];
                        target_cursor += 1;
                        run.sequence[cpu].store(index, Ordering::Release);
                        run.samples[index]
                            .requested
                            .store(platform::ordered_cycle_counter(), Ordering::Release);
                        assert!(platform::send_ipi(target, vector));
                    }
                    if waiters != 1 {
                        while run.samples[first..end]
                            .iter()
                            .any(|sample| sample.finished.load(Ordering::Acquire) == 0)
                        {
                            yield_once().await;
                        }
                    }
                }
                for join in joins.drain(..) {
                    assert!(matches!(join.await, TaskOutcome::Completed(())));
                }
                while run.samples[base..base + waiters]
                    .iter()
                    .any(|sample| sample.finished.load(Ordering::Acquire) == 0)
                {
                    yield_once().await;
                }
            }
            irq_handle_unregister(&binding.handle);

            let mut remote = 0;
            let mut overlaps = 0;
            let mut irq_counts = alloc::vec![0usize; cpus];
            let mut resume_counts = alloc::vec![0usize; cpus];
            for (index, sample) in run.samples.iter().enumerate().skip(WARMUP) {
                let requested = sample.requested.load(Ordering::Relaxed);
                let started = sample.started.load(Ordering::Relaxed);
                let signaled = sample.signaled.load(Ordering::Relaxed);
                let finished = sample.finished.load(Ordering::Relaxed);
                let resumed = sample.resumed.load(Ordering::Relaxed);
                assert!(started >= requested && finished >= started && resumed >= started);
                let irq_cpu = sample.irq_cpu.load(Ordering::Relaxed);
                let waiter_cpu = sample.waiter_cpu.load(Ordering::Relaxed);
                irq_counts[irq_cpu] += 1;
                resume_counts[waiter_cpu] += 1;
                remote += usize::from(irq_cpu != waiter_cpu);
                overlaps += usize::from(run.samples[WARMUP..].iter().enumerate().any(
                    |(other, peer)| {
                        other + WARMUP != index
                            && peer.signaled.load(Ordering::Relaxed) < finished
                            && peer.finished.load(Ordering::Relaxed) > signaled
                    },
                ));
                for (metric, cycles) in [
                    ("isr_to_resume", resumed - started),
                    ("signal_call", finished - signaled),
                    ("request_to_resume", resumed - requested),
                ] {
                    bench_measure(
                        handle,
                        metric.to_string(),
                        Stopwatch::from_cycles(cycles).as_nanos() as f64,
                        BenchMetricUnit::Nanoseconds,
                        BenchMetricDirection::LowerIsBetter,
                    );
                }
            }
            for (metric, value) in [
                ("registered_waiters", waiters),
                ("samples", SAMPLES),
                ("remote_resumes", remote),
                ("overlapping_signals", overlaps),
            ] {
                bench_measure(
                    handle,
                    metric.to_string(),
                    value as f64,
                    BenchMetricUnit::Count,
                    BenchMetricDirection::Informational,
                );
            }
            for _ in 0..128 {
                let started = platform::ordered_cycle_counter();
                let finished = platform::ordered_cycle_counter();
                bench_measure(
                    handle,
                    "counter_pair".to_string(),
                    Stopwatch::from_cycles(finished - started).as_nanos() as f64,
                    BenchMetricUnit::Nanoseconds,
                    BenchMetricDirection::Informational,
                );
            }
            for cpu in 0..cpus {
                for (name, value) in [
                    ("interrupts", irq_counts[cpu]),
                    ("resumes", resume_counts[cpu]),
                ] {
                    bench_measure(
                        handle,
                        alloc::format!("{name}.cpu{cpu}"),
                        value as f64,
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
