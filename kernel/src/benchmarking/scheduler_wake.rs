use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::{
    future::{Future, poll_fn},
    pin::pin,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering},
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
use spin::Once;

use crate::{
    idt::interrupt_impl::{bind_msi_interrupt, irq_handle_unregister, irq_wait_future},
    memory::paging::stack::StackSize,
    platform,
    scheduling::{
        runtime::runtime::KernelExecutorPlatform,
        scheduler::scheduler,
        task::{Task, TaskHandle},
    },
    structs::stopwatch::Stopwatch,
};

use super::{bench_case_end, bench_case_start, bench_measure, task_batch::yield_once};

const WARMUP: usize = 32;
const SAMPLES: usize = 256;

pub(crate) static TRIGGER: AtomicPtr<Sample> = AtomicPtr::new(core::ptr::null_mut());
pub(crate) static ORDER_TASK: AtomicU64 = AtomicU64::new(0);
pub(crate) static ORDER_SELECTED: AtomicBool = AtomicBool::new(false);
pub(crate) static ACTIVE_SIGNAL: [AtomicPtr<Sample>; platform::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; platform::MAX_CPUS];

#[repr(align(64))]
pub(crate) struct Sample {
    pub(crate) mode: usize,
    pub(crate) requested: AtomicU64,
    pub(crate) finished: AtomicU64,
    pub(crate) deadline: AtomicU64,
    pub(crate) target: AtomicUsize,
    pub(crate) vector: AtomicUsize,
    pub(crate) nested_completed: AtomicBool,
    pub(crate) signal_calls: AtomicUsize,
    pub(crate) signal_task: AtomicU64,
    pub(crate) signal_cpu: AtomicUsize,
    pub(crate) signal_state: AtomicUsize,
    poll_task: AtomicU64,
    started: AtomicU64,
    signaled: AtomicU64,
    resumed: AtomicU64,
    irq_cpu: AtomicUsize,
    waiter_cpu: AtomicUsize,
    order_context: AtomicUsize,
    older_completed_at_resume: AtomicBool,
}

struct Run {
    samples: Vec<Sample>,
    sequence: Vec<AtomicUsize>,
    ready: AtomicBool,
    older: Once<TaskHandle>,
    older_ready: AtomicBool,
    older_completed: AtomicUsize,
    stop: AtomicBool,
    older_exited: AtomicBool,
}

extern "C" fn interrupt(
    _: u32,
    cpu: u32,
    _: &mut IrqFrame,
    handle: IrqBorrowedHandle,
    context: usize,
) -> bool {
    let started = platform::ordered_cycle_counter();
    let run = unsafe { &*(context as *const Run) };
    let index = run.sequence[cpu as usize].load(Ordering::Acquire);
    let sample = &run.samples[index];
    sample.started.store(started, Ordering::Relaxed);
    sample.irq_cpu.store(cpu as usize, Ordering::Relaxed);
    if sample.mode == 5 {
        ORDER_SELECTED.store(false, Ordering::Release);
        sample.order_context.store(
            run.older.get().unwrap().sched_state() as usize
                | (usize::from(scheduler().cpu_is_idle(cpu as usize)) << 8),
            Ordering::Relaxed,
        );
        scheduler().unpark(run.older.get().unwrap());
    }
    let signaled = platform::ordered_cycle_counter();
    if sample.mode != 0 {
        ACTIVE_SIGNAL[cpu as usize].store(core::ptr::from_ref(sample).cast_mut(), Ordering::Relaxed);
        unsafe { &*handle }.signal_one(IrqMeta::with_tag(index as u64));
        ACTIVE_SIGNAL[cpu as usize].store(core::ptr::null_mut(), Ordering::Relaxed);
    }
    if sample.mode == 6 {
        platform::enable_interrupts();
    }
    sample.signaled.store(signaled, Ordering::Relaxed);
    sample
        .finished
        .store(platform::ordered_cycle_counter(), Ordering::Release);
    true
}

extern "C" fn older_thread(context: usize) {
    let run = unsafe { Arc::from_raw(context as *const Run) };
    run.older_ready.store(true, Ordering::Release);
    loop {
        scheduler().park_current();
        if run.stop.load(Ordering::Acquire) {
            break;
        }
        let index = run.sequence[0].load(Ordering::Acquire);
        run.older_completed.store(index + 1, Ordering::Release);
    }
    run.older_exited.store(true, Ordering::Release);
}

pub(super) extern "C" fn suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        let cpus = platform::processor_count();
        let targets: Vec<_> = (0..cpus).map(|cpu| {
            *crate::structs::per_cpu::percpu_by_id(cpu).unwrap().platform_cpu_id.get().unwrap()
        }).collect();
        let mut cases = [
            ("no_wake", 0),
            ("active_waiter", 1),
            ("parked_waiter", 2),
            ("nested_waiter", 3),
            ("nested_scheduler_locked", 4),
            ("normal_queue_order", 5),
            ("enabled_irq_return", 6),
        ];
        let repetition = super::boot_state::current_repetition().await;
        let case_count = cases.len();
        cases.rotate_left(repetition.saturating_sub(1) as usize % case_count);
        for (case, mode) in cases {
            if !bench_case_start(handle, case.to_string()) {
                return BenchSuiteStatus::Failed;
            }
            let run = Arc::new(Run {
                samples: (0..WARMUP + SAMPLES).map(|_| Sample {
                    mode,
                    requested: AtomicU64::new(0),
                    started: AtomicU64::new(0),
                    signaled: AtomicU64::new(0),
                    finished: AtomicU64::new(0),
                    resumed: AtomicU64::new(0),
                    deadline: AtomicU64::new(0),
                    target: AtomicUsize::new(0),
                    vector: AtomicUsize::new(0),
                    nested_completed: AtomicBool::new(false),
                    signal_calls: AtomicUsize::new(0),
                    signal_task: AtomicU64::new(0),
                    signal_cpu: AtomicUsize::new(usize::MAX),
                    signal_state: AtomicUsize::new(usize::MAX),
                    poll_task: AtomicU64::new(0),
                    irq_cpu: AtomicUsize::new(0),
                    waiter_cpu: AtomicUsize::new(0),
                    order_context: AtomicUsize::new(0),
                    older_completed_at_resume: AtomicBool::new(false),
                }).collect(),
                sequence: (0..cpus).map(|_| AtomicUsize::new(usize::MAX)).collect(),
                ready: AtomicBool::new(false),
                older: Once::new(),
                older_ready: AtomicBool::new(false),
                older_completed: AtomicUsize::new(0),
                stop: AtomicBool::new(false),
                older_exited: AtomicBool::new(false),
            });
            let binding = bind_msi_interrupt(
                &MsiBindingRequest::new(MsiRequest::new(MsiTarget::any(), MSI_KIND_MSI, 0), MsiRequester::none(), None),
                interrupt, Arc::as_ptr(&run) as usize,
            ).expect("cannot allocate scheduler benchmark interrupt");
            let vector = binding.message.data as u8;
            if mode == 5 {
                let task = Task::new_kernel_mode(
                    older_thread, Arc::into_raw(run.clone()) as usize, StackSize::Tiny,
                    "scheduler_order_probe".into(), 0,
                );
                run.older.call_once(|| task.clone());
                scheduler().add_task_on(task, Some(0));
                ORDER_TASK.store(run.older.get().unwrap().task_id(), Ordering::Release);
                while !run.older_ready.load(Ordering::Acquire) {
                    yield_once().await;
                }
            }
            let mut order_checks = 0;
            for index in 0..WARMUP + SAMPLES {
                run.ready.store(false, Ordering::Relaxed);
                let join = if mode == 0 { None } else {
                    let run = run.clone();
                    let irq = binding.handle;
                    Some(spawn_join_owned::<KernelExecutorPlatform, _, _>(async move {
                        let mut future = pin!(irq_wait_future(&irq));
                        let mut registered = false;
                        let result = poll_fn(|cx| {
                            let result = future.as_mut().poll(cx);
                            if result.is_pending() && !registered {
                                registered = true;
                                run.ready.store(true, Ordering::Release);
                            }
                            result
                        }).await;
                        let resumed = platform::ordered_cycle_counter();
                        assert!(registered && result.is_ok() && result.count == 1 && result.meta.tag == index as u64);
                        let sample = &run.samples[index];
                        let cpu = platform::current_cpu_id();
                        sample.resumed.store(resumed, Ordering::Relaxed);
                        sample.waiter_cpu.store(cpu, Ordering::Relaxed);
                        sample.poll_task.store(scheduler().try_get_current_task(cpu).unwrap().task_id(), Ordering::Relaxed);
                        sample.older_completed_at_resume.store(run.older_completed.load(Ordering::Acquire) >= index + 1, Ordering::Relaxed);
                        if mode == 5 && cpus == 1 && sample.order_context.load(Ordering::Relaxed) == 0x103 {
                            assert!(ORDER_SELECTED.load(Ordering::Acquire), "IRQ pump bypassed older normal work: index={index}, completed={}, context={:#x}", run.older_completed.load(Ordering::Acquire), sample.order_context.load(Ordering::Relaxed));
                        }
                    }))
                };
                if mode != 0 {
                    while !run.ready.load(Ordering::Acquire) {
                        yield_once().await;
                    }
                }
                let cpu = if mode == 0 { platform::current_cpu_id() } else if mode >= 3 { 0 } else { index % cpus };
                run.sequence[cpu].store(index, Ordering::Release);
                let sample = &run.samples[index];
                if mode >= 2 {
                    sample.target.store(targets[cpu] as usize, Ordering::Relaxed);
                    sample.vector.store(vector as usize, Ordering::Relaxed);
                    sample.deadline.store(platform::ordered_cycle_counter() + platform::cycle_counter_frequency_hz() / 500, Ordering::Relaxed);
                    assert!(TRIGGER.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(sample).cast_mut(), Ordering::Release, Ordering::Relaxed).is_ok());
                } else {
                    sample.requested.store(platform::ordered_cycle_counter(), Ordering::Relaxed);
                    assert!(platform::send_ipi(targets[cpu], vector));
                }
                if let Some(join) = join {
                    assert!(matches!(join.await, TaskOutcome::Completed(())));
                } else {
                    let deadline = platform::ordered_cycle_counter() + platform::cycle_counter_frequency_hz();
                    while sample.finished.load(Ordering::Acquire) == 0 {
                        assert!(platform::ordered_cycle_counter() < deadline, "no-wake IRQ did not complete");
                        core::hint::spin_loop();
                    }
                    sample.resumed.store(platform::ordered_cycle_counter(), Ordering::Relaxed);
                    sample.waiter_cpu.store(platform::current_cpu_id(), Ordering::Relaxed);
                }
                while sample.finished.load(Ordering::Acquire) == 0 || ((mode == 3 || mode == 4) && !sample.nested_completed.load(Ordering::Acquire)) {
                    yield_once().await;
                }
                if mode == 5 {
                    while run.older_completed.load(Ordering::Acquire) < index + 1 {
                        yield_once().await;
                    }
                    order_checks += usize::from(cpus == 1 && sample.order_context.load(Ordering::Relaxed) == 0x103 && index >= WARMUP);
                }
            }
            assert!(TRIGGER.load(Ordering::Acquire).is_null());
            irq_handle_unregister(&binding.handle);
            if mode == 5 {
                ORDER_TASK.store(0, Ordering::Release);
                run.stop.store(true, Ordering::Release);
                scheduler().unpark(run.older.get().unwrap());
                while !run.older_exited.load(Ordering::Acquire) {
                    yield_once().await;
                }
            }
            for group in ["all", "local", "remote"] {
                let samples: Vec<_> = run.samples.iter().skip(WARMUP).filter(|sample| {
                    let matched = sample.signal_calls.load(Ordering::Relaxed) == 1
                        && sample.signal_state.load(Ordering::Relaxed) == crate::scheduling::state::SchedState::Blocked as usize
                        && sample.signal_task.load(Ordering::Relaxed) == sample.poll_task.load(Ordering::Relaxed);
                    let local = sample.irq_cpu.load(Ordering::Relaxed) == sample.signal_cpu.load(Ordering::Relaxed);
                    group == "all" || (matched && (group == "local") == local)
                }).collect();
                if samples.is_empty() { continue; }
                for metric in ["signal", "isr_resume", "request_resume", "irq_return"] {
                    let mut values: Vec<_> = samples.iter().map(|sample| {
                        let started = sample.started.load(Ordering::Relaxed);
                        let signaled = sample.signaled.load(Ordering::Relaxed);
                        let finished = sample.finished.load(Ordering::Relaxed);
                        let resumed = sample.resumed.load(Ordering::Relaxed);
                        let requested = sample.requested.load(Ordering::Relaxed);
                        assert!(finished >= signaled && signaled >= started && started >= requested && resumed >= started);
                        let cycles = match metric {
                            "signal" => finished - signaled,
                            "isr_resume" => resumed - started,
                            "request_resume" => resumed - requested,
                            _ => resumed.saturating_sub(finished),
                        };
                        Stopwatch::from_cycles(cycles).as_nanos() as u64
                    }).collect();
                    values.sort_unstable();
                    for (name, value) in [
                        ("p50", values[values.len() / 2]),
                        ("p95", values[(values.len() * 95).div_ceil(100) - 1]),
                        ("p99", values[(values.len() * 99).div_ceil(100) - 1]),
                    ] {
                        bench_measure(handle, alloc::format!("{group}_{metric}_{name}_ns"), value as f64, BenchMetricUnit::Nanoseconds, BenchMetricDirection::LowerIsBetter);
                    }
                }
                bench_measure(handle, alloc::format!("{group}_samples"), samples.len() as f64, BenchMetricUnit::Count, BenchMetricDirection::Informational);
            }
            bench_measure(handle, "normal_order_checks".into(), order_checks as f64, BenchMetricUnit::Count, BenchMetricDirection::Informational);
            bench_measure(handle, "normal_selection_before_completion".into(), run.samples.iter().skip(WARMUP).filter(|sample| sample.mode == 5 && cpus == 1 && sample.order_context.load(Ordering::Relaxed) == 0x103 && !sample.older_completed_at_resume.load(Ordering::Relaxed)).count() as f64, BenchMetricUnit::Count, BenchMetricDirection::Informational);
            bench_measure(handle, "nested_returns".into(), run.samples.iter().skip(WARMUP).filter(|sample| sample.nested_completed.load(Ordering::Relaxed)).count() as f64, BenchMetricUnit::Count, BenchMetricDirection::Informational);
            bench_case_end(handle);
        }
        BenchSuiteStatus::Passed
    }.into_abi()
}
