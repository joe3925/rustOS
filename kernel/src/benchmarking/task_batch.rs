use alloc::{sync::Arc, vec::Vec};
use core::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use kernel_executor::runtime::runtime::spawn_detached;
use spin::Mutex;

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

#[repr(align(64))]
struct AlignedAtomicUsize(AtomicUsize);

struct TaskBatch {
    results: Vec<AtomicU64>,
    completed_per_cpu: Vec<AlignedAtomicUsize>,
    waiters: Vec<Mutex<Option<Waker>>>,
}

pub(super) struct TaskBatchResult {
    pub(super) checksum: u64,
    pub(super) cpu_tasks: Vec<usize>,
}

pub(super) async fn run_task_batch(
    task_count: usize,
    operation: fn(u64) -> u64,
) -> TaskBatchResult {
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
