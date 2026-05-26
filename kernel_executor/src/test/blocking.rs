use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::runtime::runtime::{block_on, spawn, spawn_blocking, spawn_blocking_many, JoinAll};

struct DropMarker {
    drops: Arc<AtomicUsize>,
}

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

// This test exists to cover the basic blocking API contract on the threaded
// host platform: one closure is submitted to the blocking pool and its result is
// consumed exactly once through BlockingJoin.
#[test]
fn spawn_blocking_runs_job_and_join_consumes_result() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let join = spawn_blocking(|| 21usize * 2);
    assert_eq!(block_on(join), 42);
}

// This test exists to stress spawn_blocking_many with many queued closures. It
// verifies that parallel execution does not change the public join/result order.
#[test]
fn spawn_blocking_many_preserves_join_order_under_thread_pool_load() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let count = super::stress_task_count(256);
    let funcs: Vec<_> = (0..count)
        .map(|i| {
            move || {
                std::thread::yield_now();
                i.wrapping_mul(3)
            }
        })
        .collect();

    let joins = spawn_blocking_many(funcs);
    let results: Vec<_> = joins.into_iter().map(block_on).collect();

    assert_eq!(results.len(), count);
    for (i, value) in results.into_iter().enumerate() {
        assert_eq!(value, i.wrapping_mul(3));
    }
}

// This test exists to exercise mixed runtime and blocking work. Runtime tasks
// await blocking joins while other runtime tasks continue to wake, requeue, and
// complete through JoinAll.
#[test]
fn runtime_tasks_can_await_blocking_work_under_load() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let count = super::stress_task_count(128);
    let results = block_on(async {
        let handles = (0..count)
            .map(|i| {
                spawn(async move {
                    let blocking = spawn_blocking(move || {
                        std::thread::yield_now();
                        i + 1
                    });
                    blocking.await * 2
                })
            })
            .collect();
        JoinAll::new(handles).await
    });

    assert_eq!(results.len(), count);
    for (i, value) in results.into_iter().enumerate() {
        assert_eq!(value, (i + 1) * 2);
    }
}

// This test exists to cover dropping BlockingJoin before the worker produces a
// result. The task should still run, and the unconsumed result must be dropped
// when the shared blocking task is released.
#[test]
fn dropping_blocking_join_before_completion_does_not_leak_result() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let drops = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));

    let join = {
        let drops = drops.clone();
        let started = started.clone();
        spawn_blocking(move || {
            started.fetch_add(1, Ordering::AcqRel);
            for _ in 0..256 {
                std::thread::yield_now();
            }
            DropMarker { drops }
        })
    };

    drop(join);

    super::wait_until(Duration::from_secs(10), || {
        started.load(Ordering::Acquire) == 1 && drops.load(Ordering::Acquire) == 1
    });
}
