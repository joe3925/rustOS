use alloc::{sync::Arc, vec::Vec};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use std::sync::{Condvar, Mutex};
use std::task::Wake;
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

struct WakeSignal {
    wakes: AtomicUsize,
    lock: Mutex<()>,
    condvar: Condvar,
}

impl WakeSignal {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wakes: AtomicUsize::new(0),
            lock: Mutex::new(()),
            condvar: Condvar::new(),
        })
    }

    fn waker(self: &Arc<Self>) -> Waker {
        Waker::from(self.clone())
    }

    fn wake_count(&self) -> usize {
        self.wakes.load(Ordering::Acquire)
    }

    fn wait_for_wakes(&self, expected: usize, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = self.lock.lock().expect("blocking wake signal lock");

        while self.wake_count() < expected {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }

            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, result) = self
                .condvar
                .wait_timeout(guard, remaining)
                .expect("blocking wake signal condvar");
            guard = next_guard;

            if result.timed_out() && self.wake_count() < expected {
                return false;
            }
        }

        true
    }

    fn record_wake(&self) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
        self.condvar.notify_all();
    }
}

impl Wake for WakeSignal {
    fn wake(self: Arc<Self>) {
        self.record_wake();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.record_wake();
    }
}

fn poll_once<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    let mut cx = Context::from_waker(waker);
    Pin::new(future).poll(&mut cx)
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

// This test covers the wake contract for BlockingJoin directly. Once a blocking
// join returns Pending, worker completion must wake the registered waiter before
// the test polls the join again.
#[test]
fn blocking_join_pending_poll_wakes_registered_waiter_on_completion() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let release = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicUsize::new(0));
    let release_for_worker = release.clone();
    let started_for_worker = started.clone();
    let mut join = spawn_blocking(move || {
        started_for_worker.fetch_add(1, Ordering::AcqRel);
        while !release_for_worker.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        123usize
    });

    super::wait_until(Duration::from_secs(10), || {
        started.load(Ordering::Acquire) == 1
    });

    let waiter = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut join, &waiter.waker()),
        Poll::Pending
    ));

    release.store(true, Ordering::Release);
    assert!(
        waiter.wait_for_wakes(1, Duration::from_secs(10)),
        "BlockingJoin was not woken after worker completion"
    );
    assert!(matches!(
        poll_once(&mut join, &waiter.waker()),
        Poll::Ready(123)
    ));
}

// This test covers BlockingJoin waker replacement. A second pending poll with a
// different waker must replace the old waiter so completion wakes the active
// task rather than a stale one.
#[test]
fn blocking_join_completion_uses_latest_registered_waiter() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let release = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicUsize::new(0));
    let release_for_worker = release.clone();
    let started_for_worker = started.clone();
    let mut join = spawn_blocking(move || {
        started_for_worker.fetch_add(1, Ordering::AcqRel);
        while !release_for_worker.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        456usize
    });

    super::wait_until(Duration::from_secs(10), || {
        started.load(Ordering::Acquire) == 1
    });

    let stale_waiter = WakeSignal::new();
    let latest_waiter = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut join, &stale_waiter.waker()),
        Poll::Pending
    ));
    assert!(matches!(
        poll_once(&mut join, &latest_waiter.waker()),
        Poll::Pending
    ));

    release.store(true, Ordering::Release);
    assert!(
        latest_waiter.wait_for_wakes(1, Duration::from_secs(10)),
        "latest BlockingJoin waiter was not woken"
    );
    assert_eq!(
        stale_waiter.wake_count(),
        0,
        "stale BlockingJoin waiter was woken after replacement"
    );
    assert!(matches!(
        poll_once(&mut join, &latest_waiter.waker()),
        Poll::Ready(456)
    ));
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

// This test covers the explicit empty-input branch in spawn_blocking_many. It
// should allocate no joins and should not require any worker jobs to run.
#[test]
fn spawn_blocking_many_empty_returns_empty_join_list() {
    let joins = spawn_blocking_many(Vec::<fn() -> usize>::new());
    assert!(joins.is_empty());
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
