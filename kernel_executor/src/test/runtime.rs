use alloc::{sync::Arc, vec, vec::Vec};
use core::future::Future;
use core::mem::{align_of, size_of, ManuallyDrop};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::Duration;

use crate::global_async::GlobalAsyncExecutor;
use crate::runtime::ffi_spawn::kernel_spawn_ffi_internal;
use crate::runtime::runtime::{block_on, spawn, spawn_detached, JoinAll};
use crate::runtime::slab::{INLINE_FUTURE_ALIGN, INLINE_FUTURE_SIZE, JOINABLE_STORAGE_SIZE};
use kernel_types::async_ffi::FutureExt;

fn counting_waker(count: Arc<AtomicUsize>) -> Waker {
    unsafe fn clone(ptr: *const ()) -> RawWaker {
        let arc = ManuallyDrop::new(unsafe { Arc::from_raw(ptr as *const AtomicUsize) });
        let cloned = Arc::clone(&arc);
        RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
    }
    unsafe fn wake(ptr: *const ()) {
        let arc = unsafe { Arc::from_raw(ptr as *const AtomicUsize) };
        arc.fetch_add(1, Ordering::AcqRel);
    }
    unsafe fn wake_by_ref(ptr: *const ()) {
        let arc = ManuallyDrop::new(unsafe { Arc::from_raw(ptr as *const AtomicUsize) });
        arc.fetch_add(1, Ordering::AcqRel);
    }
    unsafe fn drop(ptr: *const ()) {
        unsafe { core::mem::drop(Arc::from_raw(ptr as *const AtomicUsize)) };
    }

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(count) as *const (), &VTABLE)) }
}

fn poll_once<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    let mut cx = Context::from_waker(waker);
    Pin::new(future).poll(&mut cx)
}

struct WakeOnce {
    polls: Arc<AtomicUsize>,
    value: usize,
}

impl Future for WakeOnce {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.polls.fetch_add(1, Ordering::AcqRel) == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(this.value)
        }
    }
}

struct YieldMany {
    remaining: usize,
    value: usize,
}

impl Future for YieldMany {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.remaining == 0 {
            Poll::Ready(this.value)
        } else {
            this.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct ExternalWakeFuture {
    started: bool,
    ready: Arc<AtomicBool>,
}

impl Future for ExternalWakeFuture {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.ready.load(Ordering::Acquire) {
            return Poll::Ready(1);
        }

        if !this.started {
            this.started = true;
            let ready = this.ready.clone();
            let waker = cx.waker().clone();
            std::thread::spawn(move || {
                ready.store(true, Ordering::Release);
                waker.wake();
            });
        }

        Poll::Pending
    }
}

struct LargeJoinFuture {
    _padding: [u8; JOINABLE_STORAGE_SIZE + 1],
    value: usize,
}

impl Future for LargeJoinFuture {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.value)
    }
}

#[repr(align(16))]
struct OverAlignedJoinFuture {
    value: usize,
}

impl Future for OverAlignedJoinFuture {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.value)
    }
}

struct LargeDetachedFuture {
    _padding: [u8; INLINE_FUTURE_SIZE + 1],
    counter: Arc<AtomicUsize>,
}

impl Future for LargeDetachedFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.counter.fetch_add(1, Ordering::AcqRel);
        Poll::Ready(())
    }
}

struct LargeCountingJoinFuture {
    _padding: [u8; JOINABLE_STORAGE_SIZE + 1],
    counter: Arc<AtomicUsize>,
    value: usize,
}

impl Future for LargeCountingJoinFuture {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.counter.fetch_add(1, Ordering::AcqRel);
        Poll::Ready(self.value)
    }
}

struct LargeResult([usize; 128]);

extern "win64" fn increment_counter(ctx: usize) {
    let counter = unsafe { &*(ctx as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::AcqRel);
}

// This test exists to keep the zero-scheduling fast path honest: a ready future
// should complete without requiring the platform or global executor to be initialized.
#[test]
fn block_on_returns_immediately_for_ready_future() {
    assert_eq!(block_on(async { 123usize }), 123);
}

// This test exists to cover JoinAll's local polling contract. It proves that a
// child wake causes the parent future to be polled again and preserves result order.
#[test]
fn join_all_polls_ready_queue_after_child_wakes_parent() {
    let polls = Arc::new(AtomicUsize::new(0));
    let wake_count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(wake_count.clone());
    let mut join_all = JoinAll::new(vec![
        WakeOnce {
            polls: polls.clone(),
            value: 10,
        },
        WakeOnce {
            polls: polls.clone(),
            value: 20,
        },
    ]);

    assert!(matches!(poll_once(&mut join_all, &waker), Poll::Pending));
    assert_eq!(polls.load(Ordering::Acquire), 2);
    assert!(wake_count.load(Ordering::Acquire) >= 1);

    match poll_once(&mut join_all, &waker) {
        Poll::Ready(values) => assert_eq!(values, Vec::from([10, 20])),
        Poll::Pending => panic!("JoinAll stayed pending after children woke it"),
    }
}

// This test exists to exercise JoinHandle storage selection under the real test
// thread pool: inline futures, oversized futures, oversized results, and
// over-aligned futures all have to complete through the same public spawn API.
#[test]
fn spawn_joinhandle_completes_inline_and_fallback_storage_paths() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    assert!(size_of::<LargeJoinFuture>() > JOINABLE_STORAGE_SIZE);
    assert!(size_of::<LargeResult>() > JOINABLE_STORAGE_SIZE);
    assert!(align_of::<OverAlignedJoinFuture>() > INLINE_FUTURE_ALIGN);

    let result = block_on(async {
        let inline = spawn(async { 11usize });
        let large_future = spawn(LargeJoinFuture {
            _padding: [0; JOINABLE_STORAGE_SIZE + 1],
            value: 22,
        });
        let large_result = spawn(async { LargeResult([33usize; 128]) });
        let over_aligned = spawn(OverAlignedJoinFuture { value: 44 });

        (
            inline.await,
            large_future.await,
            large_result.await,
            over_aligned.await,
        )
    });

    let (inline, large_future, large_result, over_aligned) = result;
    assert_eq!(inline, 11);
    assert_eq!(large_future, 22);
    assert_eq!(large_result.0[0], 33);
    assert_eq!(large_result.0[127], 33);
    assert_eq!(over_aligned, 44);
}

// This test exists to stress runtime scheduling across all configured shards.
// Every task yields several times, forcing wake-by-ref, requeue, JoinHandle, and
// JoinAll paths to cooperate while many tasks are in flight.
#[test]
fn many_joinable_tasks_reschedule_across_core_count_shards() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let tasks = super::stress_task_count(256);
    let expected = tasks * (tasks - 1) / 2;

    let results = block_on(async {
        let handles = (0..tasks)
            .map(|i| {
                spawn(YieldMany {
                    remaining: i % 5,
                    value: i,
                })
            })
            .collect();
        JoinAll::new(handles).await
    });

    assert_eq!(results.len(), tasks);
    assert_eq!(results.into_iter().sum::<usize>(), expected);
}

// This test exists to cover detached work on both slab-inline and Arc fallback
// storage. Detached tasks have no JoinHandle, so completion is observed through
// shared state instead.
#[test]
fn spawn_detached_runs_inline_and_large_fallback_futures() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    assert!(size_of::<LargeDetachedFuture>() > INLINE_FUTURE_SIZE);

    let counter = Arc::new(AtomicUsize::new(0));
    let inline_tasks = super::stress_task_count(128);

    for _ in 0..inline_tasks {
        let counter = counter.clone();
        spawn_detached(async move {
            counter.fetch_add(1, Ordering::AcqRel);
        });
    }

    spawn_detached(LargeDetachedFuture {
        _padding: [0; INLINE_FUTURE_SIZE + 1],
        counter: counter.clone(),
    });

    super::wait_until(Duration::from_secs(10), || {
        counter.load(Ordering::Acquire) == inline_tasks + 1
    });
}

// This test exists to prove that dropping a JoinHandle does not cancel already
// queued work. It covers both the slab-backed small future and the fallback
// oversized future cleanup paths.
#[test]
fn dropping_joinhandles_does_not_cancel_queued_work() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let completed = Arc::new(AtomicUsize::new(0));

    let small_completed = completed.clone();
    let small = spawn(async move {
        small_completed.fetch_add(1, Ordering::AcqRel);
        1usize
    });

    let large = spawn(LargeCountingJoinFuture {
        _padding: [0; JOINABLE_STORAGE_SIZE + 1],
        counter: completed.clone(),
        value: 2,
    });

    drop(small);
    drop(large);

    super::wait_until(Duration::from_secs(10), || {
        completed.load(Ordering::Acquire) == 2
    });
}

// This test exists to cover the RawWaker path where a task is woken by a
// different host thread after returning Pending.
#[test]
fn externally_woken_future_is_rescheduled_by_executor_waker() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let value = block_on(async {
        spawn(ExternalWakeFuture {
            started: false,
            ready,
        })
        .await
    });

    assert_eq!(value, 1);
}

// This test exists to cover the FFI spawn entrypoint used by external crates.
// It verifies that an owned FfiFuture is accepted, scheduled as detached work,
// and driven to completion by the same executor backend.
#[test]
fn ffi_spawn_internal_runs_owned_ffi_future() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let completed = Arc::new(AtomicUsize::new(0));
    let completed_for_future = completed.clone();
    let future = async move {
        completed_for_future.fetch_add(1, Ordering::AcqRel);
    }
    .into_ffi();

    kernel_spawn_ffi_internal(future);

    super::wait_until(Duration::from_secs(10), || {
        completed.load(Ordering::Acquire) == 1
    });
}

// This test exists to hit GlobalAsyncExecutor directly, without going through
// spawn. It fills the sharded work queues with many raw jobs and verifies the
// configured core-count shard pump drains them all.
#[test]
fn raw_global_executor_jobs_drain_under_queue_pressure() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let jobs = super::stress_task_count(2_048);
    let counter = Arc::new(AtomicUsize::new(0));
    let ctx = Arc::as_ptr(&counter) as usize;

    for _ in 0..jobs {
        GlobalAsyncExecutor::global()
            .try_submit(increment_counter, ctx)
            .expect("raw global executor queue unexpectedly full");
    }

    super::wait_until(Duration::from_secs(10), || {
        counter.load(Ordering::Acquire) == jobs
    });
}
