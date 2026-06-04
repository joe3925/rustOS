use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::future::Future;
use core::mem::{align_of, size_of, ManuallyDrop};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::sync::{Condvar, Mutex};
use std::task::Wake;
use std::time::Duration;

use crate::global_async::{
    DomainClass, DomainConfig, DomainId, GlobalAsyncExecutor, KERNEL_NORMAL_DOMAIN,
    SimpleRoundRobinScheduler, SubmitErrorKind, WeightedDeficitRoundRobinScheduler,
};
use crate::runtime::ffi_spawn::kernel_spawn_ffi_internal;
use crate::runtime::runtime::{
    block_on, spawn, spawn_detached, spawn_detached_in_domain, spawn_in_domain, JoinAll,
};
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
        let mut guard = self.lock.lock().expect("wake signal lock");

        while self.wake_count() < expected {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }

            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, result) = self
                .condvar
                .wait_timeout(guard, remaining)
                .expect("wake signal condvar");
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

struct DropMarker {
    drops: Arc<AtomicUsize>,
}

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

struct ControlledFuture<T> {
    ready: Arc<AtomicBool>,
    child_waker: Arc<Mutex<Option<Waker>>>,
    completed: Arc<AtomicUsize>,
    value: Option<T>,
}

impl<T> Unpin for ControlledFuture<T> {}

impl<T> ControlledFuture<T> {
    fn new(
        ready: Arc<AtomicBool>,
        child_waker: Arc<Mutex<Option<Waker>>>,
        completed: Arc<AtomicUsize>,
        value: T,
    ) -> Self {
        Self {
            ready,
            child_waker,
            completed,
            value: Some(value),
        }
    }
}

impl<T> Future for ControlledFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.ready.load(Ordering::Acquire) {
            this.completed.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(this.value.take().expect("controlled future polled after ready"))
        } else {
            *this
                .child_waker
                .lock()
                .expect("controlled future waker lock") = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

struct LargeControlledFuture<T> {
    inner: ControlledFuture<T>,
    _padding: [u8; JOINABLE_STORAGE_SIZE + 1],
}

impl<T> Unpin for LargeControlledFuture<T> {}

impl<T> Future for LargeControlledFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll(cx)
    }
}

struct RecursiveSubmitState {
    remaining_submissions: AtomicUsize,
    completed: AtomicUsize,
}

extern "win64" fn increment_counter(ctx: usize) {
    let counter = unsafe { &*(ctx as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::AcqRel);
}

extern "win64" fn recursive_submit_counter(ctx: usize) {
    let state = unsafe { &*(ctx as *const RecursiveSubmitState) };
    state.completed.fetch_add(1, Ordering::AcqRel);

    let should_submit_more = state
        .remaining_submissions
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            (remaining > 0).then(|| remaining - 1)
        })
        .is_ok();

    if should_submit_more {
        GlobalAsyncExecutor::global().submit(recursive_submit_counter, ctx);
    }
}

fn take_child_waker(slot: &Arc<Mutex<Option<Waker>>>) -> Waker {
    slot.lock()
        .expect("controlled future waker lock")
        .take()
        .expect("controlled future did not register waker")
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

// This test exists to make the JoinHandle wake contract explicit for slab-backed
// tasks. After a handle returns Pending, the test waits for the registered waker
// instead of relying on block_on or JoinAll to poll in a loop.
#[test]
fn slab_joinhandle_pending_poll_wakes_registered_waiter_on_completion() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let mut handle = spawn(ControlledFuture::new(
        ready.clone(),
        child_waker.clone(),
        completed.clone(),
        77usize,
    ));

    let join_wake = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Pending
    ));

    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();

    assert!(
        join_wake.wait_for_wakes(1, Duration::from_secs(10)),
        "slab JoinHandle was not woken after its child completed"
    );
    assert_eq!(completed.load(Ordering::Acquire), 1);
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Ready(77)
    ));
}

// This test mirrors the slab wake contract on the Arc fallback path. It prevents
// the large-future path from depending on eager repolling by block_on/JoinAll.
#[test]
fn arc_fallback_joinhandle_pending_poll_wakes_registered_waiter_on_completion() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let future = LargeControlledFuture {
        inner: ControlledFuture::new(
            ready.clone(),
            child_waker.clone(),
            completed.clone(),
            88usize,
        ),
        _padding: [0; JOINABLE_STORAGE_SIZE + 1],
    };
    let mut handle = spawn(future);

    let join_wake = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Pending
    ));

    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();

    assert!(
        join_wake.wait_for_wakes(1, Duration::from_secs(10)),
        "Arc fallback JoinHandle was not woken after its child completed"
    );
    assert_eq!(completed.load(Ordering::Acquire), 1);
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Ready(88)
    ));
}

// This test protects waker replacement on slab-backed JoinHandles. If a pending
// handle is polled by a new task, completion must wake the newest waiter and not
// a stale waker left over from an earlier poll.
#[test]
fn slab_joinhandle_completion_uses_latest_registered_waiter() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let mut handle = spawn(ControlledFuture::new(
        ready.clone(),
        child_waker.clone(),
        completed,
        99usize,
    ));

    let stale_waiter = WakeSignal::new();
    let latest_waiter = WakeSignal::new();

    assert!(matches!(
        poll_once(&mut handle, &stale_waiter.waker()),
        Poll::Pending
    ));
    assert!(matches!(
        poll_once(&mut handle, &latest_waiter.waker()),
        Poll::Pending
    ));

    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();

    assert!(
        latest_waiter.wait_for_wakes(1, Duration::from_secs(10)),
        "latest JoinHandle waiter was not woken"
    );
    assert_eq!(
        stale_waiter.wake_count(),
        0,
        "stale JoinHandle waiter was woken after replacement"
    );
    assert!(matches!(
        poll_once(&mut handle, &latest_waiter.waker()),
        Poll::Ready(99)
    ));
}

// This test protects waker replacement on Arc fallback JoinHandles. The fallback
// JoinableTask path uses a different waker store than slab slots, so it needs the
// same stale-waiter check independently.
#[test]
fn arc_fallback_joinhandle_completion_uses_latest_registered_waiter() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let future = LargeControlledFuture {
        inner: ControlledFuture::new(
            ready.clone(),
            child_waker.clone(),
            completed,
            100usize,
        ),
        _padding: [0; JOINABLE_STORAGE_SIZE + 1],
    };
    let mut handle = spawn(future);

    let stale_waiter = WakeSignal::new();
    let latest_waiter = WakeSignal::new();

    assert!(matches!(
        poll_once(&mut handle, &stale_waiter.waker()),
        Poll::Pending
    ));
    assert!(matches!(
        poll_once(&mut handle, &latest_waiter.waker()),
        Poll::Pending
    ));

    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();

    assert!(
        latest_waiter.wait_for_wakes(1, Duration::from_secs(10)),
        "latest Arc fallback JoinHandle waiter was not woken"
    );
    assert_eq!(
        stale_waiter.wake_count(),
        0,
        "stale Arc fallback JoinHandle waiter was woken after replacement"
    );
    assert!(matches!(
        poll_once(&mut handle, &latest_waiter.waker()),
        Poll::Ready(100)
    ));
}

// This test covers the slab-backed completed-but-unawaited cleanup path. A task
// result stored in the slab must be dropped exactly once when its JoinHandle is
// dropped without consuming the result.
#[test]
fn dropping_completed_slab_joinhandle_drops_unconsumed_result_once() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut handle = spawn(ControlledFuture::new(
        ready.clone(),
        child_waker.clone(),
        completed.clone(),
        DropMarker {
            drops: drops.clone(),
        },
    ));

    let join_wake = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Pending
    ));
    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();
    assert!(
        join_wake.wait_for_wakes(1, Duration::from_secs(10)),
        "JoinHandle did not wake after storing an unconsumed result"
    );
    assert_eq!(completed.load(Ordering::Acquire), 1);

    drop(handle);

    super::wait_until(Duration::from_secs(10), || {
        drops.load(Ordering::Acquire) == 1
    });
}

// This test covers the slab-backed pending-then-dropped cleanup path. Dropping
// the JoinHandle must not cancel the task, and the later unconsumed result must
// still be dropped exactly once when the slot is released.
#[test]
fn dropping_pending_slab_joinhandle_drops_result_after_task_finishes() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut handle = spawn(ControlledFuture::new(
        ready.clone(),
        child_waker.clone(),
        completed.clone(),
        DropMarker {
            drops: drops.clone(),
        },
    ));

    let join_wake = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Pending
    ));
    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    drop(handle);
    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();

    super::wait_until(Duration::from_secs(10), || {
        completed.load(Ordering::Acquire) == 1 && drops.load(Ordering::Acquire) == 1
    });
}

// This test covers the Arc fallback completed-but-unawaited cleanup path. Large
// futures store their result in JoinableTask; dropping the unconsumed handle must
// still drop that result exactly once.
#[test]
fn dropping_completed_arc_fallback_joinhandle_drops_unconsumed_result_once() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let future = LargeControlledFuture {
        inner: ControlledFuture::new(
            ready.clone(),
            child_waker.clone(),
            completed.clone(),
            DropMarker {
                drops: drops.clone(),
            },
        ),
        _padding: [0; JOINABLE_STORAGE_SIZE + 1],
    };
    let mut handle = spawn(future);

    let join_wake = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Pending
    ));
    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();
    assert!(
        join_wake.wait_for_wakes(1, Duration::from_secs(10)),
        "Arc fallback JoinHandle did not wake after storing an unconsumed result"
    );
    assert_eq!(completed.load(Ordering::Acquire), 1);

    drop(handle);

    super::wait_until(Duration::from_secs(10), || {
        drops.load(Ordering::Acquire) == 1
    });
}

// This test covers the Arc fallback pending-then-dropped cleanup path. Dropping
// the JoinHandle must not cancel a large future, and its eventual result must be
// dropped when the task finishes with no waiter left.
#[test]
fn dropping_pending_arc_fallback_joinhandle_drops_result_after_task_finishes() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let ready = Arc::new(AtomicBool::new(false));
    let child_waker = Arc::new(Mutex::new(None));
    let completed = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let future = LargeControlledFuture {
        inner: ControlledFuture::new(
            ready.clone(),
            child_waker.clone(),
            completed.clone(),
            DropMarker {
                drops: drops.clone(),
            },
        ),
        _padding: [0; JOINABLE_STORAGE_SIZE + 1],
    };
    let mut handle = spawn(future);

    let join_wake = WakeSignal::new();
    assert!(matches!(
        poll_once(&mut handle, &join_wake.waker()),
        Poll::Pending
    ));
    super::wait_until(Duration::from_secs(10), || {
        child_waker
            .lock()
            .expect("controlled future waker lock")
            .is_some()
    });

    drop(handle);
    ready.store(true, Ordering::Release);
    take_child_waker(&child_waker).wake();

    super::wait_until(Duration::from_secs(10), || {
        completed.load(Ordering::Acquire) == 1 && drops.load(Ordering::Acquire) == 1
    });
}

// This test covers the slab JoinHandle double-poll guard. Once the result has
// been consumed, polling the same handle again is a caller bug and must panic
// instead of reading freed slot storage.
#[test]
#[should_panic(expected = "JoinHandle polled after completion")]
fn slab_joinhandle_panics_when_polled_after_completion() {
    let guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let mut handle = spawn(async { 5usize });
    assert_eq!(block_on(async { (&mut handle).await }), 5);
    drop(guard);

    let wake_count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(wake_count);
    let _ = poll_once(&mut handle, &waker);
}

// This test covers JoinAll's empty-input contract. An empty JoinAll should be
// immediately ready and should not wake its parent just to make progress.
#[test]
fn join_all_empty_is_ready_without_parent_wake() {
    let wake_count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(wake_count.clone());
    let mut join_all = JoinAll::new(Vec::<WakeOnce>::new());

    match poll_once(&mut join_all, &waker) {
        Poll::Ready(values) => assert!(values.is_empty()),
        Poll::Pending => panic!("empty JoinAll returned Pending"),
    }

    assert_eq!(wake_count.load(Ordering::Acquire), 0);
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

#[test]
fn compatibility_submit_routes_through_kernel_normal_domain() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let before = GlobalAsyncExecutor::global()
        .domain_stats(KERNEL_NORMAL_DOMAIN)
        .expect("kernel normal domain missing");
    let counter = Arc::new(AtomicUsize::new(0));
    let ctx = Arc::as_ptr(&counter) as usize;

    GlobalAsyncExecutor::global().submit(increment_counter, ctx);

    super::wait_until(Duration::from_secs(10), || {
        counter.load(Ordering::Acquire) == 1
    });

    let after = GlobalAsyncExecutor::global()
        .domain_stats(KERNEL_NORMAL_DOMAIN)
        .expect("kernel normal domain missing");
    assert!(after.submitted >= before.submitted + 1);
    assert!(after.completed >= before.completed + 1);
}

#[test]
fn submit_to_domain_executes_work_and_updates_domain_stats() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let jobs = super::stress_task_count(16);
    let counter = Arc::new(AtomicUsize::new(0));
    let ctx = Arc::as_ptr(&counter) as usize;
    let domain_id = GlobalAsyncExecutor::global().create_domain(DomainConfig {
        class: DomainClass::Driver,
        max_queued: jobs * 2,
        quantum: 2,
        ..DomainConfig::default()
    });

    for _ in 0..jobs {
        GlobalAsyncExecutor::global().submit_to_domain(domain_id, increment_counter, ctx);
    }

    super::wait_until(Duration::from_secs(10), || {
        counter.load(Ordering::Acquire) == jobs
    });

    let stats = GlobalAsyncExecutor::global()
        .domain_stats(domain_id)
        .expect("custom domain missing");
    assert_eq!(stats.class, DomainClass::Driver);
    assert!(stats.submitted >= jobs);
    assert!(stats.completed >= jobs);
    assert_eq!(stats.queued_count, 0);
}

#[test]
fn invalid_domain_submission_fails_without_panicking() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let counter = Arc::new(AtomicUsize::new(0));
    let invalid = DomainId::from_parts(0x00FF_FFFF, 1);
    let err = GlobalAsyncExecutor::global()
        .try_submit_to_domain(invalid, increment_counter, Arc::as_ptr(&counter) as usize)
        .expect_err("invalid domain unexpectedly accepted work");

    assert_eq!(err.kind, SubmitErrorKind::InvalidDomain);
    assert_eq!(counter.load(Ordering::Acquire), 0);
}

#[test]
fn spawn_in_domain_completes_joinhandle() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let domain_id = GlobalAsyncExecutor::global().create_domain(DomainConfig {
        class: DomainClass::KernelHigh,
        max_queued: 128,
        ..DomainConfig::default()
    });

    let value = block_on(async { spawn_in_domain(domain_id, async { 1234usize }).await });
    assert_eq!(value, 1234);

    super::wait_until(Duration::from_secs(10), || {
        GlobalAsyncExecutor::global()
            .domain_stats(domain_id)
            .is_some_and(|stats| stats.completed >= 1)
    });
}

#[test]
fn spawn_detached_in_domain_executes_work() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let domain_id = GlobalAsyncExecutor::global().create_domain(DomainConfig {
        class: DomainClass::KernelBackground,
        max_queued: 128,
        ..DomainConfig::default()
    });
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_task = counter.clone();

    spawn_detached_in_domain(domain_id, async move {
        counter_for_task.fetch_add(1, Ordering::AcqRel);
    });

    super::wait_until(Duration::from_secs(10), || {
        counter.load(Ordering::Acquire) == 1
    });

    super::wait_until(Duration::from_secs(10), || {
        GlobalAsyncExecutor::global()
            .domain_stats(domain_id)
            .is_some_and(|stats| stats.completed >= 1)
    });
}

#[test]
fn executor_runs_with_simple_round_robin_scheduler_policy() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    GlobalAsyncExecutor::global().replace_scheduler_for_tests(Box::new(
        SimpleRoundRobinScheduler::new(),
    ));

    let counter = Arc::new(AtomicUsize::new(0));
    let ctx = Arc::as_ptr(&counter) as usize;
    GlobalAsyncExecutor::global().submit(increment_counter, ctx);

    super::wait_until(Duration::from_secs(10), || {
        counter.load(Ordering::Acquire) == 1
    });

    GlobalAsyncExecutor::global().replace_scheduler_for_tests(Box::new(
        WeightedDeficitRoundRobinScheduler::new(),
    ));
}

// This test covers the global executor handoff where work is submitted by jobs
// that are already running on pump threads. Those recursive submissions must not
// be stranded when the current pump drains its local view of the queues.
#[test]
fn global_executor_drains_work_submitted_by_running_jobs() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let initial_jobs = super::stress_task_count(32);
    let recursive_jobs = super::stress_task_count(32);
    let expected = initial_jobs + recursive_jobs;
    let state = Arc::new(RecursiveSubmitState {
        remaining_submissions: AtomicUsize::new(recursive_jobs),
        completed: AtomicUsize::new(0),
    });
    let ctx = Arc::as_ptr(&state) as usize;

    for _ in 0..initial_jobs {
        GlobalAsyncExecutor::global().submit(recursive_submit_counter, ctx);
    }

    super::wait_until(Duration::from_secs(10), || {
        state.completed.load(Ordering::Acquire) == expected
    });
}
