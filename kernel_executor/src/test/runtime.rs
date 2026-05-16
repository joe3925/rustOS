use alloc::{sync::Arc, vec, vec::Vec};
use core::future::Future;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::runtime::runtime::{block_on, spawn, spawn_detached, JoinAll};

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

#[test]
fn block_on_returns_immediately_for_ready_future() {
    assert_eq!(block_on(async { 123usize }), 123);
}

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

#[test]
fn spawn_joinhandle_completes_on_inline_runtime() {
    let _guard = super::global_runtime_lock();
    super::init_inline_runtime();

    let result = block_on(async { spawn(async { 55usize }).await });
    assert_eq!(result, 55);
}

#[test]
fn spawn_detached_runs_future_on_inline_runtime() {
    let _guard = super::global_runtime_lock();
    super::init_inline_runtime();

    let ran = Arc::new(AtomicUsize::new(0));
    let ran_for_task = ran.clone();
    spawn_detached(async move {
        ran_for_task.store(1, Ordering::Release);
    });

    assert_eq!(ran.load(Ordering::Acquire), 1);
}
