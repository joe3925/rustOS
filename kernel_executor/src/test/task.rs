use alloc::sync::Arc;
use core::future::Future;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::Duration;

use crate::runtime::task::{FutureTask, JoinableTask, TaskPoll};

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

struct WakeDuringPoll {
    polls: Arc<AtomicUsize>,
}

impl Future for WakeDuringPoll {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.polls.fetch_add(1, Ordering::AcqRel) == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

struct JoinableWakeDuringPoll {
    polls: Arc<AtomicUsize>,
    value: usize,
}

impl Future for JoinableWakeDuringPoll {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.polls.fetch_add(1, Ordering::AcqRel) == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(self.value)
        }
    }
}

// This test exists to cover the detached task state machine without involving
// the global executor. An inline poll of a ready future should complete exactly
// once and prevent a second inline poll from starting.
#[test]
fn future_task_inline_poll_runs_ready_future_to_completion() {
    let ran = Arc::new(AtomicUsize::new(0));
    let ran_for_task = ran.clone();
    let task = Arc::new(FutureTask::new(async move {
        ran_for_task.fetch_add(1, Ordering::AcqRel);
    }));

    assert!(task.try_start_inline_poll());
    task.clone().poll_once_inline();

    assert!(task.is_completed());
    assert_eq!(ran.load(Ordering::Acquire), 1);
    assert!(!task.try_start_inline_poll());
}

// This test covers the detached task POLLING -> NOTIFIED -> QUEUED transition
// directly. A wake that fires during poll must requeue the task after Pending
// instead of being dropped when the poll returns.
#[test]
fn future_task_wake_during_inline_poll_requeues_and_completes() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let polls = Arc::new(AtomicUsize::new(0));
    let task = Arc::new(FutureTask::new(WakeDuringPoll {
        polls: polls.clone(),
    }));

    assert!(task.try_start_inline_poll());
    task.clone().poll_once_inline();

    super::wait_until(Duration::from_secs(10), || task.is_completed());
    assert_eq!(polls.load(Ordering::Acquire), 2);
}

// This test exists to cover the joinable task state machine directly. A ready
// future should store its result, wake the joiner once, and allow the result to
// be consumed exactly once.
#[test]
fn joinable_task_inline_poll_stores_result_and_wakes_joiner() {
    let task = Arc::new(JoinableTask::new(async { 99usize }));
    let wake_count = Arc::new(AtomicUsize::new(0));
    task.set_waker(counting_waker(wake_count.clone()));

    assert!(task.try_start_inline_poll());
    task.clone().poll_once_inline();

    assert!(task.is_completed());
    assert_eq!(task.take_result(), Some(99));
    assert_eq!(task.take_result(), None);
    assert_eq!(wake_count.load(Ordering::Acquire), 1);
}

// This test covers the joinable Arc task POLLING -> NOTIFIED -> QUEUED
// transition. The task wakes itself during its first poll, so completion depends
// on preserving that in-flight wake and polling it again.
#[test]
fn joinable_task_wake_during_inline_poll_requeues_completes_and_wakes_joiner() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let polls = Arc::new(AtomicUsize::new(0));
    let task = Arc::new(JoinableTask::new(JoinableWakeDuringPoll {
        polls: polls.clone(),
        value: 123,
    }));
    let wake_count = Arc::new(AtomicUsize::new(0));
    task.set_waker(counting_waker(wake_count.clone()));

    assert!(task.try_start_inline_poll());
    task.clone().poll_once_inline();

    super::wait_until(Duration::from_secs(10), || task.is_completed());
    assert_eq!(polls.load(Ordering::Acquire), 2);
    assert_eq!(task.take_result(), Some(123));
    assert_eq!(wake_count.load(Ordering::Acquire), 1);
}
