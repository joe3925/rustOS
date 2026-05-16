use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};

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
