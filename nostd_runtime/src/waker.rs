use alloc::sync::Arc;
use alloc::task::Wake;
use core::task::{RawWaker, RawWakerVTable, Waker};

use crate::submit_raw;
use crate::task::Task;

pub struct TaskWaker;

impl TaskWaker {
    pub fn create_waker(task: Arc<Task>) -> Waker {
        let ptr = Arc::into_raw(task) as *const ();
        unsafe { Waker::from_raw(RawWaker::new(ptr, &VTABLE)) }
    }
}

unsafe fn clone_waker(ptr: *const ()) -> RawWaker {
    let task = Arc::from_raw(ptr as *const Task);

    // We need a new reference for the new Waker
    let new_task = task.clone();

    // Forget the original so we don't drop it (we only borrowed the pointer)
    core::mem::forget(task);

    let raw_ptr = Arc::into_raw(new_task) as *const ();
    RawWaker::new(raw_ptr, &VTABLE)
}

unsafe fn wake(ptr: *const ()) {
    // wake() consumes the waker.
    // We convert the pointer back to an Arc to take ownership.
    let task = Arc::from_raw(ptr as *const Task);

    // We convert it back to a raw pointer to pass to the scheduler.
    // Effectively, we transfer ownership from the Waker to the Scheduler.
    let raw_ptr = Arc::into_raw(task) as usize;

    // Submit to kernel
    submit_raw(raw_ptr);
}

unsafe fn wake_by_ref(ptr: *const ()) {
    // wake_by_ref() does NOT consume the waker.
    // We must create a NEW reference to send to the scheduler.
    let task = Arc::from_raw(ptr as *const Task);
    let new_task = task.clone();

    // Forget the original (we are just looking at it)
    core::mem::forget(task);

    let raw_ptr = Arc::into_raw(new_task) as usize;
    submit_raw(raw_ptr);
}

unsafe fn drop_waker(ptr: *const ()) {
    // Just drop the Arc to decrement the ref count.
    let _ = Arc::from_raw(ptr as *const Task);
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake, wake_by_ref, drop_waker);
