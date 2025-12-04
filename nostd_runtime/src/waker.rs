use alloc::sync::Arc;
use core::task::{RawWaker, RawWakerVTable, Waker};

use crate::submit_raw;
use crate::task::FutureTask;
#[repr(C)]
pub struct TaskWaker;

impl TaskWaker {
    pub fn create_waker(task: Arc<FutureTask>) -> Waker {
        let ptr = Arc::into_raw(task) as *const ();
        unsafe { Waker::from_raw(RawWaker::new(ptr, &VTABLE)) }
    }
}

unsafe fn clone_waker(ptr: *const ()) -> RawWaker {
    Arc::increment_strong_count(ptr as *const FutureTask);
    RawWaker::new(ptr, &VTABLE)
}

unsafe fn wake(ptr: *const ()) {
    submit_raw(ptr as usize);
}

unsafe fn wake_by_ref(ptr: *const ()) {
    Arc::increment_strong_count(ptr as *const FutureTask);
    submit_raw(ptr as usize);
}

unsafe fn drop_waker(ptr: *const ()) {
    let _ = Arc::from_raw(ptr as *const FutureTask);
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake, wake_by_ref, drop_waker);
