use alloc::sync::Arc;
use core::task::{RawWaker, RawWakerVTable, Waker};

use crate::scheduling::runtime::task::TaskPoll;

/// Creates a Waker from any Arc<T: TaskPoll> without additional allocation.
/// The Arc's refcount is transferred to the waker.
///
/// We use a macro to generate type-specific vtables since we need concrete
/// types for Arc operations. Each TaskPoll implementation gets its own vtable.
pub fn create_from_task_poll<T: TaskPoll + 'static>(task: Arc<T>) -> Waker {
    // Get the vtable for this specific type
    let vtable = vtable_for::<T>();
    let ptr = Arc::into_raw(task) as *const ();
    unsafe { Waker::from_raw(RawWaker::new(ptr, vtable)) }
}

/// Returns a static vtable for a given TaskPoll type.
fn vtable_for<T: TaskPoll + 'static>() -> &'static RawWakerVTable {
    &RawWakerVTable::new(
        clone_waker::<T>,
        wake::<T>,
        wake_by_ref::<T>,
        drop_waker::<T>,
    )
}

unsafe fn clone_waker<T: TaskPoll + 'static>(ptr: *const ()) -> RawWaker {
    Arc::increment_strong_count(ptr as *const T);
    RawWaker::new(ptr, vtable_for::<T>())
}

unsafe fn wake<T: TaskPoll + 'static>(ptr: *const ()) {
    let arc = Arc::from_raw(ptr as *const T);
    arc.enqueue();
}

unsafe fn wake_by_ref<T: TaskPoll + 'static>(ptr: *const ()) {
    let arc = core::mem::ManuallyDrop::new(Arc::from_raw(ptr as *const T));
    arc.enqueue();
}

unsafe fn drop_waker<T: TaskPoll + 'static>(ptr: *const ()) {
    drop(Arc::from_raw(ptr as *const T));
}
