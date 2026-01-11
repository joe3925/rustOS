use alloc::sync::Arc;
use core::task::{RawWaker, RawWakerVTable, Waker};

use crate::scheduling::runtime::task::TaskPoll;
use super::slab::{decode_slab_ptr, encode_slab_ptr, enqueue_slab_task, get_task_slab};

// ============================================================================
// Arc-based wakers (for JoinableTask<T> and fallback FutureTask)
// ============================================================================

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

// ============================================================================
// Slab-based wakers (for slab-allocated FutureTask)
// ============================================================================

/// Static vtable for slab-allocated task wakers.
static SLAB_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    slab_clone_waker,
    slab_wake,
    slab_wake_by_ref,
    slab_drop_waker,
);

/// Creates a Waker for a slab-allocated task.
/// The encoded pointer contains shard index, local index, and generation.
pub fn create_slab_waker(shard_idx: usize, local_idx: usize, generation: u32) -> Waker {
    let encoded = encode_slab_ptr(shard_idx as u8, local_idx as u16, generation);
    // Increment ref count for the waker
    get_task_slab().increment_ref(shard_idx, local_idx, generation);
    unsafe { Waker::from_raw(RawWaker::new(encoded as *const (), &SLAB_WAKER_VTABLE)) }
}

unsafe fn slab_clone_waker(ptr: *const ()) -> RawWaker {
    let encoded = ptr as usize;
    if let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(encoded) {
        get_task_slab().increment_ref(shard_idx, local_idx, generation);
    }
    RawWaker::new(ptr, &SLAB_WAKER_VTABLE)
}

unsafe fn slab_wake(ptr: *const ()) {
    let encoded = ptr as usize;
    if let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(encoded) {
        enqueue_slab_task(shard_idx, local_idx, generation);
        // Decrement ref count (wake consumes the waker)
        get_task_slab().decrement_ref(shard_idx, local_idx, generation);
    }
}

unsafe fn slab_wake_by_ref(ptr: *const ()) {
    let encoded = ptr as usize;
    if let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(encoded) {
        enqueue_slab_task(shard_idx, local_idx, generation);
        // Don't decrement ref count - wake_by_ref doesn't consume the waker
    }
}

unsafe fn slab_drop_waker(ptr: *const ()) {
    let encoded = ptr as usize;
    if let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(encoded) {
        get_task_slab().decrement_ref(shard_idx, local_idx, generation);
    }
}
