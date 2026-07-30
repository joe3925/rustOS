use core::task::{RawWaker, RawWakerVTable, Waker};

use super::slab::{decode_slab_task_ptr, encode_slab_task_ptr, enqueue_slab_task, get_task_table};

#[inline]
fn encoded_to_waker_ptr(encoded: usize) -> *const () {
    core::ptr::without_provenance(encoded)
}

#[inline]
fn waker_ptr_to_encoded(ptr: *const ()) -> usize {
    ptr.addr()
}

static SLAB_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    slab_clone_waker,
    slab_wake,
    slab_wake_by_ref,
    slab_drop_waker,
);

pub fn create_slab_task_waker(shard_idx: usize, local_idx: usize, generation: u32) -> Waker {
    let encoded = encode_slab_task_ptr(shard_idx as u8, local_idx as u16, generation);
    unsafe {
        Waker::from_raw(RawWaker::new(
            encoded_to_waker_ptr(encoded),
            &SLAB_WAKER_VTABLE,
        ))
    }
}

unsafe fn slab_clone_waker(ptr: *const ()) -> RawWaker {
    RawWaker::new(ptr, &SLAB_WAKER_VTABLE)
}

unsafe fn slab_wake(ptr: *const ()) {
    let encoded = waker_ptr_to_encoded(ptr);
    if let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(encoded) {
        enqueue_slab_task(shard_idx, local_idx, generation);
    }
}

unsafe fn slab_wake_by_ref(ptr: *const ()) {
    let encoded = waker_ptr_to_encoded(ptr);
    if let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(encoded) {
        enqueue_slab_task(shard_idx, local_idx, generation);
    }
}

unsafe fn slab_drop_waker(_ptr: *const ()) {
    // No-op — slot lifetime is managed by structural anchor refs, not waker clones.
}

#[allow(dead_code)]
unsafe extern "C" fn drop_slab_ctx(ctx: usize) {
    if let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(ctx) {
        get_task_table().decrement_ref(shard_idx, local_idx, generation);
    }
}
