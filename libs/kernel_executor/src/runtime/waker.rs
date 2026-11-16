use crate::platform::ExecutorPlatform;
use core::task::{RawWaker, RawWakerVTable, Waker};

use super::slab::ptr::{decode_slab_task_ptr, encode_slab_task_ptr, enqueue_slab_task};
use super::slab::task_slab::get_task_table;

#[inline]
fn encoded_to_waker_ptr(encoded: usize) -> *const () {
    core::ptr::without_provenance(encoded)
}

#[inline]
fn waker_ptr_to_encoded(ptr: *const ()) -> usize {
    ptr.addr()
}

impl<E: ExecutorPlatform> crate::global_async::GlobalAsyncExecutor<E> {
    const SLAB_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        slab_clone_waker::<E>,
        slab_wake::<E>,
        slab_wake_by_ref::<E>,
        slab_drop_waker::<E>,
    );
}

pub fn create_slab_task_waker<E: ExecutorPlatform>(
    shard_idx: usize,
    local_idx: usize,
    generation: u32,
) -> Waker {
    let encoded = encode_slab_task_ptr(shard_idx as u8, local_idx as u32, generation);
    unsafe {
        Waker::from_raw(RawWaker::new(
            encoded_to_waker_ptr(encoded),
            &crate::global_async::GlobalAsyncExecutor::<E>::SLAB_WAKER_VTABLE,
        ))
    }
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn slab_clone_waker<E: ExecutorPlatform>(ptr: *const ()) -> RawWaker {
    RawWaker::new(
        ptr,
        &crate::global_async::GlobalAsyncExecutor::<E>::SLAB_WAKER_VTABLE,
    )
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn slab_wake<E: ExecutorPlatform>(ptr: *const ()) {
    let encoded = waker_ptr_to_encoded(ptr);
    if let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(encoded) {
        enqueue_slab_task::<E>(shard_idx, local_idx, generation);
    }
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn slab_wake_by_ref<E: ExecutorPlatform>(ptr: *const ()) {
    let encoded = waker_ptr_to_encoded(ptr);
    if let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(encoded) {
        enqueue_slab_task::<E>(shard_idx, local_idx, generation);
    }
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn slab_drop_waker<E: ExecutorPlatform>(_ptr: *const ()) {
    // No-op — slot lifetime is managed by structural anchor refs, not waker clones.
}

#[allow(dead_code)]
unsafe extern "C" fn drop_slab_ctx<E: ExecutorPlatform>(ctx: usize) {
    if let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(ctx) {
        get_task_table::<E>().decrement_ref::<false>(shard_idx, local_idx, generation);
    }
}
