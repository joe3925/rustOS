use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::TypeId;
use core::marker::PhantomData;
use core::mem::{forget, transmute_copy, ManuallyDrop};
use core::ptr;
use core::task::{RawWaker, RawWakerVTable, Waker};

use crate::platform::JobFn;

use super::slab::{
    decode_slab_ptr, encode_slab_ptr, enqueue_slab_task, get_task_slab, slab_poll_trampoline,
};
use super::task::TaskPoll;

// Bit 0 is reserved for slab pointers. Use bit 1 to tag Arc-based executor wakers.
const TASK_WAKER_TAG: usize = 0b10;
const TASK_WAKER_MASK: usize = !TASK_WAKER_TAG;

#[inline]
fn is_tagged(ptr: usize) -> bool {
    ptr & TASK_WAKER_TAG != 0
}

#[inline]
fn tag_arc_ptr<T>(arc: Arc<T>) -> *const () {
    ((Arc::into_raw(arc) as usize) | TASK_WAKER_TAG) as *const ()
}

#[inline]
unsafe fn untag_ptr<T>(ptr: *const ()) -> *const T {
    ((ptr as usize) & TASK_WAKER_MASK) as *const T
}

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
    let ptr = tag_arc_ptr(task);
    unsafe { Waker::from_raw(RawWaker::new(ptr, &vtable.raw)) }
}

struct TaskWakerVtableHolder<T>(PhantomData<T>);

impl<T: TaskPoll + 'static> TaskWakerVtableHolder<T> {
    const VTABLE: TaskWakerVtable = TaskWakerVtable {
        raw: RawWakerVTable::new(
            clone_waker::<T>,
            wake::<T>,
            wake_by_ref::<T>,
            drop_waker::<T>,
        ),
        inline_poll: poll_trampoline_inline::<T>,
        clone_ctx: clone_ctx::<T>,
        drop_ctx: drop_ctx::<T>,
    };
}

/// Returns a static vtable for a given TaskPoll type.
fn vtable_for<T: TaskPoll + 'static>() -> &'static TaskWakerVtable {
    &TaskWakerVtableHolder::<T>::VTABLE
}

unsafe fn clone_waker<T: TaskPoll + 'static>(ptr: *const ()) -> RawWaker {
    Arc::increment_strong_count(untag_ptr::<T>(ptr));
    RawWaker::new(ptr, &vtable_for::<T>().raw)
}

unsafe fn wake<T: TaskPoll + 'static>(ptr: *const ()) {
    let arc = Arc::from_raw(untag_ptr::<T>(ptr));
    arc.enqueue();
}

unsafe fn wake_by_ref<T: TaskPoll + 'static>(ptr: *const ()) {
    let arc = ManuallyDrop::new(Arc::from_raw(untag_ptr::<T>(ptr)));
    arc.enqueue();
}

unsafe fn drop_waker<T: TaskPoll + 'static>(ptr: *const ()) {
    drop(Arc::from_raw(untag_ptr::<T>(ptr)));
}

unsafe fn clone_ctx<T: TaskPoll + 'static>(ptr: *const ()) {
    Arc::increment_strong_count(untag_ptr::<T>(ptr));
}

unsafe fn drop_ctx<T: TaskPoll + 'static>(ctx: usize) {
    drop(Arc::from_raw(untag_ptr::<T>(ctx as *const ())));
}

extern "win64" fn wake_waker_trampoline(ctx: usize) {
    // ctx holds Box<Waker>
    let w = unsafe { &*(ctx as *const Waker) };
    w.wake_by_ref();
}

unsafe fn drop_waker_ctx(ctx: usize) {
    drop(Box::from_raw(ctx as *mut Waker));
}

extern "win64" fn poll_trampoline_inline<T: TaskPoll + 'static>(ctx: usize) {
    // Borrow the continuation's ref without consuming it. run_continuation
    // will call drop_fn to release the ref after we return.
    let arc = ManuallyDrop::new(unsafe { Arc::from_raw(untag_ptr::<T>(ctx as *const ())) });

    if arc.is_completed() {
        return;
    }

    // Atomically IDLE -> POLLING. If it fails, someone else owns this task, so
    // treat this as a regular wake to record the notification instead of
    // dropping it.
    if !arc.try_start_inline_poll() {
        arc.enqueue();
        return;
    }

    // We are now in POLLING state. poll_once_inline handles the rest
    // (polling the future, then transitioning to IDLE/COMPLETED/re-enqueue on NOTIFIED).
    // Clone the Arc so poll_once_inline has its own owned ref.
    Arc::clone(&arc).poll_once_inline();
}

#[repr(C)]
pub struct TaskWakerVtable {
    pub raw: RawWakerVTable,
    pub inline_poll: JobFn,
    pub clone_ctx: unsafe fn(*const ()),
    pub drop_ctx: unsafe fn(usize),
}

#[derive(Clone, Copy)]
pub struct Continuation {
    pub tramp: JobFn,
    pub ctx: usize,
    pub drop_fn: unsafe fn(usize),
}

/// Attempts to build an inline continuation from the provided waker.
/// Returns None if the waker is not one created by this runtime.
pub fn continuation_from_waker(w: &Waker) -> Option<Continuation> {
    let cloned = w.clone();
    let raw: RawWaker = unsafe { transmute_copy(&cloned) };
    // Avoid dropping the cloned Waker directly; we'll drop via from_raw below.
    forget(cloned);
    let data_ptr = w.data();
    let vtable_ptr = w.vtable();
    let data = data_ptr as usize;
    let drop_guard = unsafe { Waker::from_raw(raw) };

    // Slab-based waker
    if ptr::eq(vtable_ptr, &SLAB_WAKER_VTABLE) {
        // Keep slot alive while the continuation is stored
        if let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(data) {
            get_task_slab().increment_ref(shard_idx, local_idx, generation);
            drop(drop_guard);
            return Some(Continuation {
                tramp: slab_inline_poll,
                ctx: data,
                drop_fn: drop_slab_ctx,
            });
        } else {
            drop(drop_guard);
            return None;
        }
    }

    // Arc-based waker with TaskWakerVtable layout
    if !is_tagged(data) {
        drop(drop_guard);
        let boxed = Box::new(w.clone());
        let ctx = Box::into_raw(boxed) as usize;
        return Some(Continuation {
            tramp: wake_waker_trampoline,
            ctx,
            drop_fn: drop_waker_ctx,
        });
    }
    let meta = vtable_ptr as *const _ as *const TaskWakerVtable;
    unsafe { ((*meta).clone_ctx)(data_ptr) };
    drop(drop_guard);

    Some(Continuation {
        tramp: unsafe { (*meta).inline_poll },
        ctx: data,
        drop_fn: unsafe { (*meta).drop_ctx },
    })
}

// ============================================================================
// Slab-based wakers (for slab-allocated FutureTask)
// ============================================================================

/// Static vtable for slab-allocated task wakers.
static SLAB_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    slab_clone_waker::<u64>,
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

unsafe fn slab_clone_waker<T: 'static>(ptr: *const ()) -> RawWaker {
    let id = TypeId::of::<T>();
    if id != TypeId::of::<u64>() {}
    let encoded = ptr as usize;
    if let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(encoded) {
        let slab = get_task_slab();
        slab.increment_ref(shard_idx, local_idx, generation);
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

extern "win64" fn slab_inline_poll(ctx: usize) {
    let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(ctx) else {
        return;
    };

    let slab = get_task_slab();
    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        return;
    };

    if slot.is_completed() {
        return;
    }

    // Atomically IDLE -> QUEUED, then call slab_poll_trampoline which
    // does QUEUED -> POLLING and polls the future.
    // Loop to handle the race where try_notify sees POLLING but the task
    // transitions to IDLE before the POLLING->NOTIFIED CAS lands.
    loop {
        if slot.try_enqueue() {
            slab.increment_ref(shard_idx, local_idx, generation);
            slab_poll_trampoline(ctx);
            return;
        }

        if slot.try_notify() {
            return;
        }
    }
}

unsafe fn drop_slab_ctx(ctx: usize) {
    if let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(ctx) {
        get_task_slab().decrement_ref(shard_idx, local_idx, generation);
    }
}
