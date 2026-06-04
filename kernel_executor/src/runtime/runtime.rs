use crate::runtime::task::TaskPoll;

use alloc::vec::Vec;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::{align_of, size_of, ManuallyDrop};
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub use super::blocking::{spawn_blocking, spawn_blocking_many, BlockingJoin};

use crate::global_async::{DomainId, GlobalAsyncExecutor};
use crate::platform::{platform, Job};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::Arc;

use super::slab::{get_task_slab, INLINE_FUTURE_ALIGN, JOINABLE_STORAGE_SIZE};
use super::task::{FutureTask, JoinableTask};

pub(crate) fn submit_global(trampoline: extern "win64" fn(usize), ctx: usize) {
    GlobalAsyncExecutor::global().submit(trampoline, ctx);
}

pub(crate) fn submit_global_to_domain(
    domain_id: DomainId,
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    GlobalAsyncExecutor::global().submit_to_domain(domain_id, trampoline, ctx);
}

pub(crate) fn submit_blocking(trampoline: extern "win64" fn(usize), ctx: usize) {
    platform().submit_blocking(Job {
        f: trampoline,
        a: ctx,
    });
}

pub(crate) fn submit_blocking_many(jobs: &[Job]) {
    platform().submit_blocking_many(jobs);
}

pub fn yield_now() {
    platform().yield_now();
}

pub extern "win64" fn try_steal_blocking_one() -> bool {
    platform().try_steal_blocking_one()
}

struct BlockOnWakeState {
    ready: AtomicBool,
}

unsafe fn block_on_waker_clone(ptr: *const ()) -> RawWaker {
    let arc = ManuallyDrop::new(unsafe { Arc::from_raw(ptr as *const BlockOnWakeState) });
    let cloned = Arc::clone(&arc);
    RawWaker::new(Arc::into_raw(cloned) as *const (), &BLOCK_ON_WAKER_VTABLE)
}

unsafe fn block_on_waker_wake(ptr: *const ()) {
    let arc = unsafe { Arc::from_raw(ptr as *const BlockOnWakeState) };
    arc.ready.store(true, Ordering::Release);
}

unsafe fn block_on_waker_wake_by_ref(ptr: *const ()) {
    let arc = ManuallyDrop::new(unsafe { Arc::from_raw(ptr as *const BlockOnWakeState) });
    arc.ready.store(true, Ordering::Release);
}

unsafe fn block_on_waker_drop(ptr: *const ()) {
    drop(unsafe { Arc::from_raw(ptr as *const BlockOnWakeState) });
}

static BLOCK_ON_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    block_on_waker_clone,
    block_on_waker_wake,
    block_on_waker_wake_by_ref,
    block_on_waker_drop,
);

pub fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    let state = Arc::new(BlockOnWakeState {
        ready: AtomicBool::new(false),
    });

    let raw = RawWaker::new(
        Arc::into_raw(state.clone()) as *const (),
        &BLOCK_ON_WAKER_VTABLE,
    );
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);
    let mut future = future;

    loop {
        let poll = unsafe { Pin::new_unchecked(&mut future) }.poll(&mut cx);
        match poll {
            Poll::Ready(v) => return v,
            Poll::Pending => {}
        }

        if !state.ready.swap(false, Ordering::AcqRel) && !try_steal_blocking_one() {
            yield_now();
        }
    }
}

pub fn spawn<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let slab = get_task_slab();

    let future_fits =
        size_of::<F>() <= JOINABLE_STORAGE_SIZE && align_of::<F>() <= INLINE_FUTURE_ALIGN;
    let result_fits =
        size_of::<T>() <= JOINABLE_STORAGE_SIZE && align_of::<T>() <= INLINE_FUTURE_ALIGN;

    if future_fits && result_fits {
        if let Some(slot_handle) = slab.allocate_joinable() {
            let (shard_idx, local_idx, generation) = slot_handle.init_and_enqueue(future);
            return JoinHandle {
                inner: JoinHandleInner::Slab {
                    shard_idx,
                    local_idx,
                    generation,
                    consumed: false,
                    _marker: PhantomData,
                },
            };
        }
    }

    slab.record_joinable_fallback();

    let task = Arc::new(JoinableTask::new(future));
    task.enqueue();

    JoinHandle {
        inner: JoinHandleInner::Arc(task),
    }
}

pub fn spawn_in_domain<F, T>(domain_id: DomainId, future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let task = Arc::new(JoinableTask::new_in_domain(domain_id, future));
    task.enqueue();

    JoinHandle {
        inner: JoinHandleInner::Arc(task),
    }
}

pub struct JoinHandle<T: Send + 'static> {
    inner: JoinHandleInner<T>,
}

enum JoinHandleInner<T: Send + 'static> {
    Arc(Arc<JoinableTask<T>>),
    Slab {
        shard_idx: u8,
        local_idx: u16,
        generation: u32,
        consumed: bool,
        _marker: PhantomData<T>,
    },
}

impl<T: Send + 'static> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };

        match &mut this.inner {
            JoinHandleInner::Arc(task) => {
                if let Some(result) = task.take_result() {
                    Poll::Ready(result)
                } else {
                    task.update_waker(cx.waker());

                    if let Some(result) = task.take_result() {
                        Poll::Ready(result)
                    } else {
                        Poll::Pending
                    }
                }
            }
            JoinHandleInner::Slab {
                shard_idx,
                local_idx,
                generation,
                consumed,
                ..
            } => {
                if *consumed {
                    panic!("JoinHandle polled after completion");
                }

                let slab = get_task_slab();

                let Some(slot) =
                    slab.get_joinable_slot(*shard_idx as usize, *local_idx as usize, *generation)
                else {
                    panic!("JoinHandle slot freed prematurely");
                };

                if slot.is_completed() {
                    let result = unsafe { slot.take_result::<T>() };

                    slab.decrement_joinable_ref(
                        *shard_idx as usize,
                        *local_idx as usize,
                        *generation,
                    );

                    *consumed = true;
                    Poll::Ready(result)
                } else {
                    slot.update_join_waker(cx.waker());

                    if slot.is_completed() {
                        let result = unsafe { slot.take_result::<T>() };

                        slab.decrement_joinable_ref(
                            *shard_idx as usize,
                            *local_idx as usize,
                            *generation,
                        );

                        *consumed = true;
                        Poll::Ready(result)
                    } else {
                        Poll::Pending
                    }
                }
            }
        }
    }
}

impl<T: Send + 'static> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        if let JoinHandleInner::Slab {
            shard_idx,
            local_idx,
            generation,
            consumed,
            ..
        } = &self.inner
        {
            if !*consumed {
                get_task_slab().decrement_joinable_ref(
                    *shard_idx as usize,
                    *local_idx as usize,
                    *generation,
                );
            }
        }
    }
}

pub fn spawn_detached<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let slab = get_task_slab();

    if let Some(slot_handle) = slab.allocate() {
        slot_handle.init_and_enqueue(future);
    } else {
        slab.record_fallback();

        let task = Arc::new(FutureTask::new(future));
        task.enqueue();
    }
}

pub fn spawn_detached_in_domain<F>(domain_id: DomainId, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Arc::new(FutureTask::new_in_domain(domain_id, future));
    task.enqueue();
}

enum FutureSlot<F: Future> {
    Running(F),
    Done(Option<F::Output>),
}

pub struct JoinAll<F: Future> {
    slots: Vec<FutureSlot<F>>,
    remaining: usize,
}

impl<F: Future> JoinAll<F> {
    pub fn new(fs: Vec<F>) -> Self {
        let remaining = fs.len();
        let slots = fs.into_iter().map(FutureSlot::Running).collect();

        Self { slots, remaining }
    }
}

impl<F: Future> Future for JoinAll<F> {
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if this.remaining == 0 {
            return Poll::Ready(join_all_take_output(&mut this.slots));
        }

        let mut i = 0usize;
        while i < this.slots.len() {
            let slot = &mut this.slots[i];

            if let FutureSlot::Running(fut) = slot {
                let pinned = unsafe { Pin::new_unchecked(fut) };

                if let Poll::Ready(result) = pinned.poll(cx) {
                    *slot = FutureSlot::Done(Some(result));
                    this.remaining -= 1;

                    if this.remaining == 0 {
                        return Poll::Ready(join_all_take_output(&mut this.slots));
                    }
                }
            }

            i += 1;
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn join_all_take_output<F: Future>(slots: &mut [FutureSlot<F>]) -> Vec<F::Output> {
    let mut out = Vec::with_capacity(slots.len());

    for slot in slots.iter_mut() {
        match slot {
            FutureSlot::Done(result) => {
                out.push(result.take().expect("result already taken"));
            }
            FutureSlot::Running(_) => {
                panic!("JoinAll completed with running child");
            }
        }
    }

    out
}
