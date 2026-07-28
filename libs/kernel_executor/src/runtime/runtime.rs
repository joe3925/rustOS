use alloc::vec::Vec;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub use super::blocking::{spawn_blocking, spawn_blocking_many, BlockingJoin};

use crate::future_arena::FutureAllocation;
use crate::global_async::{ExecutorDomainId, GlobalAsyncExecutor};
use crate::platform::{platform, Job};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::Arc;

use super::slab::{get_task_table, slab_task_poll_trampoline};

pub(crate) fn submit_global(trampoline: extern "C" fn(usize), ctx: usize) {
    GlobalAsyncExecutor::global().submit(trampoline, ctx);
}

pub(crate) fn submit_global_to_executor_domain(
    domain_id: ExecutorDomainId,
    trampoline: extern "C" fn(usize),
    ctx: usize,
) {
    GlobalAsyncExecutor::global().submit_to_executor_domain(domain_id, trampoline, ctx);
}

pub(crate) fn submit_blocking(trampoline: extern "C" fn(usize), ctx: usize) {
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

pub extern "C" fn try_steal_blocking_one() -> bool {
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
    spawn_in_executor_domain(crate::global_async::KERNEL_NORMAL_EXECUTOR_DOMAIN, future)
}

pub fn spawn_in_executor_domain<F, T>(domain_id: ExecutorDomainId, future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let domain = GlobalAsyncExecutor::global()
        .get_executor_domain(domain_id)
        .expect("invalid executor domain");
    let allocation = domain
        .future_arena()
        .allocate(core::mem::size_of::<F>(), core::mem::align_of::<F>())
        .expect("future arena allocation failed");
    unsafe { allocation.ptr.as_ptr().cast::<F>().write(future) };
    let slab = get_task_table();
    let slot_handle = match slab.allocate() {
        Some(handle) => handle,
        None => unsafe {
            release_unpublished_future::<F>(&domain, allocation);
            panic!("task table allocation failed");
        },
    };

    let (shard_idx, local_idx, generation) = slot_handle.indices();

    let slot = slab
        .get_slot(shard_idx, local_idx, generation)
        .expect("reserved task slot disappeared before initialization");
    unsafe { slot.init::<F, T>(domain_id, allocation) };
    domain.retain_task();

    slab.increment_ref(shard_idx, local_idx, generation);
    slab.increment_ref(shard_idx, local_idx, generation);

    let encoded = slot_handle.encoded_ptr();
    submit_global_to_executor_domain(domain_id, slab_task_poll_trampoline, encoded);

    JoinHandle {
        shard_idx: shard_idx as u8,
        local_idx: local_idx as u16,
        generation,
        consumed: false,
        _marker: PhantomData,
    }
}

pub struct JoinHandle<T: Send + 'static> {
    shard_idx: u8,
    local_idx: u16,
    generation: u32,
    consumed: bool,
    _marker: PhantomData<T>,
}

impl<T: Send + 'static> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };

        if this.consumed {
            panic!("JoinHandle polled after completion");
        }

        let slab = get_task_table();

        let Some(slot) = slab.get_slot(
            this.shard_idx as usize,
            this.local_idx as usize,
            this.generation,
        ) else {
            panic!("JoinHandle slot freed prematurely");
        };

        if slot.is_completed() {
            let result = unsafe { slot.take_result::<T>() };

            slab.decrement_ref(
                this.shard_idx as usize,
                this.local_idx as usize,
                this.generation,
            );

            this.consumed = true;
            Poll::Ready(result)
        } else {
            slot.update_join_waker(cx.waker());

            if slot.is_completed() {
                let result = unsafe { slot.take_result::<T>() };

                slab.decrement_ref(
                    this.shard_idx as usize,
                    this.local_idx as usize,
                    this.generation,
                );

                this.consumed = true;
                Poll::Ready(result)
            } else {
                Poll::Pending
            }
        }
    }
}

impl<T: Send + 'static> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        if !self.consumed {
            get_task_table().decrement_ref(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            );
        }
    }
}

pub fn spawn_detached<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_detached_in_executor_domain(crate::global_async::KERNEL_NORMAL_EXECUTOR_DOMAIN, future);
}

pub fn spawn_detached_in_executor_domain<F>(domain_id: ExecutorDomainId, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let domain = GlobalAsyncExecutor::global()
        .get_executor_domain(domain_id)
        .expect("invalid executor domain");
    let allocation = domain
        .future_arena()
        .allocate(core::mem::size_of::<F>(), core::mem::align_of::<F>())
        .expect("future arena allocation failed");
    unsafe { allocation.ptr.as_ptr().cast::<F>().write(future) };
    let slab = get_task_table();

    let slot_handle = match slab.allocate() {
        Some(handle) => handle,
        None => unsafe {
            release_unpublished_future::<F>(&domain, allocation);
            panic!("task table allocation failed");
        },
    };
    let (shard_idx, local_idx, generation) = slot_handle.indices();

    let slot = slab
        .get_slot(shard_idx, local_idx, generation)
        .expect("reserved task slot disappeared before initialization");
    unsafe { slot.init::<F, ()>(domain_id, allocation) };
    domain.retain_task();

    slab.increment_ref(shard_idx, local_idx, generation);

    let encoded = slot_handle.encoded_ptr();
    submit_global_to_executor_domain(domain_id, slab_task_poll_trampoline, encoded);
}

unsafe fn release_unpublished_future<F>(
    domain: &crate::global_async::ExecutorDomain,
    allocation: FutureAllocation,
) {
    unsafe {
        core::ptr::drop_in_place(allocation.ptr.as_ptr().cast::<F>());
        assert!(domain.future_arena().release(allocation));
    }
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
