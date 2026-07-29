use alloc::{boxed::Box, vec::Vec};
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use kernel_types::completion::{CompletionPermit, TaskCompletion, TaskOutcome, TaskToken};

pub use super::blocking::{spawn_blocking, spawn_blocking_many, BlockingJoin};

use crate::future_arena::FutureAllocation;
use crate::global_async::{ExecutorDomainId, GlobalAsyncExecutor};
use crate::platform::{platform, Job};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::Arc;

use super::slab::slot::{RESULT_ABANDONED, RESULT_CLAIMED};
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

pub struct JoinStorage<T> {
    output: UnsafeCell<MaybeUninit<T>>,
    _pin: core::marker::PhantomPinned,
}

impl<T> JoinStorage<T> {
    pub const fn new() -> Self {
        Self {
            output: UnsafeCell::new(MaybeUninit::uninit()),
            _pin: core::marker::PhantomPinned,
        }
    }

    pub(crate) unsafe fn write(&self, output: T) {
        (*self.output.get()).write(output);
    }

    unsafe fn take(&self) -> T {
        (*self.output.get()).assume_init_read()
    }

    unsafe fn drop_output(&self) {
        (*self.output.get()).assume_init_drop();
    }
}

unsafe impl<T: Send> Send for JoinStorage<T> {}
unsafe impl<T: Send> Sync for JoinStorage<T> {}

pub fn spawn<'a, F, T>(storage: Pin<&'a mut JoinStorage<T>>, future: F) -> JoinHandle<'a, T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    spawn_in_executor_domain(
        crate::global_async::KERNEL_NORMAL_EXECUTOR_DOMAIN,
        storage,
        future,
    )
}

pub fn spawn_in_executor_domain<'a, F, T>(
    domain_id: ExecutorDomainId,
    storage: Pin<&'a mut JoinStorage<T>>,
    future: F,
) -> JoinHandle<'a, T>
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
    let storage_ptr = unsafe { storage.get_unchecked_mut() as *mut JoinStorage<T> };
    unsafe { slot.init_joinable::<F, T>(domain_id, allocation, storage_ptr) };
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
        storage: storage_ptr,
        _marker: PhantomData,
    }
}

pub struct JoinHandle<'a, T: Send + 'static> {
    shard_idx: u8,
    local_idx: u16,
    generation: u32,
    consumed: bool,
    storage: *mut JoinStorage<T>,
    _marker: PhantomData<&'a mut JoinStorage<T>>,
}

unsafe impl<T: Send + 'static> Send for JoinHandle<'_, T> {}

impl<T: Send + 'static> Future for JoinHandle<'_, T> {
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
            let result = unsafe { (&*this.storage).take() };

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
                let result = unsafe { (&*this.storage).take() };

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

impl<T: Send + 'static> Drop for JoinHandle<'_, T> {
    fn drop(&mut self) {
        if !self.consumed {
            let slab = get_task_table();
            if let Some(slot) = slab.get_slot(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            ) {
                loop {
                    let ptr = slot.result_ptr.load(Ordering::Acquire);
                    if ptr == RESULT_ABANDONED {
                        break;
                    }
                    if ptr == RESULT_CLAIMED {
                        while !slot.is_completed() {
                            core::hint::spin_loop();
                        }
                        unsafe { (&*self.storage).drop_output() };
                        break;
                    }
                    if slot
                        .result_ptr
                        .compare_exchange(
                            ptr,
                            RESULT_ABANDONED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
            }
            slab.decrement_ref(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            );
        }
    }
}

pub struct OwnedJoinHandle<T: Send + 'static> {
    handle: JoinHandle<'static, T>,
    _storage: Pin<Box<JoinStorage<T>>>,
}

impl<T: Send + 'static> Future for OwnedJoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut this.handle) }.poll(cx)
    }
}

#[doc(hidden)]
pub fn spawn_join_owned<F, T>(future: F) -> OwnedJoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    spawn_join_owned_in_executor_domain(crate::global_async::KERNEL_NORMAL_EXECUTOR_DOMAIN, future)
}

#[doc(hidden)]
pub fn spawn_join_owned_in_executor_domain<F, T>(
    domain_id: ExecutorDomainId,
    future: F,
) -> OwnedJoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut storage = Box::pin(JoinStorage::new());
    let storage_ref = unsafe {
        core::mem::transmute::<Pin<&mut JoinStorage<T>>, Pin<&'static mut JoinStorage<T>>>(
            storage.as_mut(),
        )
    };
    let handle = spawn_in_executor_domain(domain_id, storage_ref, future);
    OwnedJoinHandle {
        handle,
        _storage: storage,
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
    unsafe { slot.init_detached::<F>(domain_id, allocation) };
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

struct PortFuture<F, P: CompletionPermit<T>, T> {
    future: F,
    permit: Option<P>,
    key: u64,
    token: usize,
    completed: bool,
    _output: PhantomData<T>,
}

impl<F, P, T> Future for PortFuture<F, P, T>
where
    F: Future<Output = T>,
    P: CompletionPermit<T>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = unsafe { self.get_unchecked_mut() };
        match unsafe { Pin::new_unchecked(&mut this.future) }.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(output) => {
                this.completed = true;
                let permit = this.permit.take().expect("completion permit missing");
                permit.complete(TaskCompletion {
                    task: TaskToken::from_raw(this.token).expect("invalid task token"),
                    key: this.key,
                    outcome: TaskOutcome::Completed(output),
                });
                Poll::Ready(())
            }
        }
    }
}

impl<F, P, T> Drop for PortFuture<F, P, T>
where
    P: CompletionPermit<T>,
{
    fn drop(&mut self) {
        if !self.completed {
            if let (Some(permit), Some(task)) =
                (self.permit.take(), TaskToken::from_raw(self.token))
            {
                permit.complete(TaskCompletion {
                    task,
                    key: self.key,
                    outcome: TaskOutcome::Cancelled,
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnToPortError {
    InvalidDomain,
    FutureAllocationFailed,
    TaskAllocationFailed,
}

pub fn try_spawn_to_port_in_executor_domain<F, P, T>(
    domain_id: ExecutorDomainId,
    future: F,
    completion_key: u64,
    permit: P,
) -> Result<TaskToken, SpawnToPortError>
where
    F: Future<Output = T> + Send + 'static,
    P: CompletionPermit<T>,
    T: Send + 'static,
{
    let domain = GlobalAsyncExecutor::global()
        .get_executor_domain(domain_id)
        .ok_or(SpawnToPortError::InvalidDomain)?;
    let allocation = domain
        .future_arena()
        .allocate(
            core::mem::size_of::<PortFuture<F, P, T>>(),
            core::mem::align_of::<PortFuture<F, P, T>>(),
        )
        .ok_or(SpawnToPortError::FutureAllocationFailed)?;
    unsafe {
        allocation
            .ptr
            .as_ptr()
            .cast::<PortFuture<F, P, T>>()
            .write(PortFuture {
                future,
                permit: Some(permit),
                key: completion_key,
                token: 0,
                completed: false,
                _output: PhantomData,
            });
    }
    let slab = get_task_table();
    let Some(handle) = slab.allocate() else {
        unsafe { release_unpublished_future::<PortFuture<F, P, T>>(&domain, allocation) };
        return Err(SpawnToPortError::TaskAllocationFailed);
    };
    let (shard, local, generation) = handle.indices();
    let Some(token) = TaskToken::from_raw(handle.encoded_ptr()) else {
        unsafe { release_unpublished_future::<PortFuture<F, P, T>>(&domain, allocation) };
        return Err(SpawnToPortError::TaskAllocationFailed);
    };
    unsafe { (*allocation.ptr.as_ptr().cast::<PortFuture<F, P, T>>()).token = token.raw() };
    let slot = slab
        .get_slot(shard, local, generation)
        .expect("reserved task slot disappeared");
    unsafe { slot.init_abortable::<PortFuture<F, P, T>>(domain_id, allocation) };
    domain.retain_task();
    slab.increment_ref(shard, local, generation);
    submit_global_to_executor_domain(domain_id, slab_task_poll_trampoline, handle.encoded_ptr());
    Ok(token)
}

pub fn abort_task(token: TaskToken) -> bool {
    let Some((shard, local, generation)) = super::slab::decode_slab_task_ptr(token.raw()) else {
        return false;
    };
    let slab = get_task_table();
    if !slab.increment_ref(shard, local, generation) {
        return false;
    }
    let result = slab
        .get_slot(shard, local, generation)
        .is_some_and(|slot| slot.request_abort());
    if result {
        super::slab::enqueue_slab_task(shard, local, generation);
    }
    slab.decrement_ref(shard, local, generation);
    result
}
