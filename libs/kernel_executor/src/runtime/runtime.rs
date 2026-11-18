use crate::platform::ExecutorPlatform;
use crate::thread_state::BlockOnThreadState;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
pub use kernel_sync::completion::TaskOutcome;
use kernel_sync::completion::{CompletionPermit, TaskCompletion, TaskToken};

pub use super::blocking::{BlockingJoin, spawn_blocking, spawn_blocking_many};

use crate::future_allocation::FutureAllocation;
use crate::global_async::{ExecutorDomainId, GlobalAsyncExecutor};
use crate::platform::Job;
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::slab::slot::{RESULT_ABANDONED, RESULT_CLAIMED, TaskSlot};
use super::slab::task_slab::{SlotHandle, get_task_table};

pub(crate) fn submit_global_to_executor_domain<E: ExecutorPlatform>(
    domain_id: ExecutorDomainId,
    ctx: usize,
) {
    GlobalAsyncExecutor::<E>::global().enqueue_task_to_executor_domain(domain_id, ctx);
}

pub(crate) fn submit_blocking<E: ExecutorPlatform>(trampoline: extern "C" fn(usize), ctx: usize) {
    E::submit_blocking(Job {
        f: trampoline,
        a: ctx,
    });
}

pub(crate) fn submit_blocking_many<E: ExecutorPlatform>(jobs: &[Job]) {
    E::submit_blocking_many(jobs);
}

pub fn yield_now<E: ExecutorPlatform>() {
    let _suspend = crate::platform::ExecutorSuspendGuard::<E>::enter();
    E::yield_now();
}

pub extern "C" fn try_steal_blocking_one<E: ExecutorPlatform>() -> bool {
    let _suspend = crate::platform::ExecutorSuspendGuard::<E>::enter();
    E::try_steal_blocking_one()
}

struct BlockOnWakeState {
    ready: AtomicBool,
    thread_state: Option<Arc<BlockOnThreadState>>,
    refs: AtomicUsize,
    retired_next: AtomicUsize,
}

unsafe fn release_block_on_wake_state<E: ExecutorPlatform, const NOTIFY: bool>(
    ptr: *mut BlockOnWakeState,
) {
    let state = unsafe { &*ptr };
    if state.refs.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    let retired = ptr.expose_provenance();
    let mut head = GlobalAsyncExecutor::<E>::global()
        .retired_block_on_states
        .load(Ordering::Relaxed);
    loop {
        state.retired_next.store(head, Ordering::Relaxed);
        match GlobalAsyncExecutor::<E>::global().retired_block_on_states.compare_exchange(
            head,
            retired,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                if NOTIFY && head == 0 {
                    GlobalAsyncExecutor::<E>::global().try_schedule::<true>();
                }
                return;
            }
            Err(actual) => head = actual,
        }
    }
}

pub(crate) fn has_retired_block_on_states<E: ExecutorPlatform>() -> bool {
    GlobalAsyncExecutor::<E>::global()
        .retired_block_on_states
        .load(Ordering::Acquire)
        != 0
}

#[cfg_attr(irq_check, irq::forbidden)]
pub(crate) fn drain_retired_block_on_states<E: ExecutorPlatform>() {
    if !has_retired_block_on_states::<E>() {
        return;
    }
    core::hint::cold_path();
    let mut retired = GlobalAsyncExecutor::<E>::global()
        .retired_block_on_states
        .swap(0, Ordering::Acquire);
    while retired != 0 {
        let state = unsafe {
            Box::from_raw(core::ptr::with_exposed_provenance_mut::<BlockOnWakeState>(
                retired,
            ))
        };
        retired = state.retired_next.load(Ordering::Relaxed);
        drop(state);
    }
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn block_on_waker_clone<E: ExecutorPlatform>(ptr: *const ()) -> RawWaker {
    let state = unsafe { &*ptr.cast::<BlockOnWakeState>() };
    let mut refs = state.refs.load(Ordering::Relaxed);
    loop {
        assert!(
            refs < isize::MAX as usize,
            "block_on waker reference count overflow"
        );
        match state
            .refs
            .compare_exchange(refs, refs + 1, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return RawWaker::new(ptr, &GlobalAsyncExecutor::<E>::BLOCK_ON_WAKER_VTABLE),
            Err(actual) => refs = actual,
        }
    }
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn block_on_waker_wake<E: ExecutorPlatform>(ptr: *const ()) {
    let ptr = ptr.cast::<BlockOnWakeState>().cast_mut();
    let state = unsafe { &*ptr };
    if let Some(thread_state) = &state.thread_state {
        thread_state.mark_ready();
    } else {
        state.ready.store(true, Ordering::Release);
    }
    unsafe { release_block_on_wake_state::<E, true>(ptr) };
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn block_on_waker_wake_by_ref<E: ExecutorPlatform>(ptr: *const ()) {
    let state = unsafe { &*ptr.cast::<BlockOnWakeState>() };
    if let Some(thread_state) = &state.thread_state {
        thread_state.mark_ready();
    } else {
        state.ready.store(true, Ordering::Release);
    }
}

#[cfg_attr(irq_check, irq::context)]
unsafe fn block_on_waker_drop<E: ExecutorPlatform>(ptr: *const ()) {
    unsafe { release_block_on_wake_state::<E, true>(ptr.cast::<BlockOnWakeState>().cast_mut()) };
}

impl<E: ExecutorPlatform> GlobalAsyncExecutor<E> {
    const BLOCK_ON_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        block_on_waker_clone::<E>,
        block_on_waker_wake::<E>,
        block_on_waker_wake_by_ref::<E>,
        block_on_waker_drop::<E>,
    );
}

#[cfg_attr(irq_check, irq::forbidden)]
pub fn block_on_waker<E: ExecutorPlatform>(thread_state: Option<Arc<BlockOnThreadState>>) -> Waker {
    let ptr = Box::into_raw(Box::new(BlockOnWakeState {
        ready: AtomicBool::new(false),
        thread_state,
        refs: AtomicUsize::new(1),
        retired_next: AtomicUsize::new(0),
    }));
    let raw = RawWaker::new(ptr.cast(), &GlobalAsyncExecutor::<E>::BLOCK_ON_WAKER_VTABLE);
    unsafe { Waker::from_raw(raw) }
}

pub fn block_on<E: ExecutorPlatform, F>(future: F) -> F::Output
where
    F: Future,
{
    let _suspend = crate::platform::ExecutorSuspendGuard::<E>::enter();
    let waker = block_on_waker::<E>(None);
    let ptr = waker.data().cast::<BlockOnWakeState>().cast_mut();
    let state = unsafe { &*ptr };
    let output = {
        let mut cx = Context::from_waker(&waker);
        let mut future = future;

        loop {
            let poll = unsafe { Pin::new_unchecked(&mut future) }.poll(&mut cx);
            drain_retired_block_on_states::<E>();
            match poll {
                Poll::Ready(v) => break v,
                Poll::Pending => {}
            }

            if !state.ready.swap(false, Ordering::AcqRel) && !try_steal_blocking_one::<E>() {
                yield_now::<E>();
            }
        }
    };
    let _waker = ManuallyDrop::new(waker);
    unsafe { release_block_on_wake_state::<E, false>(ptr) };
    drain_retired_block_on_states::<E>();
    output
}

pub struct JoinStorage<T> {
    output: UnsafeCell<MaybeUninit<TaskOutcome<T>>>,
    _pin: core::marker::PhantomPinned,
}

impl<T> JoinStorage<T> {
    pub const fn new() -> Self {
        Self {
            output: UnsafeCell::new(MaybeUninit::uninit()),
            _pin: core::marker::PhantomPinned,
        }
    }

    pub(crate) unsafe fn write(&self, output: TaskOutcome<T>) {
        unsafe {
            (*self.output.get()).write(output);
        }
    }

    unsafe fn take(&self) -> TaskOutcome<T> {
        unsafe { (*self.output.get()).assume_init_read() }
    }

    unsafe fn drop_output(&self) {
        unsafe {
            (*self.output.get()).assume_init_drop();
        }
    }
}

unsafe impl<T: Send> Send for JoinStorage<T> {}
unsafe impl<T: Send> Sync for JoinStorage<T> {}

pub fn spawn<'a, E: ExecutorPlatform, F, T>(
    storage: Pin<&'a mut JoinStorage<T>>,
    future: F,
) -> JoinHandle<'a, T, E>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    spawn_in_executor_domain::<E, _, _>(
        crate::global_async::KERNEL_NORMAL_EXECUTOR_DOMAIN,
        storage,
        future,
    )
}

fn reserve_future<E: ExecutorPlatform, F>(
    future: F,
    refs: u32,
) -> (FutureAllocation, SlotHandle, &'static TaskSlot) {
    let allocation =
        FutureAllocation::allocate(core::mem::size_of::<F>(), core::mem::align_of::<F>())
            .expect("future heap allocation failed");
    unsafe { allocation.ptr.as_ptr().cast::<F>().write(future) };
    let slab = get_task_table::<E>();
    let (slot_handle, slot) = match slab.allocate_with_refs(refs) {
        Some(reserved) => reserved,
        None => unsafe {
            release_unpublished_future::<F>(allocation);
            panic!("task table allocation failed");
        },
    };
    (allocation, slot_handle, slot)
}

pub fn spawn_in_executor_domain<'a, E: ExecutorPlatform, F, T>(
    domain_id: ExecutorDomainId,
    storage: Pin<&'a mut JoinStorage<T>>,
    future: F,
) -> JoinHandle<'a, T, E>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    assert!(
        !E::in_interrupt_context(),
        "attempted to spawn a task from interrupt context"
    );
    let storage_ptr = unsafe { storage.get_unchecked_mut() as *mut JoinStorage<T> };
    GlobalAsyncExecutor::<E>::global()
        .with_executor_domain(domain_id, |domain| {
            if domain.state() != crate::domain::ExecutorDomainState::Active {
                return None;
            }
            let (allocation, slot_handle, slot) = reserve_future::<E, _>(future, 3);

            let (shard_idx, local_idx, generation) = slot_handle.indices();

            unsafe { slot.init_joinable::<F, T>(domain_id, allocation, storage_ptr) };

            let encoded = slot_handle.encoded_ptr();
            GlobalAsyncExecutor::<E>::global().enqueue_task::<true, false>(domain, encoded, slot);

            Some(JoinHandle {
                shard_idx: shard_idx as u8,
                local_idx: local_idx as u32,
                generation,
                consumed: false,
                slot: Some(slot),
                storage: storage_ptr,
                _marker: PhantomData,
            })
        })
        .flatten()
        .unwrap_or(JoinHandle {
            shard_idx: 0,
            local_idx: 0,
            generation: 0,
            consumed: false,
            slot: None,
            storage: storage_ptr,
            _marker: PhantomData,
        })
}

pub struct JoinHandle<'a, T: Send + 'static, E: ExecutorPlatform> {
    shard_idx: u8,
    local_idx: u32,
    generation: u32,
    consumed: bool,
    slot: Option<&'static TaskSlot>,
    storage: *mut JoinStorage<T>,
    _marker: PhantomData<(&'a mut JoinStorage<T>, fn() -> E)>,
}

unsafe impl<T: Send + 'static, E: ExecutorPlatform> Send for JoinHandle<'_, T, E> {}

impl<T: Send + 'static, E: ExecutorPlatform> Future for JoinHandle<'_, T, E> {
    type Output = TaskOutcome<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if this.consumed {
            panic!("JoinHandle polled after completion");
        }
        let Some(slot) = this.slot else {
            this.consumed = true;
            return Poll::Ready(TaskOutcome::Cancelled);
        };

        if slot.is_completed() {
            let result = unsafe { (&*this.storage).take() };

            unsafe {
                get_task_table::<E>().decrement_owned_refs(
                    slot,
                    this.shard_idx as usize,
                    this.local_idx as usize,
                    this.generation,
                    1,
                );
            }

            this.consumed = true;
            Poll::Ready(result)
        } else {
            slot.update_join_waker(cx.waker());

            if slot.is_completed() {
                let result = unsafe { (&*this.storage).take() };

                unsafe {
                    get_task_table::<E>().decrement_owned_refs(
                        slot,
                        this.shard_idx as usize,
                        this.local_idx as usize,
                        this.generation,
                        1,
                    );
                }

                this.consumed = true;
                Poll::Ready(result)
            } else {
                Poll::Pending
            }
        }
    }
}

impl<T: Send + 'static, E: ExecutorPlatform> Drop for JoinHandle<'_, T, E> {
    fn drop(&mut self) {
        if !self.consumed && let Some(slot) = self.slot {
            let slab = get_task_table::<E>();
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
            unsafe {
                slab.decrement_owned_refs(
                    slot,
                    self.shard_idx as usize,
                    self.local_idx as usize,
                    self.generation,
                    1,
                );
            }
        }
    }
}

#[repr(align(64))]
struct OwnedJoinStorage<T>(JoinStorage<T>);

pub struct OwnedJoinHandle<T: Send + 'static, E: ExecutorPlatform> {
    handle: JoinHandle<'static, T, E>,
    _storage: Pin<Box<OwnedJoinStorage<T>>>,
}

impl<T: Send + 'static, E: ExecutorPlatform> Future for OwnedJoinHandle<T, E> {
    type Output = TaskOutcome<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut this.handle) }.poll(cx)
    }
}

#[doc(hidden)]
pub fn spawn_join_owned<E: ExecutorPlatform, F, T>(future: F) -> OwnedJoinHandle<T, E>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    spawn_join_owned_in_executor_domain::<E, _, _>(
        crate::global_async::KERNEL_NORMAL_EXECUTOR_DOMAIN,
        future,
    )
}

#[doc(hidden)]
pub fn spawn_join_owned_in_executor_domain<E: ExecutorPlatform, F, T>(
    domain_id: ExecutorDomainId,
    future: F,
) -> OwnedJoinHandle<T, E>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut storage = Box::pin(OwnedJoinStorage(JoinStorage::new()));
    let storage_ref = unsafe {
        core::mem::transmute::<Pin<&mut JoinStorage<T>>, Pin<&'static mut JoinStorage<T>>>(
            storage.as_mut().map_unchecked_mut(|storage| &mut storage.0),
        )
    };
    let handle = spawn_in_executor_domain::<E, _, _>(domain_id, storage_ref, future);
    OwnedJoinHandle {
        handle,
        _storage: storage,
    }
}

pub fn spawn_detached<E: ExecutorPlatform, F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_detached_in_executor_domain::<E, _>(
        crate::global_async::KERNEL_NORMAL_EXECUTOR_DOMAIN,
        future,
    );
}

pub fn spawn_detached_in_executor_domain<E: ExecutorPlatform, F>(
    domain_id: ExecutorDomainId,
    future: F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    assert!(
        !E::in_interrupt_context(),
        "attempted to spawn a task from interrupt context"
    );
    GlobalAsyncExecutor::<E>::global()
        .with_executor_domain(domain_id, |domain| {
            if domain.state() != crate::domain::ExecutorDomainState::Active {
                return;
            }
            let (allocation, slot_handle, slot) = reserve_future::<E, _>(future, 2);
            unsafe { slot.init_detached::<F>(domain_id, allocation) };

            let encoded = slot_handle.encoded_ptr();
            GlobalAsyncExecutor::<E>::global().enqueue_task::<true, false>(domain, encoded, slot);
        })
        .unwrap_or(())
}

unsafe fn release_unpublished_future<F>(allocation: FutureAllocation) {
    unsafe {
        core::ptr::drop_in_place(allocation.ptr.as_ptr().cast::<F>());
        allocation.release();
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
    DomainClosing,
    InterruptContext,
    FutureAllocationFailed,
    TaskAllocationFailed,
}

pub fn try_spawn_to_port_in_executor_domain<E: ExecutorPlatform, F, P, T>(
    domain_id: ExecutorDomainId,
    make_future: impl FnOnce() -> F,
    completion_key: u64,
    permit: P,
    poll_inline: bool,
    on_spawn: impl FnOnce(TaskToken),
) -> Result<TaskToken, SpawnToPortError>
where
    F: Future<Output = T> + Send + 'static,
    P: CompletionPermit<T>,
    T: Send + 'static,
{
    if E::in_interrupt_context() {
        return Err(SpawnToPortError::InterruptContext);
    }
    GlobalAsyncExecutor::<E>::global()
        .with_executor_domain(domain_id, |domain| {
            if domain.state() != crate::domain::ExecutorDomainState::Active {
                return Err(SpawnToPortError::DomainClosing);
            }
            let allocation = FutureAllocation::allocate(
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
                        future: make_future(),
                        permit: Some(permit),
                        key: completion_key,
                        token: 0,
                        completed: false,
                        _output: PhantomData,
                    });
            }
            let slab = get_task_table::<E>();
            let Some((handle, slot)) = slab.allocate_with_refs(2) else {
                unsafe { release_unpublished_future::<PortFuture<F, P, T>>(allocation) };
                return Err(SpawnToPortError::TaskAllocationFailed);
            };
            let Some(token) = TaskToken::from_raw(handle.encoded_ptr()) else {
                unsafe { release_unpublished_future::<PortFuture<F, P, T>>(allocation) };
                return Err(SpawnToPortError::TaskAllocationFailed);
            };
            unsafe { (*allocation.ptr.as_ptr().cast::<PortFuture<F, P, T>>()).token = token.raw() };
            unsafe { slot.init_detached::<PortFuture<F, P, T>>(domain_id, allocation) };
            on_spawn(token);
            if poll_inline {
                GlobalAsyncExecutor::<E>::global().enqueue_task::<true, true>(
                    domain,
                    handle.encoded_ptr(),
                    slot,
                );
            } else {
                GlobalAsyncExecutor::<E>::global().enqueue_task::<true, false>(
                    domain,
                    handle.encoded_ptr(),
                    slot,
                );
            }
            Ok(token)
        })
        .ok_or(SpawnToPortError::InvalidDomain)?
}

pub fn abort_task<E: ExecutorPlatform>(token: TaskToken) -> bool {
    let Some((shard, local, generation)) = super::slab::ptr::decode_slab_task_ptr(token.raw())
    else {
        return false;
    };
    let slab = get_task_table::<E>();
    if !slab.increment_ref(shard, local, generation) {
        return false;
    }
    let result = slab
        .get_slot(shard, local, generation)
        .is_some_and(|slot| slot.request_abort());
    if result {
        super::slab::ptr::enqueue_slab_task::<E>(shard, local, generation);
    }
    slab.decrement_ref::<false>(shard, local, generation);
    result
}
