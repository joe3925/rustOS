use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::future_arena::FutureAllocation;
use crate::global_async::{ExecutorDomainId, GlobalAsyncExecutor};
use crate::platform::{CurrentExecutorContext, CurrentExecutorContextGuard};
use crate::runtime::runtime::submit_global_to_executor_domain;
use crate::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};
use crate::sync::spin_loop;

use super::super::runtime::JoinStorage;
use super::super::task::{
    STATE_COMPLETED, STATE_IDLE, STATE_NOTIFIED, STATE_POLLING, STATE_QUEUED,
};
use super::ptr::encode_slab_task_ptr;
use super::storage::drop_inline;
use super::task_slab::get_task_table;

const CW_NONE: u8 = 0;
const CW_UPDATING: u8 = 1;
const CW_SET: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WakeAction {
    Enqueue,
    Represented,
    Completed,
}

pub(super) const WAKER_NONE: u8 = 0;
pub(super) const WAKER_UPDATING: u8 = 1;
pub(super) const WAKER_SET: u8 = 2;
pub(super) const WAKER_TAKEN: u8 = 3;

enum JoinWakeStep {
    Wake(Waker),
    WaitForUpdate,
    NoWaker,
}

type TaskPollFn = for<'cx> unsafe fn(&TaskSlot, &mut Context<'cx>) -> bool;
type TaskDropFn = unsafe fn(*mut u8);
type TaskCancelFn = unsafe fn(&TaskSlot, usize);
const CONTROL_ABORT_REQUESTED: u8 = 1;
pub(crate) const RESULT_ABANDONED: usize = 0;
pub(crate) const RESULT_CLAIMED: usize = usize::MAX;

#[inline]
fn read_poll_fn(c: &UnsafeCell<Option<TaskPollFn>>) -> Option<TaskPollFn> {
    unsafe { *c.get() }
}

#[inline]
fn write_poll_fn(c: &UnsafeCell<Option<TaskPollFn>>, v: Option<TaskPollFn>) {
    unsafe { *c.get() = v }
}

#[inline]
fn read_drop_fn(c: &UnsafeCell<Option<TaskDropFn>>) -> Option<TaskDropFn> {
    unsafe { *c.get() }
}

#[inline]
fn write_drop_fn(c: &UnsafeCell<Option<TaskDropFn>>, v: Option<TaskDropFn>) {
    unsafe { *c.get() = v }
}

#[repr(C, align(64))]
pub struct TaskSlot {
    pub(super) gen_ref: AtomicU32,
    pub(super) state: AtomicU8,
    pub(super) control: AtomicU8,
    pub(super) waker_state: AtomicU8,
    pub(super) cached_waker_state: AtomicU8,
    pub(super) _pad: u8,
    pub(crate) ready_next: AtomicUsize,
    pub(super) domain_id: UnsafeCell<Option<ExecutorDomainId>>,
    pub(super) future: UnsafeCell<Option<FutureAllocation>>,
    pub(super) poll_fn: UnsafeCell<Option<TaskPollFn>>,
    pub(super) drop_fn: UnsafeCell<Option<TaskDropFn>>,
    pub(super) cancel_fn: UnsafeCell<Option<TaskCancelFn>>,
    pub(crate) result_ptr: AtomicUsize,
    pub(super) join_waker: UnsafeCell<MaybeUninit<Waker>>,
    pub(super) cached_waker: UnsafeCell<MaybeUninit<Waker>>,
}

unsafe impl Sync for TaskSlot {}

impl TaskSlot {
    pub(super) fn new() -> Self {
        Self {
            gen_ref: AtomicU32::new(0),
            state: AtomicU8::new(STATE_IDLE),
            control: AtomicU8::new(0),
            waker_state: AtomicU8::new(WAKER_NONE),
            cached_waker_state: AtomicU8::new(CW_NONE),
            _pad: 0,
            ready_next: AtomicUsize::new(0),
            domain_id: UnsafeCell::new(None),
            future: UnsafeCell::new(None),
            poll_fn: UnsafeCell::new(None),
            drop_fn: UnsafeCell::new(None),
            cancel_fn: UnsafeCell::new(None),
            result_ptr: AtomicUsize::new(RESULT_ABANDONED),
            join_waker: UnsafeCell::new(MaybeUninit::uninit()),
            cached_waker: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline]
    pub(super) fn prepare_for_allocation(&self) {
        self.state.store(STATE_IDLE, Ordering::Relaxed);
        self.control.store(0, Ordering::Relaxed);
        self.waker_state.store(WAKER_NONE, Ordering::Relaxed);
        self.cached_waker_state.store(CW_NONE, Ordering::Relaxed);
        self.ready_next.store(0, Ordering::Relaxed);
        write_poll_fn(&self.poll_fn, None);
        write_drop_fn(&self.drop_fn, None);
        unsafe { *self.cancel_fn.get() = None };
        self.result_ptr.store(RESULT_ABANDONED, Ordering::Relaxed);
        unsafe {
            *self.domain_id.get() = None;
            *self.future.get() = None;
        }
    }

    #[inline]
    pub(super) fn release_last_ref(&self) {
        if let Some(drop_fn) = read_drop_fn(&self.drop_fn) {
            unsafe {
                if let Some(allocation) = (&mut *self.future.get()).take() {
                    drop_fn(allocation.ptr.as_ptr());
                    release_future_allocation(allocation);
                }
            };
        }
        write_drop_fn(&self.drop_fn, None);
        unsafe { *self.cancel_fn.get() = None };

        let cws = self.cached_waker_state.load(Ordering::Acquire);
        if cws == CW_SET {
            unsafe {
                core::ptr::drop_in_place((*self.cached_waker.get()).as_mut_ptr());
            }
        }
        self.cached_waker_state.store(CW_NONE, Ordering::Release);

        let ws = self.waker_state.load(Ordering::Acquire);
        if ws == WAKER_SET {
            unsafe {
                core::ptr::drop_in_place((*self.join_waker.get()).as_mut_ptr());
            }
        }
        self.waker_state.store(WAKER_NONE, Ordering::Release);

        write_poll_fn(&self.poll_fn, None);
        self.result_ptr.store(RESULT_ABANDONED, Ordering::Release);
        self.state.store(STATE_IDLE, Ordering::Release);
        self.ready_next.store(0, Ordering::Relaxed);
        if let Some(domain_id) = unsafe { (&mut *self.domain_id.get()).take() } {
            if let Some(domain) = GlobalAsyncExecutor::global().get_executor_domain(domain_id) {
                domain.release_task();
            }
        }
    }

    pub unsafe fn init_joinable<F, T>(
        &self,
        domain_id: ExecutorDomainId,
        allocation: FutureAllocation,
        result_ptr: *mut JoinStorage<T>,
    ) where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.result_ptr
            .store(result_ptr as usize, Ordering::Release);
        self.init_internal::<F, T>(domain_id, allocation, poll_joinable::<F, T>);
    }

    pub fn executor_domain_id(&self) -> Option<ExecutorDomainId> {
        unsafe { *self.domain_id.get() }
    }

    pub unsafe fn init_detached<F>(&self, domain_id: ExecutorDomainId, allocation: FutureAllocation)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.init_internal::<F, ()>(domain_id, allocation, poll_detached::<F>);
    }

    unsafe fn init_internal<F, T>(
        &self,
        domain_id: ExecutorDomainId,
        allocation: FutureAllocation,
        poll_fn: TaskPollFn,
    ) where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        *self.domain_id.get() = Some(domain_id);
        *self.future.get() = Some(allocation);
        write_poll_fn(&self.poll_fn, Some(poll_fn));
        write_drop_fn(&self.drop_fn, Some(drop_inline::<F>));

        self.waker_state.store(WAKER_NONE, Ordering::Release);
        self.cached_waker_state.store(CW_NONE, Ordering::Release);

        self.state.store(STATE_QUEUED, Ordering::Release);
    }

    pub fn poll_once(
        &self,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        let prev = self.state.compare_exchange(
            STATE_QUEUED,
            STATE_POLLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if prev.is_err() {
            return false;
        }

        let mut cx = Context::from_waker(waker);

        let Some(poll_fn) = read_poll_fn(&self.poll_fn) else {
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return true;
        };

        let domain_id =
            unsafe { *self.domain_id.get() }.expect("task domain missing while polling");
        let _context_guard = CurrentExecutorContextGuard::enter(CurrentExecutorContext {
            task_id: encode_slab_task_ptr(shard_idx as u8, local_idx as u16, generation),
            domain_id: domain_id.raw(),
        });
        if self.control.load(Ordering::Acquire) & CONTROL_ABORT_REQUESTED != 0 {
            if let Some(cancel) = unsafe { *self.cancel_fn.get() } {
                unsafe {
                    cancel(
                        self,
                        encode_slab_task_ptr(shard_idx as u8, local_idx as u16, generation),
                    )
                };
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return true;
            }
        }
        let is_ready = unsafe { poll_fn(self, &mut cx) };

        if is_ready {
            write_poll_fn(&self.poll_fn, None);
            self.state.store(STATE_COMPLETED, Ordering::Release);
            self.wake_join_handle();
            true
        } else {
            if self.control.load(Ordering::Acquire) & CONTROL_ABORT_REQUESTED != 0 {
                if let Some(cancel) = unsafe { *self.cancel_fn.get() } {
                    unsafe {
                        cancel(
                            self,
                            encode_slab_task_ptr(shard_idx as u8, local_idx as u16, generation),
                        )
                    };
                    self.state.store(STATE_COMPLETED, Ordering::Release);
                    return true;
                }
            }
            let prev = self.state.compare_exchange(
                STATE_POLLING,
                STATE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if let Err(STATE_NOTIFIED) = prev {
                self.state.store(STATE_QUEUED, Ordering::Release);
                let slab = get_task_table();
                slab.increment_ref(shard_idx, local_idx, generation);
                let encoded = encode_slab_task_ptr(shard_idx as u8, local_idx as u16, generation);
                submit_global_to_executor_domain(domain_id, encoded);
            }
            false
        }
    }

    pub unsafe fn init_abortable<F>(
        &self,
        domain_id: ExecutorDomainId,
        allocation: FutureAllocation,
    ) where
        F: Future<Output = ()> + Send + 'static,
    {
        self.init_detached::<F>(domain_id, allocation);
        *self.cancel_fn.get() = Some(cancel_future::<F>);
    }

    pub fn request_abort(&self) -> bool {
        if self.state.load(Ordering::Acquire) == STATE_COMPLETED {
            return false;
        }
        self.control
            .fetch_or(CONTROL_ABORT_REQUESTED, Ordering::AcqRel);
        true
    }

    pub fn set_join_waker(&self, waker: &Waker) {
        if self.state.load(Ordering::Acquire) == STATE_COMPLETED {
            return;
        }

        loop {
            let s = self.waker_state.load(Ordering::Acquire);
            if s == WAKER_TAKEN {
                return;
            }
            if s == WAKER_UPDATING {
                spin_loop();
                continue;
            }
            if self
                .waker_state
                .compare_exchange(s, WAKER_UPDATING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            unsafe {
                if s == WAKER_SET {
                    core::ptr::drop_in_place((*self.join_waker.get()).as_mut_ptr());
                }
                (*self.join_waker.get()).write(waker.clone());
            }

            self.waker_state.store(WAKER_SET, Ordering::Release);
            break;
        }

        if self.state.load(Ordering::Acquire) == STATE_COMPLETED {
            self.wake_join_handle();
        }
    }

    pub fn update_join_waker(&self, waker: &Waker) {
        if self.state.load(Ordering::Acquire) == STATE_COMPLETED {
            return;
        }

        loop {
            let s = self.waker_state.load(Ordering::Acquire);
            if s == WAKER_TAKEN {
                return;
            }
            if s == WAKER_UPDATING {
                spin_loop();
                continue;
            }
            if self
                .waker_state
                .compare_exchange(s, WAKER_UPDATING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            let mut should_write = true;

            if s == WAKER_SET {
                unsafe {
                    let current = (*self.join_waker.get()).assume_init_ref();
                    if current.will_wake(waker) {
                        should_write = false;
                    } else {
                        core::ptr::drop_in_place((*self.join_waker.get()).as_mut_ptr());
                    }
                }
            }

            if should_write {
                unsafe {
                    (*self.join_waker.get()).write(waker.clone());
                }
            }

            self.waker_state.store(WAKER_SET, Ordering::Release);
            break;
        }

        if self.state.load(Ordering::Acquire) == STATE_COMPLETED {
            self.wake_join_handle();
        }
    }

    fn take_join_waker_for_wake(&self) -> JoinWakeStep {
        match self.waker_state.compare_exchange(
            WAKER_SET,
            WAKER_TAKEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let waker = unsafe { (*self.join_waker.get()).assume_init_read() };
                JoinWakeStep::Wake(waker)
            }
            Err(WAKER_UPDATING) => JoinWakeStep::WaitForUpdate,
            Err(_) => JoinWakeStep::NoWaker,
        }
    }

    pub(super) fn wake_join_handle(&self) {
        loop {
            match self.take_join_waker_for_wake() {
                JoinWakeStep::Wake(waker) => {
                    waker.wake();
                    return;
                }
                JoinWakeStep::WaitForUpdate => spin_loop(),
                JoinWakeStep::NoWaker => return,
            }
        }
    }

    pub fn get_cached_waker(&self, shard_idx: usize, local_idx: usize, generation: u32) -> Waker {
        loop {
            let s = self.cached_waker_state.load(Ordering::Acquire);
            if s == CW_SET {
                return unsafe { (*self.cached_waker.get()).assume_init_ref().clone() };
            }
            if s == CW_UPDATING {
                spin_loop();
                continue;
            }
            if self
                .cached_waker_state
                .compare_exchange(CW_NONE, CW_UPDATING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            let w = super::super::waker::create_slab_task_waker(shard_idx, local_idx, generation);
            unsafe {
                (*self.cached_waker.get()).write(w.clone());
            }
            self.cached_waker_state.store(CW_SET, Ordering::Release);
            return w;
        }
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_COMPLETED
    }

    #[inline]
    pub fn record_wake(&self) -> WakeAction {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            let (next, action) = match state {
                STATE_IDLE => (STATE_QUEUED, WakeAction::Enqueue),
                STATE_POLLING => (STATE_NOTIFIED, WakeAction::Represented),
                STATE_QUEUED | STATE_NOTIFIED => return WakeAction::Represented,
                STATE_COMPLETED => return WakeAction::Completed,
                _ => unreachable!("invalid slab task state"),
            };

            // Never wait for a poller to finish: a failed strong CAS returns
            // a state that another CPU changed, and we dispatch from that.
            match self
                .state
                .compare_exchange(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return action,
                Err(actual) => state = actual,
            }
        }
    }

    #[inline]
    pub fn try_start_inline_poll(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_IDLE,
                STATE_POLLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

unsafe fn poll_joinable<F, T>(slot: &TaskSlot, cx: &mut Context<'_>) -> bool
where
    F: Future<Output = T>,
    T: Send + 'static,
{
    let allocation = (&mut *slot.future.get())
        .as_mut()
        .expect("task future allocation missing");
    let future = &mut *(allocation.ptr.as_ptr() as *mut F);
    let poll_res = Pin::new_unchecked(&mut *future).poll(cx);

    match poll_res {
        Poll::Ready(result) => {
            core::ptr::drop_in_place(future);
            let allocation = (&mut *slot.future.get())
                .take()
                .expect("task future allocation missing on completion");
            release_future_allocation(allocation);
            loop {
                let ptr = slot.result_ptr.load(Ordering::Acquire);
                if ptr == RESULT_ABANDONED {
                    drop(result);
                    break;
                }
                if ptr == RESULT_CLAIMED {
                    panic!("join result storage claimed twice");
                }
                if slot
                    .result_ptr
                    .compare_exchange(ptr, RESULT_CLAIMED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    (*(ptr as *mut JoinStorage<T>)).write(result);
                    break;
                }
            }
            true
        }
        Poll::Pending => false,
    }
}

unsafe fn poll_detached<F>(slot: &TaskSlot, cx: &mut Context<'_>) -> bool
where
    F: Future<Output = ()>,
{
    let allocation = (&mut *slot.future.get())
        .as_mut()
        .expect("task future allocation missing");
    let future = &mut *(allocation.ptr.as_ptr() as *mut F);
    match Pin::new_unchecked(&mut *future).poll(cx) {
        Poll::Ready(()) => {
            core::ptr::drop_in_place(future);
            let allocation = (&mut *slot.future.get())
                .take()
                .expect("task future allocation missing on completion");
            release_future_allocation(allocation);
            true
        }
        Poll::Pending => false,
    }
}

unsafe fn release_future_allocation(allocation: FutureAllocation) {
    let domain_id = allocation.owner_domain;
    let domain = GlobalAsyncExecutor::global()
        .get_executor_domain(domain_id)
        .expect("future owner domain disappeared while allocation was live");
    assert!(domain.future_arena().release(allocation));
    domain.maybe_finish_draining();
}

unsafe fn cancel_future<F>(slot: &TaskSlot, _token: usize) {
    if let Some(allocation) = (&mut *slot.future.get()).take() {
        core::ptr::drop_in_place(allocation.ptr.as_ptr().cast::<F>());
        release_future_allocation(allocation);
    }
    write_poll_fn(&slot.poll_fn, None);
    write_drop_fn(&slot.drop_fn, None);
    *slot.cancel_fn.get() = None;
}
