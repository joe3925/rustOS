use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::future_arena::FutureAllocation;
use crate::global_async::{ExecutorDomainId, GlobalAsyncExecutor};
use crate::platform::{CurrentExecutorContext, CurrentExecutorContextGuard};
use crate::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use crate::sync::spin_loop;

use super::super::runtime::submit_global;
use super::super::task::{
    STATE_COMPLETED, STATE_IDLE, STATE_NOTIFIED, STATE_POLLING, STATE_QUEUED,
};
use super::ptr::{encode_slab_task_ptr, slab_task_poll_trampoline};
use super::storage::drop_inline;
use super::task_slab::get_task_table;
use super::{INLINE_FUTURE_ALIGN, JOINABLE_STORAGE_SIZE};

const CW_NONE: u8 = 0;
const CW_UPDATING: u8 = 1;
const CW_SET: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NotifyResult {
    Notified,
    AlreadyQueued,
    IdleRace,
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

#[repr(C, align(8))]
pub(super) struct TaskStorage {
    data: MaybeUninit<[u8; JOINABLE_STORAGE_SIZE]>,
}

impl TaskStorage {
    const fn new() -> Self {
        Self {
            data: MaybeUninit::uninit(),
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr() as *mut u8
    }
}

type TaskPollFn = for<'cx> unsafe fn(&TaskSlot, &mut Context<'cx>) -> bool;
type TaskDropFn = unsafe fn(*mut u8);
type TaskCancelFn = unsafe fn(&TaskSlot, usize);
const CONTROL_ABORT_REQUESTED: u8 = 1;

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
    pub(super) domain_id: UnsafeCell<Option<ExecutorDomainId>>,
    pub(super) future: UnsafeCell<Option<FutureAllocation>>,
    pub(super) poll_fn: UnsafeCell<Option<TaskPollFn>>,
    pub(super) drop_fn: UnsafeCell<Option<TaskDropFn>>,
    pub(super) cancel_fn: UnsafeCell<Option<TaskCancelFn>>,
    pub(super) result_drop_fn: UnsafeCell<Option<TaskDropFn>>,
    pub(super) join_waker: UnsafeCell<MaybeUninit<Waker>>,
    pub(super) cached_waker: UnsafeCell<MaybeUninit<Waker>>,
    pub(super) buffer: UnsafeCell<TaskStorage>,
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
            domain_id: UnsafeCell::new(None),
            future: UnsafeCell::new(None),
            poll_fn: UnsafeCell::new(None),
            drop_fn: UnsafeCell::new(None),
            cancel_fn: UnsafeCell::new(None),
            result_drop_fn: UnsafeCell::new(None),
            join_waker: UnsafeCell::new(MaybeUninit::uninit()),
            cached_waker: UnsafeCell::new(MaybeUninit::uninit()),
            buffer: UnsafeCell::new(TaskStorage::new()),
        }
    }

    #[inline]
    pub(super) fn prepare_for_allocation(&self) {
        self.state.store(STATE_IDLE, Ordering::Relaxed);
        self.control.store(0, Ordering::Relaxed);
        self.waker_state.store(WAKER_NONE, Ordering::Relaxed);
        self.cached_waker_state.store(CW_NONE, Ordering::Relaxed);
        write_poll_fn(&self.poll_fn, None);
        write_drop_fn(&self.drop_fn, None);
        unsafe { *self.cancel_fn.get() = None };
        write_drop_fn(&self.result_drop_fn, None);
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
                } else {
                    drop_fn((*self.buffer.get()).as_mut_ptr());
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
        write_drop_fn(&self.result_drop_fn, None);
        self.state.store(STATE_IDLE, Ordering::Release);
        if let Some(domain_id) = unsafe { (&mut *self.domain_id.get()).take() } {
            if let Some(domain) = GlobalAsyncExecutor::global().get_executor_domain(domain_id) {
                domain.release_task();
            }
        }
    }

    pub unsafe fn init<F, T>(&self, domain_id: ExecutorDomainId, allocation: FutureAllocation)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let result_size = core::mem::size_of::<T>();
        let result_align = core::mem::align_of::<T>();

        if result_size > JOINABLE_STORAGE_SIZE || result_align > INLINE_FUTURE_ALIGN {
            self.init_internal::<F, T>(domain_id, allocation, poll_and_store_arena_boxed::<F, T>);
        } else {
            self.init_internal::<F, T>(domain_id, allocation, poll_and_store_arena::<F, T>);
        }
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

        write_drop_fn(&self.result_drop_fn, Some(drop_inline::<T>));

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
                submit_global(slab_task_poll_trampoline, encoded);
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
        self.init::<F, ()>(domain_id, allocation);
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

    pub unsafe fn take_result<T>(&self) -> T {
        debug_assert!(self.state.load(Ordering::Acquire) == STATE_COMPLETED);

        let result_size = core::mem::size_of::<T>();
        let result_align = core::mem::align_of::<T>();
        let ptr = (*self.buffer.get()).as_mut_ptr();

        let result = if result_size > JOINABLE_STORAGE_SIZE || result_align > INLINE_FUTURE_ALIGN {
            let boxed_ptr = ptr as *mut Box<T>;
            let boxed = core::ptr::read(boxed_ptr);
            *boxed
        } else {
            let result_ptr = ptr as *mut T;
            core::ptr::read(result_ptr)
        };

        write_drop_fn(&self.drop_fn, None);
        result
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
    pub fn try_enqueue(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_IDLE,
                STATE_QUEUED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub fn try_notify_result(&self) -> NotifyResult {
        match self.state.compare_exchange(
            STATE_POLLING,
            STATE_NOTIFIED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => NotifyResult::Notified,
            Err(STATE_IDLE) => NotifyResult::IdleRace,
            Err(STATE_QUEUED) => NotifyResult::AlreadyQueued,
            Err(STATE_NOTIFIED) => NotifyResult::AlreadyQueued,
            Err(STATE_COMPLETED) => NotifyResult::Completed,
            Err(_) => NotifyResult::IdleRace,
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

unsafe fn poll_and_store_arena<F, T>(slot: &TaskSlot, cx: &mut Context<'_>) -> bool
where
    F: Future<Output = T>,
    T: Send + 'static,
{
    let buffer_ptr = (*slot.buffer.get()).as_mut_ptr();
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
            let result_ptr = buffer_ptr as *mut T;
            core::ptr::write(result_ptr, result);

            let result_drop = read_drop_fn(&slot.result_drop_fn);
            write_drop_fn(&slot.drop_fn, result_drop);

            true
        }
        Poll::Pending => false,
    }
}

unsafe fn poll_and_store_arena_boxed<F, T>(slot: &TaskSlot, cx: &mut Context<'_>) -> bool
where
    F: Future<Output = T>,
    T: Send + 'static,
{
    let buffer_ptr = (*slot.buffer.get()).as_mut_ptr();
    let allocation = (&mut *slot.future.get())
        .as_mut()
        .expect("task future allocation missing");
    let future = &mut *(allocation.ptr.as_ptr() as *mut F);
    match Pin::new_unchecked(&mut *future).poll(cx) {
        Poll::Ready(result) => {
            core::ptr::drop_in_place(future);
            let allocation = (&mut *slot.future.get())
                .take()
                .expect("task future allocation missing on completion");
            release_future_allocation(allocation);
            core::ptr::write(buffer_ptr as *mut Box<T>, Box::new(result));
            write_drop_fn(&slot.drop_fn, Some(drop_inline::<Box<T>>));
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
