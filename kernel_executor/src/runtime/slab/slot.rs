use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use crate::sync::spin_loop;

use super::super::runtime::submit_global;
use super::super::task::{
    STATE_COMPLETED, STATE_IDLE, STATE_NOTIFIED, STATE_POLLING, STATE_QUEUED,
};
use super::ptr::{
    encode_joinable_slab_ptr, encode_slab_ptr, joinable_slab_poll_trampoline, slab_poll_trampoline,
};
use super::storage::{drop_inline, FutureStorage};
use super::task_slab::get_task_slab;
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

pub(super) trait SlabSlot: Sized {
    fn new() -> Self;
    fn gen_ref(&self) -> &AtomicU32;
    fn state(&self) -> &AtomicU8;
    fn cached_waker_state(&self) -> &AtomicU8;
    fn cached_waker(&self) -> &UnsafeCell<MaybeUninit<Waker>>;
    fn create_waker(shard_idx: usize, local_idx: usize, generation: u32) -> Waker;
    fn prepare_for_allocation(&self);
    fn release_last_ref(&self);

    #[inline]
    fn reset_cached_waker(&self) {
        self.cached_waker_state().store(CW_NONE, Ordering::Relaxed);
    }

    #[inline]
    fn drop_cached_waker_if_set(&self) {
        let s = self.cached_waker_state().load(Ordering::Acquire);
        if s == CW_SET {
            unsafe {
                core::ptr::drop_in_place((*self.cached_waker().get()).as_mut_ptr());
            }
        }
        self.cached_waker_state().store(CW_NONE, Ordering::Release);
    }

    fn get_cached_waker(&self, shard_idx: usize, local_idx: usize, generation: u32) -> Waker {
        loop {
            let s = self.cached_waker_state().load(Ordering::Acquire);
            if s == CW_SET {
                return unsafe { (*self.cached_waker().get()).assume_init_ref().clone() };
            }
            if s == CW_UPDATING {
                spin_loop();
                continue;
            }
            if self
                .cached_waker_state()
                .compare_exchange(CW_NONE, CW_UPDATING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            let w = Self::create_waker(shard_idx, local_idx, generation);
            unsafe {
                (*self.cached_waker().get()).write(w.clone());
            }
            self.cached_waker_state().store(CW_SET, Ordering::Release);
            return w;
        }
    }

    #[inline]
    fn is_completed(&self) -> bool {
        self.state().load(Ordering::Acquire) == STATE_COMPLETED
    }

    #[inline]
    fn try_enqueue(&self) -> bool {
        self.state()
            .compare_exchange(
                STATE_IDLE,
                STATE_QUEUED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    fn try_notify_result(&self) -> NotifyResult {
        match self.state().compare_exchange(
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
}

#[repr(C, align(64))]
pub struct TaskSlot {
    pub(super) gen_ref: AtomicU32,
    pub(super) state: AtomicU8,
    pub(super) cached_waker_state: AtomicU8,
    pub(super) _pad: [u8; 2],
    pub(super) cached_waker: UnsafeCell<MaybeUninit<Waker>>,
    pub(super) future: UnsafeCell<Option<FutureStorage>>,
}

unsafe impl Sync for TaskSlot {}

impl TaskSlot {
    pub(super) fn new() -> Self {
        Self {
            gen_ref: AtomicU32::new(0),
            state: AtomicU8::new(STATE_IDLE),
            cached_waker_state: AtomicU8::new(CW_NONE),
            _pad: [0; 2],
            cached_waker: UnsafeCell::new(MaybeUninit::uninit()),
            future: UnsafeCell::new(None),
        }
    }

    #[inline]
    pub fn init(&self, future: impl Future<Output = ()> + Send + 'static) {
        unsafe { *self.future.get() = Some(FutureStorage::new(future)) };
        self.state.store(STATE_QUEUED, Ordering::Release);
    }

    #[inline]
    pub fn get_cached_waker(&self, shard_idx: usize, local_idx: usize, generation: u32) -> Waker {
        <Self as SlabSlot>::get_cached_waker(self, shard_idx, local_idx, generation)
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

        let future_ref = unsafe { &mut *self.future.get() };

        let poll_res = {
            let Some(fut) = future_ref.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return true;
            };
            fut.poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            unsafe { *self.future.get() = None };
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return true;
        }

        let prev = self.state.compare_exchange(
            STATE_POLLING,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if let Err(STATE_NOTIFIED) = prev {
            self.state.store(STATE_QUEUED, Ordering::Release);
            let slab = get_task_slab();
            slab.increment_ref(shard_idx, local_idx, generation);
            let encoded = encode_slab_ptr(shard_idx as u8, local_idx as u16, generation);
            submit_global(slab_poll_trampoline, encoded);
        }

        false
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        <Self as SlabSlot>::is_completed(self)
    }

    #[inline]
    pub fn try_enqueue(&self) -> bool {
        <Self as SlabSlot>::try_enqueue(self)
    }

    #[inline]
    pub fn try_notify_result(&self) -> NotifyResult {
        <Self as SlabSlot>::try_notify_result(self)
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

impl SlabSlot for TaskSlot {
    fn new() -> Self {
        TaskSlot::new()
    }

    #[inline]
    fn gen_ref(&self) -> &AtomicU32 {
        &self.gen_ref
    }

    #[inline]
    fn state(&self) -> &AtomicU8 {
        &self.state
    }

    #[inline]
    fn cached_waker_state(&self) -> &AtomicU8 {
        &self.cached_waker_state
    }

    #[inline]
    fn cached_waker(&self) -> &UnsafeCell<MaybeUninit<Waker>> {
        &self.cached_waker
    }

    #[inline]
    fn create_waker(shard_idx: usize, local_idx: usize, generation: u32) -> Waker {
        super::super::waker::create_slab_waker(shard_idx, local_idx, generation)
    }

    #[inline]
    fn prepare_for_allocation(&self) {
        self.state.store(STATE_IDLE, Ordering::Relaxed);
        <Self as SlabSlot>::reset_cached_waker(self);
        unsafe { *self.future.get() = None };
    }

    #[inline]
    fn release_last_ref(&self) {
        unsafe { *self.future.get() = None };
        <Self as SlabSlot>::drop_cached_waker_if_set(self);
        self.state.store(STATE_IDLE, Ordering::Release);
    }
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
pub(super) struct JoinableStorage {
    data: MaybeUninit<[u8; JOINABLE_STORAGE_SIZE]>,
}

impl JoinableStorage {
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

type JoinablePollFn = for<'cx> unsafe fn(&JoinableSlot, &mut Context<'cx>) -> bool;
type JoinableDropFn = unsafe fn(*mut u8);

#[inline]
fn read_poll_fn(c: &UnsafeCell<Option<JoinablePollFn>>) -> Option<JoinablePollFn> {
    unsafe { *c.get() }
}

#[inline]
fn write_poll_fn(c: &UnsafeCell<Option<JoinablePollFn>>, v: Option<JoinablePollFn>) {
    unsafe { *c.get() = v }
}

#[inline]
fn read_drop_fn(c: &UnsafeCell<Option<JoinableDropFn>>) -> Option<JoinableDropFn> {
    unsafe { *c.get() }
}

#[inline]
fn write_drop_fn(c: &UnsafeCell<Option<JoinableDropFn>>, v: Option<JoinableDropFn>) {
    unsafe { *c.get() = v }
}

#[repr(C, align(64))]
pub struct JoinableSlot {
    pub(super) gen_ref: AtomicU32,
    pub(super) state: AtomicU8,
    pub(super) waker_state: AtomicU8,
    pub(super) cached_waker_state: AtomicU8,
    pub(super) _pad: u8,
    pub(super) poll_fn: UnsafeCell<Option<JoinablePollFn>>,
    pub(super) drop_fn: UnsafeCell<Option<JoinableDropFn>>,
    pub(super) result_drop_fn: UnsafeCell<Option<JoinableDropFn>>,
    pub(super) join_waker: UnsafeCell<MaybeUninit<Waker>>,
    pub(super) cached_waker: UnsafeCell<MaybeUninit<Waker>>,
    pub(super) buffer: UnsafeCell<JoinableStorage>,
}

unsafe impl Sync for JoinableSlot {}

impl JoinableSlot {
    pub(super) fn new() -> Self {
        Self {
            gen_ref: AtomicU32::new(0),
            state: AtomicU8::new(STATE_IDLE),
            waker_state: AtomicU8::new(WAKER_NONE),
            cached_waker_state: AtomicU8::new(CW_NONE),
            _pad: 0,
            poll_fn: UnsafeCell::new(None),
            drop_fn: UnsafeCell::new(None),
            result_drop_fn: UnsafeCell::new(None),
            join_waker: UnsafeCell::new(MaybeUninit::uninit()),
            cached_waker: UnsafeCell::new(MaybeUninit::uninit()),
            buffer: UnsafeCell::new(JoinableStorage::new()),
        }
    }

    pub unsafe fn init_joinable<F, T>(&self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let size = core::mem::size_of::<F>();
        let align = core::mem::align_of::<F>();

        let result_size = core::mem::size_of::<T>();
        let result_align = core::mem::align_of::<T>();
        // TODO: temp fix because the result is written to a fixed size buffer
        if result_size > JOINABLE_STORAGE_SIZE || result_align > INLINE_FUTURE_ALIGN {
            panic!(
                "Joinable task result type {} (size {}, align {}) exceeds slab limits (max size {}, max align {})",
                core::any::type_name::<T>(),
                result_size,
                result_align,
                JOINABLE_STORAGE_SIZE,
                INLINE_FUTURE_ALIGN
            );
        }

        let buf_ptr = (*self.buffer.get()).as_mut_ptr();

        if size <= JOINABLE_STORAGE_SIZE && align <= INLINE_FUTURE_ALIGN {
            let ptr = buf_ptr as *mut F;
            core::ptr::write(ptr, future);
            write_poll_fn(&self.poll_fn, Some(poll_and_store_inline::<F, T>));
            write_drop_fn(&self.drop_fn, Some(drop_inline::<F>));
        } else {
            let boxed: Pin<Box<dyn Future<Output = T> + Send + 'static>> = Box::pin(future);
            let ptr = buf_ptr as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;
            core::ptr::write(ptr, Some(boxed));
            write_poll_fn(&self.poll_fn, Some(poll_and_store_boxed::<T>));
            write_drop_fn(&self.drop_fn, Some(drop_boxed_future::<T>));
        }

        write_drop_fn(&self.result_drop_fn, Some(drop_inline::<T>));

        self.waker_state.store(WAKER_NONE, Ordering::Release);
        self.cached_waker_state.store(CW_NONE, Ordering::Release);

        self.state.store(STATE_QUEUED, Ordering::Release);
    }

    pub fn poll_once_joinable(
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

        let is_ready = unsafe { poll_fn(self, &mut cx) };

        if is_ready {
            write_poll_fn(&self.poll_fn, None);
            self.state.store(STATE_COMPLETED, Ordering::Release);
            self.wake_join_handle();
            true
        } else {
            let prev = self.state.compare_exchange(
                STATE_POLLING,
                STATE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if let Err(STATE_NOTIFIED) = prev {
                self.state.store(STATE_QUEUED, Ordering::Release);
                let slab = get_task_slab();
                slab.increment_joinable_ref(shard_idx, local_idx, generation);
                let encoded =
                    encode_joinable_slab_ptr(shard_idx as u8, local_idx as u16, generation);
                submit_global(joinable_slab_poll_trampoline, encoded);
            }
            false
        }
    }

    pub unsafe fn take_result<T>(&self) -> T {
        debug_assert!(self.state.load(Ordering::Acquire) == STATE_COMPLETED);

        let ptr = (*self.buffer.get()).as_mut_ptr() as *mut T;
        let result = core::ptr::read(ptr);

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
        <Self as SlabSlot>::get_cached_waker(self, shard_idx, local_idx, generation)
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        <Self as SlabSlot>::is_completed(self)
    }

    #[inline]
    pub fn try_enqueue(&self) -> bool {
        <Self as SlabSlot>::try_enqueue(self)
    }

    #[inline]
    pub fn try_notify_result(&self) -> NotifyResult {
        <Self as SlabSlot>::try_notify_result(self)
    }
}

impl SlabSlot for JoinableSlot {
    fn new() -> Self {
        JoinableSlot::new()
    }

    #[inline]
    fn gen_ref(&self) -> &AtomicU32 {
        &self.gen_ref
    }

    #[inline]
    fn state(&self) -> &AtomicU8 {
        &self.state
    }

    #[inline]
    fn cached_waker_state(&self) -> &AtomicU8 {
        &self.cached_waker_state
    }

    #[inline]
    fn cached_waker(&self) -> &UnsafeCell<MaybeUninit<Waker>> {
        &self.cached_waker
    }

    #[inline]
    fn create_waker(shard_idx: usize, local_idx: usize, generation: u32) -> Waker {
        super::super::waker::create_joinable_slab_waker(shard_idx, local_idx, generation)
    }

    #[inline]
    fn prepare_for_allocation(&self) {
        self.state.store(STATE_IDLE, Ordering::Relaxed);
        self.waker_state.store(WAKER_NONE, Ordering::Relaxed);
        <Self as SlabSlot>::reset_cached_waker(self);
        write_poll_fn(&self.poll_fn, None);
        write_drop_fn(&self.drop_fn, None);
        write_drop_fn(&self.result_drop_fn, None);
    }

    #[inline]
    fn release_last_ref(&self) {
        if let Some(drop_fn) = read_drop_fn(&self.drop_fn) {
            unsafe { drop_fn((*self.buffer.get()).as_mut_ptr()) };
        }
        write_drop_fn(&self.drop_fn, None);

        <Self as SlabSlot>::drop_cached_waker_if_set(self);

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
    }
}

unsafe fn poll_and_store_inline<F, T>(slot: &JoinableSlot, cx: &mut Context<'_>) -> bool
where
    F: Future<Output = T>,
    T: Send + 'static,
{
    let buffer_ptr = (*slot.buffer.get()).as_mut_ptr();
    let future = &mut *(buffer_ptr as *mut F);
    let poll_res = Pin::new_unchecked(future).poll(cx);

    match poll_res {
        Poll::Ready(result) => {
            core::ptr::drop_in_place(buffer_ptr as *mut F);
            let result_ptr = buffer_ptr as *mut T;
            core::ptr::write(result_ptr, result);

            let result_drop = read_drop_fn(&slot.result_drop_fn);
            write_drop_fn(&slot.drop_fn, result_drop);

            true
        }
        Poll::Pending => false,
    }
}

unsafe fn poll_and_store_boxed<T>(slot: &JoinableSlot, cx: &mut Context<'_>) -> bool
where
    T: Send + 'static,
{
    let buffer_ptr = (*slot.buffer.get()).as_mut_ptr();
    let boxed_ptr = buffer_ptr as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;

    let poll_res = if let Some(fut) = (*boxed_ptr).as_mut() {
        fut.as_mut().poll(cx)
    } else {
        return true;
    };

    match poll_res {
        Poll::Ready(result) => {
            *boxed_ptr = None;

            let result_ptr = buffer_ptr as *mut T;
            core::ptr::write(result_ptr, result);

            let result_drop = read_drop_fn(&slot.result_drop_fn);
            write_drop_fn(&slot.drop_fn, result_drop);

            true
        }
        Poll::Pending => false,
    }
}

unsafe fn drop_boxed_future<T>(ptr: *mut u8) {
    let boxed_ptr = ptr as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;
    core::ptr::drop_in_place(boxed_ptr);
}
