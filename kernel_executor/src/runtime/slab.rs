use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::{align_of, MaybeUninit};
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, Waker};

use crate::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use crate::sync::spin_loop;
use spin::Once;

use super::runtime::submit_global;
use super::task::{STATE_COMPLETED, STATE_IDLE, STATE_NOTIFIED, STATE_POLLING, STATE_QUEUED};

const NUM_SHARDS: usize = 8;

const MIN_SLOTS_PER_SHARD: usize = 64;
const DEFAULT_SLOTS_PER_SHARD: usize = 128;
const MAX_SLOTS_PER_SHARD: usize = 4096;

const MIN_JOINABLE_SLOTS_PER_SHARD: usize = 32;
const DEFAULT_JOINABLE_SLOTS_PER_SHARD: usize = 64;
const MAX_JOINABLE_SLOTS_PER_SHARD: usize = 1024;

pub const INLINE_FUTURE_SIZE: usize = 5096;
pub const JOINABLE_STORAGE_SIZE: usize = 480;

pub const INLINE_FUTURE_ALIGN: usize = 8;

static TASK_SLAB_PTR: Once<&'static TaskSlab> = Once::new();
static mut TASK_SLAB_STORAGE: MaybeUninit<TaskSlab> = MaybeUninit::uninit();

#[repr(align(64))]
struct CachePadded<T>(T);

impl<T> CachePadded<T> {
    const fn new(v: T) -> Self {
        Self(v)
    }
}

impl<T> core::ops::Deref for CachePadded<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::DerefMut for CachePadded<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[repr(C, align(8))]
struct InlineFutureBuffer {
    data: MaybeUninit<[u8; INLINE_FUTURE_SIZE]>,
}

impl InlineFutureBuffer {
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

enum FutureStorage {
    Boxed(Pin<Box<dyn Future<Output = ()> + Send + 'static>>),
    Inline {
        storage: InlineFutureBuffer,
        poll_fn: unsafe fn(*mut u8, &mut Context<'_>) -> Poll<()>,
        drop_fn: unsafe fn(*mut u8),
    },
}

unsafe fn poll_inline<F>(ptr: *mut u8, cx: &mut Context<'_>) -> Poll<()>
where
    F: Future<Output = ()>,
{
    let future = &mut *(ptr as *mut F);
    Pin::new_unchecked(future).poll(cx)
}

unsafe fn drop_inline<F>(ptr: *mut u8) {
    core::ptr::drop_in_place(ptr as *mut F);
}

impl FutureStorage {
    fn new<F>(future: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let size = core::mem::size_of::<F>();
        let align = align_of::<F>();
        if size <= INLINE_FUTURE_SIZE && align <= INLINE_FUTURE_ALIGN {
            Self::new_inline(future)
        } else {
            Self::Boxed(Box::pin(future))
        }
    }

    fn new_inline<F>(future: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut storage = InlineFutureBuffer::new();

        debug_assert!(align_of::<F>() <= INLINE_FUTURE_ALIGN);

        unsafe {
            let ptr = storage.as_mut_ptr() as *mut F;
            core::ptr::write(ptr, future);
        }

        Self::Inline {
            storage,
            poll_fn: poll_inline::<F>,
            drop_fn: drop_inline::<F>,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            FutureStorage::Boxed(fut) => fut.as_mut().poll(cx),
            FutureStorage::Inline {
                storage, poll_fn, ..
            } => unsafe { poll_fn(storage.as_mut_ptr(), cx) },
        }
    }
}

impl Drop for FutureStorage {
    fn drop(&mut self) {
        if let FutureStorage::Inline {
            storage, drop_fn, ..
        } = self
        {
            unsafe { drop_fn(storage.as_mut_ptr()) }
        }
    }
}

#[derive(Clone, Copy)]
pub struct SlabConfig {
    pub slots_per_shard: usize,
    pub allow_fallback: bool,
}

impl Default for SlabConfig {
    fn default() -> Self {
        Self {
            slots_per_shard: DEFAULT_SLOTS_PER_SHARD,
            allow_fallback: true,
        }
    }
}

pub struct SlabConfigBuilder {
    config: SlabConfig,
}

impl Default for SlabConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SlabConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: SlabConfig::default(),
        }
    }

    pub fn capacity(mut self, total: usize) -> Self {
        self.config.slots_per_shard = total
            .div_ceil(NUM_SHARDS)
            .min(MAX_SLOTS_PER_SHARD)
            .max(MIN_SLOTS_PER_SHARD);
        self
    }

    pub fn slots_per_shard(mut self, slots: usize) -> Self {
        self.config.slots_per_shard =
            slots.min(MAX_SLOTS_PER_SHARD).max(MIN_SLOTS_PER_SHARD);
        self
    }

    pub fn fallback(mut self, enabled: bool) -> Self {
        self.config.allow_fallback = enabled;
        self
    }

    pub fn build(self) -> SlabConfig {
        self.config
    }
}

#[derive(Debug, Clone)]
pub struct SlabStats {
    pub total_capacity: usize,
    pub currently_allocated: usize,
    pub total_allocations: u64,
    pub fallback_allocations: u64,
}

const GEN_SHIFT: u32 = 16;
const REF_MASK: u32 = 0xFFFF;
const GEN_MASK: u32 = 0xFFFF;

#[inline]
fn pack_gen_ref(generation: u32, ref_count: u32) -> u32 {
    ((generation & GEN_MASK) << GEN_SHIFT) | (ref_count & REF_MASK)
}

#[inline]
fn unpack_gen(packed: u32) -> u32 {
    (packed >> GEN_SHIFT) & GEN_MASK
}

#[inline]
fn unpack_ref(packed: u32) -> u32 {
    packed & REF_MASK
}

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

trait SlabSlot: Sized {
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
    gen_ref: AtomicU32,
    state: AtomicU8,
    cached_waker_state: AtomicU8,
    _pad: [u8; 2],
    cached_waker: UnsafeCell<MaybeUninit<Waker>>,
    future: UnsafeCell<Option<FutureStorage>>,
}

unsafe impl Sync for TaskSlot {}

impl TaskSlot {
    fn new() -> Self {
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
        super::waker::create_slab_waker(shard_idx, local_idx, generation)
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

const WAKER_NONE: u8 = 0;
const WAKER_UPDATING: u8 = 1;
const WAKER_SET: u8 = 2;
const WAKER_TAKEN: u8 = 3;

enum JoinWakeStep {
    Wake(Waker),
    WaitForUpdate,
    NoWaker,
}

#[repr(C, align(8))]
struct JoinableStorage {
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
    gen_ref: AtomicU32,
    state: AtomicU8,
    waker_state: AtomicU8,
    cached_waker_state: AtomicU8,
    _pad: u8,
    poll_fn: UnsafeCell<Option<JoinablePollFn>>,
    drop_fn: UnsafeCell<Option<JoinableDropFn>>,
    result_drop_fn: UnsafeCell<Option<JoinableDropFn>>,
    join_waker: UnsafeCell<MaybeUninit<Waker>>,
    cached_waker: UnsafeCell<MaybeUninit<Waker>>,
    buffer: UnsafeCell<JoinableStorage>,
}

unsafe impl Sync for JoinableSlot {}

impl JoinableSlot {
    fn new() -> Self {
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

    fn wake_join_handle(&self) {
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
        super::waker::create_joinable_slab_waker(shard_idx, local_idx, generation)
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

struct SlotShard<S, const MIN_SLOTS: usize, const MAX_SLOTS: usize> {
    free_bitmap: Box<[AtomicU64]>,
    alloc_hint: CachePadded<AtomicUsize>,
    slots: Box<[S]>,
    active_slots: usize,
    allocated_count: CachePadded<AtomicUsize>,
}

impl<S, const MIN_SLOTS: usize, const MAX_SLOTS: usize> SlotShard<S, MIN_SLOTS, MAX_SLOTS>
where
    S: SlabSlot,
{
    fn new(num_slots: usize) -> Self {
        let num_slots = num_slots.min(MAX_SLOTS).max(MIN_SLOTS);
        let num_words = num_slots.div_ceil(64);

        let mut bitmap = Vec::with_capacity(num_words);
        for _ in 0..num_words {
            bitmap.push(AtomicU64::new(0));
        }

        for i in 0..num_words {
            let slots_in_word = if i == num_words - 1 {
                let rem = num_slots % 64;
                if rem == 0 {
                    64
                } else {
                    rem
                }
            } else {
                64
            };

            let mask = if slots_in_word == 64 {
                !0u64
            } else {
                (1u64 << slots_in_word) - 1
            };

            bitmap[i].store(mask, Ordering::Relaxed);
        }

        let mut slots = Vec::with_capacity(num_slots);
        for _ in 0..num_slots {
            slots.push(S::new());
        }

        Self {
            free_bitmap: bitmap.into_boxed_slice(),
            alloc_hint: CachePadded::new(AtomicUsize::new(0)),
            slots: slots.into_boxed_slice(),
            active_slots: num_slots,
            allocated_count: CachePadded::new(AtomicUsize::new(0)),
        }
    }

    fn try_allocate(&self) -> Option<usize> {
        let hint = self.alloc_hint.load(Ordering::Relaxed);
        let num_words = self.free_bitmap.len();

        for offset in 0..num_words {
            let word_idx = (hint / 64 + offset) % num_words;
            let word = &self.free_bitmap[word_idx];

            loop {
                let bits = word.load(Ordering::Relaxed);
                if bits == 0 {
                    break;
                }

                let bit_idx = bits.trailing_zeros() as usize;
                let slot_idx = word_idx * 64 + bit_idx;

                if slot_idx >= self.active_slots {
                    break;
                }

                let mask = 1u64 << bit_idx;

                match word.compare_exchange_weak(
                    bits,
                    bits & !mask,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        self.alloc_hint.store(slot_idx + 1, Ordering::Relaxed);
                        self.allocated_count.fetch_add(1, Ordering::Relaxed);
                        return Some(slot_idx);
                    }
                    Err(_) => {
                        spin_loop();
                        continue;
                    }
                }
            }
        }

        None
    }

    fn deallocate(&self, slot_idx: usize) {
        if slot_idx >= self.active_slots {
            return;
        }

        let word_idx = slot_idx / 64;
        let bit_idx = slot_idx % 64;
        let mask = 1u64 << bit_idx;

        self.free_bitmap[word_idx].fetch_or(mask, Ordering::Relaxed);
        self.alloc_hint.store(slot_idx, Ordering::Relaxed);
        self.allocated_count.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    fn get_slot(&self, idx: usize) -> Option<&S> {
        if idx >= self.active_slots {
            return None;
        }
        Some(&self.slots[idx])
    }
}

type SlabShard = SlotShard<TaskSlot, MIN_SLOTS_PER_SHARD, MAX_SLOTS_PER_SHARD>;
type JoinableShard =
    SlotShard<JoinableSlot, MIN_JOINABLE_SLOTS_PER_SHARD, MAX_JOINABLE_SLOTS_PER_SHARD>;

pub struct TaskSlab {
    shards: [SlabShard; NUM_SHARDS],
    joinable_shards: [JoinableShard; NUM_SHARDS],
    config: SlabConfig,
    shard_counter: CachePadded<AtomicUsize>,
    total_allocations: AtomicU64,
    fallback_allocations: AtomicU64,
    joinable_allocations: AtomicU64,
    joinable_fallback_allocations: AtomicU64,
}

impl TaskSlab {
    fn init_in_place(dst: *mut TaskSlab, mut config: SlabConfig) {
        config.slots_per_shard = config
            .slots_per_shard
            .min(MAX_SLOTS_PER_SHARD)
            .max(MIN_SLOTS_PER_SHARD);

        let joinable_slots = (config.slots_per_shard / 2)
            .max(DEFAULT_JOINABLE_SLOTS_PER_SHARD)
            .min(MAX_JOINABLE_SLOTS_PER_SHARD);

        let mut shards: MaybeUninit<[SlabShard; NUM_SHARDS]> = MaybeUninit::uninit();
        let shards_ptr = shards.as_mut_ptr() as *mut SlabShard;

        let mut joinable_shards: MaybeUninit<[JoinableShard; NUM_SHARDS]> = MaybeUninit::uninit();
        let joinable_ptr = joinable_shards.as_mut_ptr() as *mut JoinableShard;

        unsafe {
            for i in 0..NUM_SHARDS {
                shards_ptr
                    .add(i)
                    .write(SlabShard::new(config.slots_per_shard));
                joinable_ptr
                    .add(i)
                    .write(JoinableShard::new(joinable_slots));
            }

            ptr::write(
                dst,
                TaskSlab {
                    shards: shards.assume_init(),
                    joinable_shards: joinable_shards.assume_init(),
                    config,
                    shard_counter: CachePadded::new(AtomicUsize::new(0)),
                    total_allocations: AtomicU64::new(0),
                    fallback_allocations: AtomicU64::new(0),
                    joinable_allocations: AtomicU64::new(0),
                    joinable_fallback_allocations: AtomicU64::new(0),
                },
            );
        }
    }

    fn allocate_in<S, const MIN_SLOTS: usize, const MAX_SLOTS: usize>(
        &self,
        shards: &[SlotShard<S, MIN_SLOTS, MAX_SLOTS>; NUM_SHARDS],
        allocations: &AtomicU64,
    ) -> Option<(u8, u16, u32)>
    where
        S: SlabSlot,
    {
        let start_shard = self.shard_hint();

        for offset in 0..NUM_SHARDS {
            let shard_idx = (start_shard + offset) % NUM_SHARDS;
            let shard = &shards[shard_idx];

            if let Some(local_idx) = shard.try_allocate() {
                let slot = shard.get_slot(local_idx)?;
                slot.prepare_for_allocation();

                let old = slot.gen_ref().load(Ordering::Acquire);
                let new_gen = (unpack_gen(old).wrapping_add(1)) & GEN_MASK;
                slot.gen_ref()
                    .store(pack_gen_ref(new_gen, 1), Ordering::Release);

                allocations.fetch_add(1, Ordering::Relaxed);

                return Some((shard_idx as u8, local_idx as u16, new_gen));
            }
        }

        None
    }

    #[inline]
    fn get_slot_in<'a, S, const MIN_SLOTS: usize, const MAX_SLOTS: usize>(
        shards: &'a [SlotShard<S, MIN_SLOTS, MAX_SLOTS>; NUM_SHARDS],
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> Option<&'a S>
    where
        S: SlabSlot,
    {
        if shard_idx >= NUM_SHARDS {
            return None;
        }
        let slot = shards[shard_idx].get_slot(local_idx)?;
        let packed = slot.gen_ref().load(Ordering::Acquire);
        if unpack_gen(packed) != (expected_gen & GEN_MASK) {
            return None;
        }
        Some(slot)
    }

    fn increment_ref_in<S, const MIN_SLOTS: usize, const MAX_SLOTS: usize>(
        shards: &[SlotShard<S, MIN_SLOTS, MAX_SLOTS>; NUM_SHARDS],
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> bool
    where
        S: SlabSlot,
    {
        if shard_idx >= NUM_SHARDS {
            return false;
        }

        let shard = &shards[shard_idx];
        let Some(slot) = shard.get_slot(local_idx) else {
            return false;
        };

        let expected_gen = expected_gen & GEN_MASK;

        loop {
            let cur = slot.gen_ref().load(Ordering::Acquire);

            if unpack_gen(cur) != expected_gen {
                return false;
            }

            let rc = unpack_ref(cur);

            if rc == 0 || rc >= REF_MASK {
                return false;
            }

            let new = pack_gen_ref(expected_gen, rc + 1);

            match slot
                .gen_ref()
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(v) if unpack_gen(v) != expected_gen => return false,
                Err(_) => {
                    spin_loop();
                }
            }
        }
    }

    fn decrement_ref_in<S, const MIN_SLOTS: usize, const MAX_SLOTS: usize>(
        shards: &[SlotShard<S, MIN_SLOTS, MAX_SLOTS>; NUM_SHARDS],
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) where
        S: SlabSlot,
    {
        if shard_idx >= NUM_SHARDS {
            return;
        }

        let shard = &shards[shard_idx];
        let Some(slot) = shard.get_slot(local_idx) else {
            return;
        };

        let expected_gen = expected_gen & GEN_MASK;
        loop {
            let cur = slot.gen_ref().load(Ordering::Acquire);
            if unpack_gen(cur) != expected_gen {
                return;
            }
            let rc = unpack_ref(cur);
            if rc == 0 {
                return;
            }
            let new = pack_gen_ref(expected_gen, rc - 1);
            match slot
                .gen_ref()
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if rc == 1 {
                        slot.release_last_ref();
                        shard.deallocate(local_idx);
                    }
                    return;
                }
                Err(v) if unpack_gen(v) != expected_gen => return,
                Err(_) => {
                    spin_loop();
                    continue;
                }
            }
        }
    }

    pub fn allocate(&self) -> Option<SlotHandle<'_>> {
        let (shard_idx, local_idx, generation) =
            self.allocate_in(&self.shards, &self.total_allocations)?;

        Some(SlotHandle {
            slab: self,
            shard_idx,
            local_idx,
            generation,
        })
    }

    pub fn record_fallback(&self) {
        self.fallback_allocations.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn get_slot(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> Option<&TaskSlot> {
        Self::get_slot_in(&self.shards, shard_idx, local_idx, expected_gen)
    }

    pub fn increment_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) -> bool {
        Self::increment_ref_in(&self.shards, shard_idx, local_idx, expected_gen)
    }

    pub fn decrement_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) {
        Self::decrement_ref_in(&self.shards, shard_idx, local_idx, expected_gen);
    }

    pub fn allocate_joinable(&self) -> Option<JoinableSlotHandle<'_>> {
        let (shard_idx, local_idx, generation) =
            self.allocate_in(&self.joinable_shards, &self.joinable_allocations)?;

        Some(JoinableSlotHandle {
            slab: self,
            shard_idx,
            local_idx,
            generation,
        })
    }

    pub fn record_joinable_fallback(&self) {
        self.joinable_fallback_allocations
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn get_joinable_slot(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> Option<&JoinableSlot> {
        Self::get_slot_in(&self.joinable_shards, shard_idx, local_idx, expected_gen)
    }

    pub fn increment_joinable_ref(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> bool {
        Self::increment_ref_in(&self.joinable_shards, shard_idx, local_idx, expected_gen)
    }

    pub fn decrement_joinable_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) {
        Self::decrement_ref_in(&self.joinable_shards, shard_idx, local_idx, expected_gen);
    }

    #[inline]
    fn shard_hint(&self) -> usize {
        self.shard_counter.fetch_add(1, Ordering::Relaxed) % NUM_SHARDS
    }

    pub fn stats(&self) -> SlabStats {
        let allocated: usize = self
            .shards
            .iter()
            .map(|s| s.allocated_count.load(Ordering::Relaxed))
            .sum();

        SlabStats {
            total_capacity: self.config.slots_per_shard * NUM_SHARDS,
            currently_allocated: allocated,
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            fallback_allocations: self.fallback_allocations.load(Ordering::Relaxed),
        }
    }

    #[inline]
    pub fn allows_fallback(&self) -> bool {
        self.config.allow_fallback
    }
}

pub struct SlotHandle<'a> {
    slab: &'a TaskSlab,
    shard_idx: u8,
    local_idx: u16,
    generation: u32,
}

impl<'a> SlotHandle<'a> {
    pub fn init_and_enqueue(self, future: impl Future<Output = ()> + Send + 'static) {
        let shard = &self.slab.shards[self.shard_idx as usize];
        if let Some(slot) = shard.get_slot(self.local_idx as usize) {
            slot.init(future);

            self.slab.increment_ref(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            );

            let encoded = encode_slab_ptr(self.shard_idx, self.local_idx, self.generation);
            submit_global(slab_poll_trampoline, encoded);
        }
    }

    #[inline]
    pub fn encoded_ptr(&self) -> usize {
        encode_slab_ptr(self.shard_idx, self.local_idx, self.generation)
    }

    #[inline]
    pub fn indices(&self) -> (usize, usize, u32) {
        (
            self.shard_idx as usize,
            self.local_idx as usize,
            self.generation,
        )
    }
}

pub struct JoinableSlotHandle<'a> {
    slab: &'a TaskSlab,
    pub shard_idx: u8,
    pub local_idx: u16,
    pub generation: u32,
}

impl<'a> JoinableSlotHandle<'a> {
    pub fn init_and_enqueue<F, T>(self, future: F) -> (u8, u16, u32)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let shard = &self.slab.joinable_shards[self.shard_idx as usize];
        if let Some(slot) = shard.get_slot(self.local_idx as usize) {
            unsafe { slot.init_joinable(future) };

            self.slab.increment_joinable_ref(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            );

            self.slab.increment_joinable_ref(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            );

            let encoded = encode_joinable_slab_ptr(self.shard_idx, self.local_idx, self.generation);
            submit_global(joinable_slab_poll_trampoline, encoded);
        }

        (self.shard_idx, self.local_idx, self.generation)
    }

    #[inline]
    pub fn encoded_ptr(&self) -> usize {
        encode_joinable_slab_ptr(self.shard_idx, self.local_idx, self.generation)
    }

    #[inline]
    pub fn indices(&self) -> (usize, usize, u32) {
        (
            self.shard_idx as usize,
            self.local_idx as usize,
            self.generation,
        )
    }
}

const PTR_TAG_DETACHED: usize = 0b01;
const PTR_TAG_JOINABLE: usize = 0b11;

const PTR_SHARD_BITS: usize = 3;
const PTR_LOCAL_BITS: usize = 12;
const PTR_GEN_BITS: usize = 16;

const PTR_SHARD_SHIFT: usize = 2;
const PTR_LOCAL_SHIFT: usize = PTR_SHARD_SHIFT + PTR_SHARD_BITS;
const PTR_GEN_SHIFT: usize = PTR_LOCAL_SHIFT + PTR_LOCAL_BITS;

const PTR_SHARD_MASK: usize = (1usize << PTR_SHARD_BITS) - 1;
const PTR_LOCAL_MASK: usize = (1usize << PTR_LOCAL_BITS) - 1;
const PTR_GEN_MASK: usize = (1usize << PTR_GEN_BITS) - 1;

#[inline]
fn encode_slab_ptr_tag<const TAG: usize>(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let shard_bits = ((shard_idx as usize) & PTR_SHARD_MASK) << PTR_SHARD_SHIFT;
    let local_bits = ((local_idx as usize) & PTR_LOCAL_MASK) << PTR_LOCAL_SHIFT;
    let gen_bits = ((generation as usize) & PTR_GEN_MASK) << PTR_GEN_SHIFT;
    gen_bits | local_bits | shard_bits | TAG
}

#[inline]
fn decode_slab_ptr_tag<const TAG: usize>(ptrv: usize) -> Option<(usize, usize, u32)> {
    if (ptrv & 0b11) != TAG {
        return None;
    }
    let shard_idx = (ptrv >> PTR_SHARD_SHIFT) & PTR_SHARD_MASK;
    let local_idx = (ptrv >> PTR_LOCAL_SHIFT) & PTR_LOCAL_MASK;
    let generation = ((ptrv >> PTR_GEN_SHIFT) & PTR_GEN_MASK) as u32;

    Some((shard_idx, local_idx, generation))
}

#[inline]
pub fn encode_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    encode_slab_ptr_tag::<PTR_TAG_DETACHED>(shard_idx, local_idx, generation)
}

#[inline]
pub fn decode_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    decode_slab_ptr_tag::<PTR_TAG_DETACHED>(ptrv)
}

#[inline]
pub fn encode_joinable_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    encode_slab_ptr_tag::<PTR_TAG_JOINABLE>(shard_idx, local_idx, generation)
}

#[inline]
pub fn decode_joinable_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    decode_slab_ptr_tag::<PTR_TAG_JOINABLE>(ptrv)
}

#[inline]
#[allow(dead_code)]
pub fn is_slab_ptr(ptrv: usize) -> bool {
    (ptrv & 0b01) != 0
}

#[inline]
#[allow(dead_code)]
pub fn is_joinable_slab_ptr(ptrv: usize) -> bool {
    (ptrv & 0b11) == PTR_TAG_JOINABLE
}

trait SlabTaskKind {
    type Slot: SlabSlot;

    const TRAMPOLINE: extern "win64" fn(usize);

    fn encode(shard_idx: u8, local_idx: u16, generation: u32) -> usize;
    fn decode(ctx: usize) -> Option<(usize, usize, u32)>;
    fn get_slot(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> Option<&Self::Slot>;
    fn increment_ref(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool;
    fn decrement_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32);
    fn poll_once(
        slot: &Self::Slot,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool;
}

struct DetachedSlabTask;

impl SlabTaskKind for DetachedSlabTask {
    type Slot = TaskSlot;

    const TRAMPOLINE: extern "win64" fn(usize) = slab_poll_trampoline;

    #[inline]
    fn encode(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
        encode_slab_ptr(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decode(ctx: usize) -> Option<(usize, usize, u32)> {
        decode_slab_ptr(ctx)
    }

    #[inline]
    fn get_slot(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> Option<&TaskSlot> {
        slab.get_slot(shard_idx, local_idx, generation)
    }

    #[inline]
    fn increment_ref(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        slab.increment_ref(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decrement_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32) {
        slab.decrement_ref(shard_idx, local_idx, generation);
    }

    #[inline]
    fn poll_once(
        slot: &TaskSlot,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        slot.poll_once(waker, shard_idx, local_idx, generation)
    }
}

struct JoinableSlabTask;

impl SlabTaskKind for JoinableSlabTask {
    type Slot = JoinableSlot;

    const TRAMPOLINE: extern "win64" fn(usize) = joinable_slab_poll_trampoline;

    #[inline]
    fn encode(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
        encode_joinable_slab_ptr(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decode(ctx: usize) -> Option<(usize, usize, u32)> {
        decode_joinable_slab_ptr(ctx)
    }

    #[inline]
    fn get_slot(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> Option<&JoinableSlot> {
        slab.get_joinable_slot(shard_idx, local_idx, generation)
    }

    #[inline]
    fn increment_ref(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        slab.increment_joinable_ref(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decrement_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32) {
        slab.decrement_joinable_ref(shard_idx, local_idx, generation);
    }

    #[inline]
    fn poll_once(
        slot: &JoinableSlot,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        slot.poll_once_joinable(waker, shard_idx, local_idx, generation)
    }
}

#[inline(always)]
fn poll_slab_task<K>(ctx: usize)
where
    K: SlabTaskKind,
{
    let Some((shard_idx, local_idx, generation)) = K::decode(ctx) else {
        return;
    };

    let slab = get_task_slab();
    let Some(slot) = K::get_slot(slab, shard_idx, local_idx, generation) else {
        return;
    };

    let waker = slot.get_cached_waker(shard_idx, local_idx, generation);

    let completed = K::poll_once(slot, &waker, shard_idx, local_idx, generation);

    K::decrement_ref(slab, shard_idx, local_idx, generation);

    if completed {
        K::decrement_ref(slab, shard_idx, local_idx, generation);
    }
}

#[inline(always)]
fn enqueue_slab_task_inner<K>(shard_idx: usize, local_idx: usize, generation: u32)
where
    K: SlabTaskKind,
{
    let slab = get_task_slab();

    if !K::increment_ref(slab, shard_idx, local_idx, generation) {
        return;
    }

    let Some(slot) = K::get_slot(slab, shard_idx, local_idx, generation) else {
        K::decrement_ref(slab, shard_idx, local_idx, generation);
        return;
    };

    loop {
        if slot.try_enqueue() {
            let encoded = K::encode(shard_idx as u8, local_idx as u16, generation);
            submit_global(K::TRAMPOLINE, encoded);
            return;
        }

        match slot.try_notify_result() {
            NotifyResult::Notified | NotifyResult::AlreadyQueued | NotifyResult::Completed => {
                K::decrement_ref(slab, shard_idx, local_idx, generation);
                return;
            }
            NotifyResult::IdleRace => {
                spin_loop();
            }
        }
    }
}

#[inline(never)]
pub extern "win64" fn slab_poll_trampoline(ctx: usize) {
    poll_slab_task::<DetachedSlabTask>(ctx);
}

pub fn enqueue_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    enqueue_slab_task_inner::<DetachedSlabTask>(shard_idx, local_idx, generation);
}

#[inline(never)]
pub extern "win64" fn joinable_slab_poll_trampoline(ctx: usize) {
    poll_slab_task::<JoinableSlabTask>(ctx);
}

pub fn enqueue_joinable_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    enqueue_slab_task_inner::<JoinableSlabTask>(shard_idx, local_idx, generation);
}
pub fn init_task_slab(config: SlabConfig) {
    TASK_SLAB_PTR.call_once(|| unsafe {
        let p = core::ptr::addr_of_mut!(TASK_SLAB_STORAGE).cast::<TaskSlab>();
        TaskSlab::init_in_place(p, config);
        &*p
    });
}

pub fn init_task_slab_with<F>(f: F)
where
    F: FnOnce(SlabConfigBuilder) -> SlabConfigBuilder,
{
    let config = f(SlabConfigBuilder::new()).build();
    init_task_slab(config);
}

pub fn get_task_slab() -> &'static TaskSlab {
    TASK_SLAB_PTR.call_once(|| unsafe {
        let p = core::ptr::addr_of_mut!(TASK_SLAB_STORAGE).cast::<TaskSlab>();
        TaskSlab::init_in_place(p, SlabConfig::default());
        &*p
    })
}

pub fn slab_stats() -> SlabStats {
    get_task_slab().stats()
}

#[cfg(all(test, any(loom, feature = "loom")))]
mod tests {
    use super::*;
    use crate::sync::exhaustive_model;
    use core::mem::ManuallyDrop;
    use core::task::{RawWaker, RawWakerVTable, Waker};

    struct ModelWakeCounter {
        wakes: crate::sync::atomic::AtomicUsize,
    }

    unsafe fn clone_model_waker(ptr: *const ()) -> RawWaker {
        let arc =
            ManuallyDrop::new(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
        let cloned = std::sync::Arc::clone(&arc);
        RawWaker::new(
            std::sync::Arc::into_raw(cloned).cast::<()>(),
            &MODEL_WAKER_VTABLE,
        )
    }

    unsafe fn wake_model_waker(ptr: *const ()) {
        let arc = unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) };
        arc.wakes
            .fetch_add(1, crate::sync::atomic::Ordering::AcqRel);
    }

    unsafe fn wake_model_waker_by_ref(ptr: *const ()) {
        let arc =
            ManuallyDrop::new(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
        arc.wakes
            .fetch_add(1, crate::sync::atomic::Ordering::AcqRel);
    }

    unsafe fn drop_model_waker(ptr: *const ()) {
        drop(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
    }

    static MODEL_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_model_waker,
        wake_model_waker,
        wake_model_waker_by_ref,
        drop_model_waker,
    );

    fn model_waker(counter: std::sync::Arc<ModelWakeCounter>) -> Waker {
        let raw = RawWaker::new(
            std::sync::Arc::into_raw(counter).cast::<()>(),
            &MODEL_WAKER_VTABLE,
        );
        unsafe { Waker::from_raw(raw) }
    }

    // Models the exact JoinableSlot lost-wakeup protocol with Loom-controlled
    // atomics. wake_join_handle must not return while another thread is between
    // WAKER_UPDATING and WAKER_SET.
    #[test]
    fn loom_joinable_wake_waits_for_in_progress_waker_update() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(JoinableSlot::new());
            let counter = std::sync::Arc::new(ModelWakeCounter {
                wakes: crate::sync::atomic::AtomicUsize::new(0),
            });
            let waker = model_waker(counter.clone());

            slot.waker_state
                .store(WAKER_UPDATING, crate::sync::atomic::Ordering::Release);

            let wake_slot = slot.clone();
            let wake_thread = loom::thread::spawn(move || {
                wake_slot.wake_join_handle();
            });

            let finish_slot = slot.clone();
            let finish_thread = loom::thread::spawn(move || {
                unsafe {
                    (*finish_slot.join_waker.get()).write(waker);
                }
                finish_slot
                    .waker_state
                    .store(WAKER_SET, crate::sync::atomic::Ordering::Release);
            });

            finish_thread.join().expect("waker install thread panicked");
            wake_thread.join().expect("wake thread panicked");

            assert_eq!(
                counter.wakes.load(crate::sync::atomic::Ordering::Acquire),
                1
            );
            assert_eq!(
                slot.waker_state
                    .load(crate::sync::atomic::Ordering::Acquire),
                WAKER_TAKEN
            );
        });
    }

    // Models the production JoinHandle poll race: the handle registers a waker
    // while task completion stores STATE_COMPLETED and wakes the handle. If the
    // poll path can still return Pending, exactly one completion wake is required.
    #[test]
    fn loom_joinable_pending_poll_gets_completion_wake() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(JoinableSlot::new());
            let counter = std::sync::Arc::new(ModelWakeCounter {
                wakes: crate::sync::atomic::AtomicUsize::new(0),
            });
            let returned_pending =
                crate::sync::Arc::new(crate::sync::atomic::AtomicBool::new(false));
            let waker = model_waker(counter.clone());

            let waiter_slot = slot.clone();
            let waiter_pending = returned_pending.clone();
            let waiter = loom::thread::spawn(move || {
                if !waiter_slot.is_completed() {
                    loom::thread::yield_now();
                    waiter_slot.update_join_waker(&waker);
                    loom::thread::yield_now();

                    if !waiter_slot.is_completed() {
                        waiter_pending.store(true, crate::sync::atomic::Ordering::Release);
                    }
                }
            });

            let complete_slot = slot.clone();
            let completer = loom::thread::spawn(move || {
                loom::thread::yield_now();
                complete_slot
                    .state
                    .store(STATE_COMPLETED, crate::sync::atomic::Ordering::Release);
                loom::thread::yield_now();
                complete_slot.wake_join_handle();
            });

            waiter.join().expect("join handle poll thread panicked");
            completer.join().expect("completion thread panicked");

            if returned_pending.load(crate::sync::atomic::Ordering::Acquire) {
                assert_eq!(
                    counter.wakes.load(crate::sync::atomic::Ordering::Acquire),
                    1
                );
                assert_eq!(
                    slot.waker_state
                        .load(crate::sync::atomic::Ordering::Acquire),
                    WAKER_TAKEN
                );
            }
        });
    }

    // Models the detached slab task wake-vs-pending-poll race. The caller's
    // IdleRace retry must convert a just-idled task into QUEUED instead of
    // losing the wake.
    #[test]
    fn loom_task_slot_notify_idle_race_requeues() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(TaskSlot::new());
            slot.state
                .store(STATE_POLLING, crate::sync::atomic::Ordering::Release);

            let poll_slot = slot.clone();
            let poller = loom::thread::spawn(move || {
                let prev = poll_slot.state.compare_exchange(
                    STATE_POLLING,
                    STATE_IDLE,
                    crate::sync::atomic::Ordering::AcqRel,
                    crate::sync::atomic::Ordering::Acquire,
                );

                if let Err(STATE_NOTIFIED) = prev {
                    poll_slot
                        .state
                        .store(STATE_QUEUED, crate::sync::atomic::Ordering::Release);
                }
            });

            let notify_slot = slot.clone();
            let notifier = loom::thread::spawn(move || loop {
                match notify_slot.try_notify_result() {
                    NotifyResult::Notified
                    | NotifyResult::AlreadyQueued
                    | NotifyResult::Completed => return,
                    NotifyResult::IdleRace => {
                        if notify_slot.try_enqueue() {
                            return;
                        }
                    }
                }
            });

            poller.join().expect("poller thread panicked");
            notifier.join().expect("notifier thread panicked");

            assert_eq!(
                slot.state.load(crate::sync::atomic::Ordering::Acquire),
                STATE_QUEUED
            );
        });
    }

    // Models the same wake-vs-pending-poll race for joinable slab slots, which
    // have their own slot type but must preserve the same no-lost-wake contract.
    #[test]
    fn loom_joinable_slot_notify_idle_race_requeues() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(JoinableSlot::new());
            slot.state
                .store(STATE_POLLING, crate::sync::atomic::Ordering::Release);

            let poll_slot = slot.clone();
            let poller = loom::thread::spawn(move || {
                let prev = poll_slot.state.compare_exchange(
                    STATE_POLLING,
                    STATE_IDLE,
                    crate::sync::atomic::Ordering::AcqRel,
                    crate::sync::atomic::Ordering::Acquire,
                );

                if let Err(STATE_NOTIFIED) = prev {
                    poll_slot
                        .state
                        .store(STATE_QUEUED, crate::sync::atomic::Ordering::Release);
                }
            });

            let notify_slot = slot.clone();
            let notifier = loom::thread::spawn(move || loop {
                match notify_slot.try_notify_result() {
                    NotifyResult::Notified
                    | NotifyResult::AlreadyQueued
                    | NotifyResult::Completed => return,
                    NotifyResult::IdleRace => {
                        if notify_slot.try_enqueue() {
                            return;
                        }
                    }
                }
            });

            poller.join().expect("poller thread panicked");
            notifier.join().expect("notifier thread panicked");

            assert_eq!(
                slot.state.load(crate::sync::atomic::Ordering::Acquire),
                STATE_QUEUED
            );
        });
    }
}
