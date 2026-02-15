use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::hint::spin_loop;
use core::mem::{align_of, MaybeUninit};
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use spin::Once;

use super::runtime::submit_global;
use super::task::{STATE_COMPLETED, STATE_IDLE, STATE_NOTIFIED, STATE_POLLING, STATE_QUEUED};

const NUM_SHARDS: usize = 8;

const DEFAULT_SLOTS_PER_SHARD: usize = 128;
const MAX_SLOTS_PER_SHARD: usize = 4096;

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

impl SlabConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: SlabConfig::default(),
        }
    }

    pub fn capacity(mut self, total: usize) -> Self {
        self.config.slots_per_shard = ((total + NUM_SHARDS - 1) / NUM_SHARDS)
            .min(MAX_SLOTS_PER_SHARD)
            .max(64);
        self
    }

    pub fn slots_per_shard(mut self, slots: usize) -> Self {
        self.config.slots_per_shard = slots.min(MAX_SLOTS_PER_SHARD).max(64);
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
    const fn new() -> Self {
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
    fn reset_cached_waker(&self) {
        self.cached_waker_state.store(CW_NONE, Ordering::Relaxed);
    }

    #[inline]
    fn drop_cached_waker_if_set(&self) {
        let s = self.cached_waker_state.load(Ordering::Acquire);
        if s == CW_SET {
            unsafe {
                core::ptr::drop_in_place((*self.cached_waker.get()).as_mut_ptr());
            }
        }
        self.cached_waker_state.store(CW_NONE, Ordering::Release);
    }

    #[inline]
    pub fn init(&self, future: impl Future<Output = ()> + Send + 'static) {
        unsafe { *self.future.get() = Some(FutureStorage::new(future)) };
        self.state.store(STATE_QUEUED, Ordering::Release);
    }

    #[inline]
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

            let w = super::waker::create_slab_waker(shard_idx, local_idx, generation);
            unsafe {
                (*self.cached_waker.get()).write(w.clone());
            }
            self.cached_waker_state.store(CW_SET, Ordering::Release);
            return w;
        }
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

        if let Err(s) = prev {
            return s == STATE_COMPLETED;
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
    pub fn try_notify(&self) -> bool {
        match self.state.compare_exchange(
            STATE_POLLING,
            STATE_NOTIFIED,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => true,
            Err(STATE_IDLE) => false,
            Err(STATE_QUEUED) => true,
            Err(_) => true,
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

const WAKER_NONE: u8 = 0;
const WAKER_UPDATING: u8 = 1;
const WAKER_SET: u8 = 2;
const WAKER_TAKEN: u8 = 3;

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

#[inline]
fn read_cell_usize(c: &UnsafeCell<usize>) -> usize {
    unsafe { *c.get() }
}

#[inline]
fn write_cell_usize(c: &UnsafeCell<usize>, v: usize) {
    unsafe { *c.get() = v }
}

#[repr(C, align(64))]
pub struct JoinableSlot {
    gen_ref: AtomicU32,
    state: AtomicU8,
    waker_state: AtomicU8,
    cached_waker_state: AtomicU8,
    _pad: u8,
    poll_fn: UnsafeCell<usize>,
    drop_fn: UnsafeCell<usize>,
    result_drop_fn: UnsafeCell<usize>,
    join_waker: UnsafeCell<MaybeUninit<Waker>>,
    cached_waker: UnsafeCell<MaybeUninit<Waker>>,
    buffer: UnsafeCell<JoinableStorage>,
}

unsafe impl Sync for JoinableSlot {}

impl JoinableSlot {
    const fn new() -> Self {
        Self {
            gen_ref: AtomicU32::new(0),
            state: AtomicU8::new(STATE_IDLE),
            waker_state: AtomicU8::new(WAKER_NONE),
            cached_waker_state: AtomicU8::new(CW_NONE),
            _pad: 0,
            poll_fn: UnsafeCell::new(0),
            drop_fn: UnsafeCell::new(0),
            result_drop_fn: UnsafeCell::new(0),
            join_waker: UnsafeCell::new(MaybeUninit::uninit()),
            cached_waker: UnsafeCell::new(MaybeUninit::uninit()),
            buffer: UnsafeCell::new(JoinableStorage::new()),
        }
    }

    #[inline]
    fn reset_cached_waker(&self) {
        self.cached_waker_state.store(CW_NONE, Ordering::Relaxed);
    }

    #[inline]
    fn drop_cached_waker_if_set(&self) {
        let s = self.cached_waker_state.load(Ordering::Acquire);
        if s == CW_SET {
            unsafe {
                core::ptr::drop_in_place((*self.cached_waker.get()).as_mut_ptr());
            }
        }
        self.cached_waker_state.store(CW_NONE, Ordering::Release);
    }

    pub unsafe fn init_joinable<F, T>(&self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let size = core::mem::size_of::<F>();
        let align = core::mem::align_of::<F>();

        let buf_ptr = (*self.buffer.get()).as_mut_ptr();

        if size <= JOINABLE_STORAGE_SIZE && align <= INLINE_FUTURE_ALIGN {
            let ptr = buf_ptr as *mut F;
            core::ptr::write(ptr, future);
            write_cell_usize(&self.poll_fn, poll_and_store_inline::<F, T> as usize);
            write_cell_usize(&self.drop_fn, drop_inline::<F> as usize);
        } else {
            let boxed: Pin<Box<dyn Future<Output = T> + Send + 'static>> = Box::pin(future);
            let ptr = buf_ptr as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;
            core::ptr::write(ptr, Some(boxed));
            write_cell_usize(&self.poll_fn, poll_and_store_boxed::<T> as usize);
            write_cell_usize(&self.drop_fn, drop_boxed_future::<T> as usize);
        }

        write_cell_usize(&self.result_drop_fn, drop_inline::<T> as usize);

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

        if let Err(s) = prev {
            return s == STATE_COMPLETED;
        }

        let mut cx = Context::from_waker(waker);

        let poll_fn = read_cell_usize(&self.poll_fn);
        if poll_fn == 0 {
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return true;
        }

        let poll_fn: unsafe fn(&JoinableSlot, &mut Context<'_>) -> bool =
            unsafe { core::mem::transmute(poll_fn) };
        let is_ready = unsafe { poll_fn(self, &mut cx) };

        if is_ready {
            write_cell_usize(&self.poll_fn, 0);
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

        write_cell_usize(&self.drop_fn, 0);
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

    fn wake_join_handle(&self) {
        if self
            .waker_state
            .compare_exchange(WAKER_SET, WAKER_TAKEN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe {
                let waker = (*self.join_waker.get()).assume_init_read();
                waker.wake();
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

            let w = super::waker::create_joinable_slab_waker(shard_idx, local_idx, generation);
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
    pub fn try_notify(&self) -> bool {
        match self.state.compare_exchange(
            STATE_POLLING,
            STATE_NOTIFIED,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => true,
            Err(STATE_IDLE) => false,
            Err(STATE_QUEUED) => true,
            Err(_) => true,
        }
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

            let result_drop = read_cell_usize(&slot.result_drop_fn);
            write_cell_usize(&slot.drop_fn, result_drop);

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

            let result_drop = read_cell_usize(&slot.result_drop_fn);
            write_cell_usize(&slot.drop_fn, result_drop);

            true
        }
        Poll::Pending => false,
    }
}

unsafe fn drop_boxed_future<T>(ptr: *mut u8) {
    let boxed_ptr = ptr as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;
    core::ptr::drop_in_place(boxed_ptr);
}

struct SlabShard {
    free_bitmap: Box<[AtomicU64]>,
    alloc_hint: CachePadded<AtomicUsize>,
    slots: Box<[TaskSlot]>,
    active_slots: usize,
    allocated_count: CachePadded<AtomicUsize>,
}

impl SlabShard {
    fn new(num_slots: usize) -> Self {
        let num_slots = num_slots.min(MAX_SLOTS_PER_SHARD).max(64);
        let num_words = (num_slots + 63) / 64;

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
            slots.push(TaskSlot::new());
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
    fn get_slot(&self, idx: usize) -> Option<&TaskSlot> {
        if idx >= self.active_slots {
            return None;
        }
        Some(&self.slots[idx])
    }
}

struct JoinableShard {
    free_bitmap: Box<[AtomicU64]>,
    alloc_hint: CachePadded<AtomicUsize>,
    slots: Box<[JoinableSlot]>,
    active_slots: usize,
    allocated_count: CachePadded<AtomicUsize>,
}

impl JoinableShard {
    fn new(num_slots: usize) -> Self {
        let num_slots = num_slots.min(MAX_JOINABLE_SLOTS_PER_SHARD).max(32);
        let num_words = (num_slots + 63) / 64;

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
            slots.push(JoinableSlot::new());
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
    fn get_slot(&self, idx: usize) -> Option<&JoinableSlot> {
        if idx >= self.active_slots {
            return None;
        }
        Some(&self.slots[idx])
    }
}

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
        config.slots_per_shard = config.slots_per_shard.min(MAX_SLOTS_PER_SHARD).max(64);

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

    pub fn allocate(&self) -> Option<SlotHandle<'_>> {
        let start_shard = self.shard_hint();

        for offset in 0..NUM_SHARDS {
            let shard_idx = (start_shard + offset) % NUM_SHARDS;
            let shard = &self.shards[shard_idx];

            if let Some(local_idx) = shard.try_allocate() {
                let slot = shard.get_slot(local_idx)?;

                slot.state.store(STATE_IDLE, Ordering::Relaxed);
                slot.reset_cached_waker();
                unsafe { *slot.future.get() = None };

                let old = slot.gen_ref.load(Ordering::Acquire);
                let new_gen = (unpack_gen(old).wrapping_add(1)) & GEN_MASK;
                slot.gen_ref
                    .store(pack_gen_ref(new_gen, 1), Ordering::Release);

                self.total_allocations.fetch_add(1, Ordering::Relaxed);

                return Some(SlotHandle {
                    slab: self,
                    shard_idx: shard_idx as u8,
                    local_idx: local_idx as u16,
                    generation: new_gen,
                });
            }
        }

        None
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
        if shard_idx >= NUM_SHARDS {
            return None;
        }
        let slot = self.shards[shard_idx].get_slot(local_idx)?;
        let packed = slot.gen_ref.load(Ordering::Acquire);
        if unpack_gen(packed) != (expected_gen & GEN_MASK) {
            return None;
        }
        Some(slot)
    }

    pub fn increment_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) -> bool {
        if shard_idx >= NUM_SHARDS {
            return false;
        }
        let shard = &self.shards[shard_idx];
        let Some(slot) = shard.get_slot(local_idx) else {
            return false;
        };

        let expected_gen = expected_gen & GEN_MASK;
        loop {
            let cur = slot.gen_ref.load(Ordering::Acquire);
            if unpack_gen(cur) != expected_gen {
                return false;
            }
            let rc = unpack_ref(cur);
            if rc >= REF_MASK {
                return false;
            }
            let new = pack_gen_ref(expected_gen, rc + 1);
            match slot
                .gen_ref
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(v) if unpack_gen(v) != expected_gen => return false,
                Err(_) => {
                    spin_loop();
                    continue;
                }
            }
        }
    }

    pub fn decrement_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) {
        if shard_idx >= NUM_SHARDS {
            return;
        }

        let shard = &self.shards[shard_idx];
        let Some(slot) = shard.get_slot(local_idx) else {
            return;
        };

        let expected_gen = expected_gen & GEN_MASK;
        loop {
            let cur = slot.gen_ref.load(Ordering::Acquire);
            if unpack_gen(cur) != expected_gen {
                return;
            }
            let rc = unpack_ref(cur);
            if rc == 0 {
                return;
            }
            let new = pack_gen_ref(expected_gen, rc - 1);
            match slot
                .gen_ref
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if rc == 1 {
                        unsafe { *slot.future.get() = None };
                        slot.drop_cached_waker_if_set();
                        slot.state.store(STATE_IDLE, Ordering::Release);
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

    pub fn allocate_joinable(&self) -> Option<JoinableSlotHandle<'_>> {
        let start_shard = self.shard_hint();

        for offset in 0..NUM_SHARDS {
            let shard_idx = (start_shard + offset) % NUM_SHARDS;
            let shard = &self.joinable_shards[shard_idx];

            if let Some(local_idx) = shard.try_allocate() {
                let slot = shard.get_slot(local_idx)?;

                slot.state.store(STATE_IDLE, Ordering::Relaxed);
                slot.waker_state.store(WAKER_NONE, Ordering::Relaxed);
                slot.reset_cached_waker();
                write_cell_usize(&slot.poll_fn, 0);
                write_cell_usize(&slot.drop_fn, 0);
                write_cell_usize(&slot.result_drop_fn, 0);

                let old = slot.gen_ref.load(Ordering::Acquire);
                let new_gen = (unpack_gen(old).wrapping_add(1)) & GEN_MASK;
                slot.gen_ref
                    .store(pack_gen_ref(new_gen, 1), Ordering::Release);

                self.joinable_allocations.fetch_add(1, Ordering::Relaxed);

                return Some(JoinableSlotHandle {
                    slab: self,
                    shard_idx: shard_idx as u8,
                    local_idx: local_idx as u16,
                    generation: new_gen,
                });
            }
        }

        None
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
        if shard_idx >= NUM_SHARDS {
            return None;
        }
        let slot = self.joinable_shards[shard_idx].get_slot(local_idx)?;
        let packed = slot.gen_ref.load(Ordering::Acquire);
        if unpack_gen(packed) != (expected_gen & GEN_MASK) {
            return None;
        }
        Some(slot)
    }

    pub fn increment_joinable_ref(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> bool {
        if shard_idx >= NUM_SHARDS {
            return false;
        }
        let shard = &self.joinable_shards[shard_idx];
        let Some(slot) = shard.get_slot(local_idx) else {
            return false;
        };

        let expected_gen = expected_gen & GEN_MASK;
        loop {
            let cur = slot.gen_ref.load(Ordering::Acquire);
            if unpack_gen(cur) != expected_gen {
                return false;
            }
            let rc = unpack_ref(cur);
            if rc >= REF_MASK {
                return false;
            }
            let new = pack_gen_ref(expected_gen, rc + 1);
            match slot
                .gen_ref
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(v) if unpack_gen(v) != expected_gen => return false,
                Err(_) => {
                    spin_loop();
                    continue;
                }
            }
        }
    }

    pub fn decrement_joinable_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) {
        if shard_idx >= NUM_SHARDS {
            return;
        }

        let shard = &self.joinable_shards[shard_idx];
        let Some(slot) = shard.get_slot(local_idx) else {
            return;
        };

        let expected_gen = expected_gen & GEN_MASK;
        loop {
            let cur = slot.gen_ref.load(Ordering::Acquire);
            if unpack_gen(cur) != expected_gen {
                return;
            }
            let rc = unpack_ref(cur);
            if rc == 0 {
                return;
            }
            let new = pack_gen_ref(expected_gen, rc - 1);
            match slot
                .gen_ref
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if rc == 1 {
                        let drop_fn = read_cell_usize(&slot.drop_fn);
                        if drop_fn != 0 {
                            unsafe {
                                let f: unsafe fn(*mut u8) = core::mem::transmute(drop_fn);
                                f((*slot.buffer.get()).as_mut_ptr());
                            }
                        }
                        write_cell_usize(&slot.drop_fn, 0);

                        slot.drop_cached_waker_if_set();

                        let ws = slot.waker_state.load(Ordering::Acquire);
                        if ws == WAKER_SET {
                            unsafe {
                                core::ptr::drop_in_place((*slot.join_waker.get()).as_mut_ptr());
                            }
                        }
                        slot.waker_state.store(WAKER_NONE, Ordering::Release);

                        write_cell_usize(&slot.poll_fn, 0);
                        write_cell_usize(&slot.result_drop_fn, 0);
                        slot.state.store(STATE_IDLE, Ordering::Release);

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
pub fn encode_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let shard_bits = ((shard_idx as usize) & PTR_SHARD_MASK) << PTR_SHARD_SHIFT;
    let local_bits = ((local_idx as usize) & PTR_LOCAL_MASK) << PTR_LOCAL_SHIFT;
    let gen_bits = ((generation as usize) & PTR_GEN_MASK) << PTR_GEN_SHIFT;
    gen_bits | local_bits | shard_bits | PTR_TAG_DETACHED
}

#[inline]
pub fn decode_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    if (ptrv & 0b11) != PTR_TAG_DETACHED {
        return None;
    }
    let shard_idx = (ptrv >> PTR_SHARD_SHIFT) & PTR_SHARD_MASK;
    let local_idx = (ptrv >> PTR_LOCAL_SHIFT) & PTR_LOCAL_MASK;
    let generation = ((ptrv >> PTR_GEN_SHIFT) & PTR_GEN_MASK) as u32;

    if shard_idx >= NUM_SHARDS {
        return None;
    }
    Some((shard_idx, local_idx, generation))
}

#[inline]
pub fn encode_joinable_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let shard_bits = ((shard_idx as usize) & PTR_SHARD_MASK) << PTR_SHARD_SHIFT;
    let local_bits = ((local_idx as usize) & PTR_LOCAL_MASK) << PTR_LOCAL_SHIFT;
    let gen_bits = ((generation as usize) & PTR_GEN_MASK) << PTR_GEN_SHIFT;
    gen_bits | local_bits | shard_bits | PTR_TAG_JOINABLE
}

#[inline]
pub fn decode_joinable_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    if (ptrv & 0b11) != PTR_TAG_JOINABLE {
        return None;
    }
    let shard_idx = (ptrv >> PTR_SHARD_SHIFT) & PTR_SHARD_MASK;
    let local_idx = (ptrv >> PTR_LOCAL_SHIFT) & PTR_LOCAL_MASK;
    let generation = ((ptrv >> PTR_GEN_SHIFT) & PTR_GEN_MASK) as u32;

    if shard_idx >= NUM_SHARDS {
        return None;
    }
    Some((shard_idx, local_idx, generation))
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

#[inline(never)]
pub extern "win64" fn slab_poll_trampoline(ctx: usize) {
    let Some((shard_idx, local_idx, generation)) = decode_slab_ptr(ctx) else {
        return;
    };

    let slab = get_task_slab();
    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        return;
    };

    let waker = slot.get_cached_waker(shard_idx, local_idx, generation);

    let completed = slot.poll_once(&waker, shard_idx, local_idx, generation);

    slab.decrement_ref(shard_idx, local_idx, generation);

    if completed {
        slab.decrement_ref(shard_idx, local_idx, generation);
    }
}

pub fn enqueue_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    let slab = get_task_slab();
    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        return;
    };

    for _ in 0..2 {
        if slot.try_enqueue() {
            slab.increment_ref(shard_idx, local_idx, generation);
            let encoded = encode_slab_ptr(shard_idx as u8, local_idx as u16, generation);
            submit_global(slab_poll_trampoline, encoded);
            return;
        }

        if slot.try_notify() {
            return;
        }
    }
}

#[inline(never)]
pub extern "win64" fn joinable_slab_poll_trampoline(ctx: usize) {
    let Some((shard_idx, local_idx, generation)) = decode_joinable_slab_ptr(ctx) else {
        return;
    };

    let slab = get_task_slab();
    let Some(slot) = slab.get_joinable_slot(shard_idx, local_idx, generation) else {
        return;
    };

    let waker = slot.get_cached_waker(shard_idx, local_idx, generation);

    let completed = slot.poll_once_joinable(&waker, shard_idx, local_idx, generation);

    slab.decrement_joinable_ref(shard_idx, local_idx, generation);

    if completed {
        slab.decrement_joinable_ref(shard_idx, local_idx, generation);
    }
}

pub fn enqueue_joinable_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    let slab = get_task_slab();
    let Some(slot) = slab.get_joinable_slot(shard_idx, local_idx, generation) else {
        return;
    };

    for _ in 0..2 {
        if slot.try_enqueue() {
            slab.increment_joinable_ref(shard_idx, local_idx, generation);
            let encoded = encode_joinable_slab_ptr(shard_idx as u8, local_idx as u16, generation);
            submit_global(joinable_slab_poll_trampoline, encoded);
            return;
        }

        if slot.try_notify() {
            return;
        }
    }
}

pub fn init_task_slab(config: SlabConfig) {
    TASK_SLAB_PTR.call_once(|| unsafe {
        let p = TASK_SLAB_STORAGE.as_mut_ptr();
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
        let p = TASK_SLAB_STORAGE.as_mut_ptr();
        TaskSlab::init_in_place(p, SlabConfig::default());
        &*p
    })
}

pub fn slab_stats() -> SlabStats {
    get_task_slab().stats()
}
