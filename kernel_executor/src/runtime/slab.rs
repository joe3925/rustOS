use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
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

pub const INLINE_FUTURE_SIZE: usize = 512;
pub const JOINABLE_STORAGE_SIZE: usize = 480;

pub const INLINE_FUTURE_ALIGN: usize = 8;

const SLOT_FREE: u8 = 0;
const SLOT_ALLOCATED: u8 = 1;

static TASK_SLAB_PTR: Once<&'static TaskSlab> = Once::new();
static mut TASK_SLAB_STORAGE: MaybeUninit<TaskSlab> = MaybeUninit::uninit();

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
    // Safety: The future is pinned within the TaskSlot which doesn't move
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

        debug_assert!(
            align_of::<F>() <= INLINE_FUTURE_ALIGN,
            "inline future alignment exceeded"
        );

        // Safety: We've verified size and alignment requirements in the caller
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
            } => {
                // Safety: storage contains a valid F, properly aligned
                unsafe { poll_fn(storage.as_mut_ptr(), cx) }
            }
        }
    }
}

impl Drop for FutureStorage {
    fn drop(&mut self) {
        if let FutureStorage::Inline {
            storage, drop_fn, ..
        } = self
        {
            // Safety: storage contains a valid future that needs dropping
            unsafe { drop_fn(storage.as_mut_ptr()) }
        }
        // Boxed variant drops automatically
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

/// Packed generation (high 16 bits) + ref_count (low 16 bits) so that
/// increment/decrement can atomically verify the generation in a single CAS.
/// Refcount is managed only by structural anchor refs (enqueue/dequeue paths
/// and continuations), not by waker clone/drop. Typical peak is ~3-4 refs.
#[repr(C, align(64))]
pub struct TaskSlot {
    /// Layout: bits [31:16] = generation (16 bits), bits [15:0] = ref_count (16 bits)
    gen_ref: AtomicU32,
    state: AtomicU8,
    _pad: [u8; 3],
    /// Safety: exclusive access is guaranteed by the task state machine
    /// (only one thread can be in POLLING state) and by ref-count exclusivity
    /// (cleanup runs only when rc drops to 0).
    future: UnsafeCell<Option<FutureStorage>>,
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

impl TaskSlot {
    const fn new() -> Self {
        Self {
            gen_ref: AtomicU32::new(0),
            state: AtomicU8::new(STATE_IDLE),
            _pad: [0; 3],
            future: UnsafeCell::new(None),
        }
    }

    pub fn init(&self, future: impl Future<Output = ()> + Send + 'static) {
        // Safety: called on a freshly allocated slot before it is visible to other threads.
        unsafe { *self.future.get() = Some(FutureStorage::new(future)) };
        self.state.store(STATE_QUEUED, Ordering::Release);
    }

    /// Poll the task. Returns true if the task completed (or was already completed).
    /// The caller must supply shard/local/generation so we can re-enqueue on NOTIFIED.
    pub fn poll_once(
        &self,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        // Transition QUEUED -> POLLING
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

        // Safety: state machine guarantees exclusive access — only one thread
        // can CAS QUEUED→POLLING, so no concurrent access to the future.
        let future_ref = unsafe { &mut *self.future.get() };

        let poll_res = {
            let Some(fut) = future_ref.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return true;
            };
            fut.poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            // Safety: still in POLLING state, exclusive access.
            unsafe { *self.future.get() = None };
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return true;
        }

        // Pending – try POLLING -> IDLE
        let prev = self.state.compare_exchange(
            STATE_POLLING,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if let Err(STATE_NOTIFIED) = prev {
            // Wake arrived during poll – re-enqueue
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
            Err(STATE_QUEUED) => true, // already enqueued, wake is redundant
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

// ============================================================================
// JoinableSlot - Slab-backed task slot for spawn() with result storage
// ============================================================================

const WAKER_NONE: u8 = 0;
const WAKER_SET: u8 = 1;
const WAKER_TAKEN: u8 = 2;

/// A slab-backed slot for joinable tasks (tasks that return a value T).
/// Uses the same buffer for both the future and the result (mutually exclusive).
#[repr(C, align(64))]
pub struct JoinableSlot {
    /// Packed generation (high 16 bits) + ref_count (low 16 bits)
    gen_ref: AtomicU32,
    /// Task state machine: IDLE, QUEUED, POLLING, NOTIFIED, COMPLETED
    state: AtomicU8,
    /// JoinHandle waker state: NONE, SET, TAKEN
    waker_state: AtomicU8,
    /// Whether cached_waker contains a valid waker
    cached_waker_valid: AtomicU8,
    _pad: u8,
    /// Function pointer to poll the inline future (0 = boxed)
    poll_fn: AtomicUsize,
    /// Drop function for current buffer contents (future or result)
    drop_fn: AtomicUsize,
    /// Drop function for the result type T (stored at init, used after completion)
    result_drop_fn: AtomicUsize,
    /// JoinHandle's waker for completion notification
    join_waker: UnsafeCell<MaybeUninit<Waker>>,
    /// Cached waker for poll_once optimization
    cached_waker: UnsafeCell<MaybeUninit<Waker>>,
    /// Storage buffer for future (before completion) or result (after completion)
    buffer: UnsafeCell<MaybeUninit<[u8; JOINABLE_STORAGE_SIZE]>>,
}

// Safety: JoinableSlot is Sync because:
// - Atomics are inherently thread-safe
// - UnsafeCell fields are protected by the state machine (exclusive access in POLLING)
// - join_waker is protected by waker_state atomic
unsafe impl Sync for JoinableSlot {}

impl JoinableSlot {
    const fn new() -> Self {
        Self {
            gen_ref: AtomicU32::new(0),
            state: AtomicU8::new(STATE_IDLE),
            waker_state: AtomicU8::new(WAKER_NONE),
            cached_waker_valid: AtomicU8::new(0),
            _pad: 0,
            poll_fn: AtomicUsize::new(0),
            drop_fn: AtomicUsize::new(0),
            result_drop_fn: AtomicUsize::new(0),
            join_waker: UnsafeCell::new(MaybeUninit::uninit()),
            cached_waker: UnsafeCell::new(MaybeUninit::uninit()),
            buffer: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Initialize the slot with a future. Must be called on a freshly allocated slot.
    ///
    /// # Safety
    /// - F and T must fit in JOINABLE_STORAGE_SIZE with alignment <= 8
    /// - Called on a freshly allocated slot before it is visible to other threads
    pub unsafe fn init_joinable<F, T>(&self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let size = core::mem::size_of::<F>();
        let align = core::mem::align_of::<F>();

        if size <= JOINABLE_STORAGE_SIZE && align <= INLINE_FUTURE_ALIGN {
            // Inline the future
            let ptr = (*self.buffer.get()).as_mut_ptr() as *mut F;
            core::ptr::write(ptr, future);
            // Store the type-erased poll function that handles both polling and result storage
            self.poll_fn.store(
                poll_and_store_inline::<F, T> as usize,
                Ordering::Release,
            );
            self.drop_fn.store(drop_inline::<F> as usize, Ordering::Release);
        } else {
            // Box the future (shouldn't happen if caller checked size)
            let boxed: Pin<Box<dyn Future<Output = T> + Send + 'static>> = Box::pin(future);
            let ptr = (*self.buffer.get()).as_mut_ptr() as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;
            core::ptr::write(ptr, Some(boxed));
            self.poll_fn.store(
                poll_and_store_boxed::<T> as usize,
                Ordering::Release,
            );
            self.drop_fn.store(
                drop_boxed_future::<T> as usize,
                Ordering::Release,
            );
        }

        // Store the result drop function for later use
        self.result_drop_fn.store(drop_inline::<T> as usize, Ordering::Release);

        // Reset waker state
        self.waker_state.store(WAKER_NONE, Ordering::Release);
        self.cached_waker_valid.store(0, Ordering::Release);

        self.state.store(STATE_QUEUED, Ordering::Release);
    }

    /// Poll the joinable task (type-erased). Returns true if completed.
    ///
    /// On completion: the stored poll function handles dropping the future,
    /// writing the result to the buffer, and we wake the JoinHandle's waker.
    pub fn poll_once_joinable(
        &self,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        // Transition QUEUED -> POLLING
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

        let poll_fn = self.poll_fn.load(Ordering::Acquire);
        if poll_fn == 0 {
            // Already completed or invalid state
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return true;
        }

        // Call the type-erased poll function which handles everything
        // Returns true if Ready, false if Pending
        let poll_fn: unsafe fn(&JoinableSlot, &mut Context<'_>) -> bool =
            unsafe { core::mem::transmute(poll_fn) };
        let is_ready = unsafe { poll_fn(self, &mut cx) };

        if is_ready {
            // Mark poll_fn as consumed
            self.poll_fn.store(0, Ordering::Release);
            self.state.store(STATE_COMPLETED, Ordering::Release);

            // Wake JoinHandle if waiting
            self.wake_join_handle();

            true
        } else {
            // Pending - try POLLING -> IDLE
            let prev = self.state.compare_exchange(
                STATE_POLLING,
                STATE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );

            if let Err(STATE_NOTIFIED) = prev {
                // Wake arrived during poll - re-enqueue
                self.state.store(STATE_QUEUED, Ordering::Release);
                let slab = get_task_slab();
                slab.increment_joinable_ref(shard_idx, local_idx, generation);
                let encoded = encode_joinable_slab_ptr(shard_idx as u8, local_idx as u16, generation);
                submit_global(joinable_slab_poll_trampoline, encoded);
            }

            false
        }
    }

    /// Take the result from a completed task.
    ///
    /// # Safety
    /// - Must only be called once after the task has completed
    /// - T must match the type the task was initialized with
    pub unsafe fn take_result<T>(&self) -> T {
        debug_assert!(self.state.load(Ordering::Acquire) == STATE_COMPLETED);

        let ptr = (*self.buffer.get()).as_mut_ptr() as *mut T;
        let result = core::ptr::read(ptr);

        // Clear drop_fn since we've taken ownership
        self.drop_fn.store(0, Ordering::Release);

        result
    }

    /// Set the JoinHandle's waker for completion notification.
    pub fn set_join_waker(&self, waker: &Waker) {
        // Only set if not already completed
        if self.state.load(Ordering::Acquire) == STATE_COMPLETED {
            return;
        }

        unsafe {
            // Drop old waker if present
            if self.waker_state.load(Ordering::Acquire) == WAKER_SET {
                core::ptr::drop_in_place((*self.join_waker.get()).as_mut_ptr());
            }

            (*self.join_waker.get()).write(waker.clone());
        }
        self.waker_state.store(WAKER_SET, Ordering::Release);
    }

    /// Update the JoinHandle's waker only if will_wake returns false.
    pub fn update_join_waker(&self, waker: &Waker) {
        if self.state.load(Ordering::Acquire) == STATE_COMPLETED {
            return;
        }

        let current_state = self.waker_state.load(Ordering::Acquire);
        if current_state == WAKER_SET {
            unsafe {
                let current = (*self.join_waker.get()).assume_init_ref();
                if current.will_wake(waker) {
                    return;
                }
                core::ptr::drop_in_place((*self.join_waker.get()).as_mut_ptr());
            }
        }

        unsafe {
            (*self.join_waker.get()).write(waker.clone());
        }
        self.waker_state.store(WAKER_SET, Ordering::Release);
    }

    /// Wake the JoinHandle's waker on task completion.
    fn wake_join_handle(&self) {
        // Try to take the waker
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

    /// Get or refresh the cached waker for poll_once.
    pub fn get_or_refresh_cached_waker(
        &self,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> Waker {
        if self.cached_waker_valid.load(Ordering::Acquire) != 0 {
            let cached = unsafe { (*self.cached_waker.get()).assume_init_ref() };
            let new = super::waker::create_joinable_slab_waker(shard_idx, local_idx, generation);
            if cached.will_wake(&new) {
                return cached.clone();
            }
            // Drop old cached waker
            unsafe {
                core::ptr::drop_in_place((*self.cached_waker.get()).as_mut_ptr());
            }
        }

        let waker = super::waker::create_joinable_slab_waker(shard_idx, local_idx, generation);
        unsafe {
            (*self.cached_waker.get()).write(waker.clone());
        }
        self.cached_waker_valid.store(1, Ordering::Release);
        waker
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_COMPLETED
    }

    #[inline]
    pub fn try_enqueue(&self) -> bool {
        self.state
            .compare_exchange(STATE_IDLE, STATE_QUEUED, Ordering::AcqRel, Ordering::Acquire)
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

/// Poll an inline future, and on Ready, drop the future and store the result.
/// Returns true if Ready, false if Pending.
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
            // Drop the future first
            core::ptr::drop_in_place(buffer_ptr as *mut F);

            // Write result into buffer (reusing the same space)
            let result_ptr = buffer_ptr as *mut T;
            core::ptr::write(result_ptr, result);

            // Update drop_fn to result's drop
            let result_drop = slot.result_drop_fn.load(Ordering::Acquire);
            slot.drop_fn.store(result_drop, Ordering::Release);

            true
        }
        Poll::Pending => false,
    }
}

/// Poll a boxed future, and on Ready, drop the future and store the result.
/// Returns true if Ready, false if Pending.
unsafe fn poll_and_store_boxed<T>(slot: &JoinableSlot, cx: &mut Context<'_>) -> bool
where
    T: Send + 'static,
{
    let buffer_ptr = (*slot.buffer.get()).as_mut_ptr();
    let boxed_ptr = buffer_ptr as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;

    let poll_res = if let Some(fut) = (*boxed_ptr).as_mut() {
        fut.as_mut().poll(cx)
    } else {
        return true; // Already consumed
    };

    match poll_res {
        Poll::Ready(result) => {
            // Drop the boxed future
            *boxed_ptr = None;

            // Write result into buffer
            let result_ptr = buffer_ptr as *mut T;
            core::ptr::write(result_ptr, result);

            // Update drop_fn to result's drop
            let result_drop = slot.result_drop_fn.load(Ordering::Acquire);
            slot.drop_fn.store(result_drop, Ordering::Release);

            true
        }
        Poll::Pending => false,
    }
}

/// Drop a boxed future stored in the buffer.
unsafe fn drop_boxed_future<T>(ptr: *mut u8) {
    let boxed_ptr = ptr as *mut Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>;
    core::ptr::drop_in_place(boxed_ptr);
}

struct SlabShard {
    free_bitmap: [AtomicU64; MAX_SLOTS_PER_SHARD / 64],
    alloc_hint: AtomicUsize,
    slots: [UnsafeCell<MaybeUninit<TaskSlot>>; MAX_SLOTS_PER_SHARD],
    active_slots: usize,
    allocated_count: AtomicUsize,
}

unsafe impl Sync for SlabShard {}

impl SlabShard {
    fn init_in_place(dst: *mut SlabShard, num_slots: usize) {
        let num_slots = num_slots.min(MAX_SLOTS_PER_SHARD);
        let num_words = (num_slots + 63) / 64;

        unsafe {
            for i in 0..(MAX_SLOTS_PER_SHARD / 64) {
                let p = ptr::addr_of_mut!((*dst).free_bitmap[i]);
                ptr::write(p, AtomicU64::new(0));
            }

            ptr::write(ptr::addr_of_mut!((*dst).alloc_hint), AtomicUsize::new(0));

            for i in 0..MAX_SLOTS_PER_SHARD {
                let p = ptr::addr_of_mut!((*dst).slots[i]);
                ptr::write(p, UnsafeCell::new(MaybeUninit::uninit()));
            }

            ptr::write(ptr::addr_of_mut!((*dst).active_slots), num_slots);
            ptr::write(
                ptr::addr_of_mut!((*dst).allocated_count),
                AtomicUsize::new(0),
            );

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

                (*dst).free_bitmap[i].store(mask, Ordering::Relaxed);
            }

            for i in 0..num_slots {
                (*(*dst).slots[i].get()).write(TaskSlot::new());
            }
        }
    }

    fn try_allocate(&self) -> Option<usize> {
        let hint = self.alloc_hint.load(Ordering::Relaxed);
        let num_words = (self.active_slots + 63) / 64;

        for offset in 0..num_words {
            let word_idx = (hint / 64 + offset) % num_words;
            let word = &self.free_bitmap[word_idx];

            loop {
                let bits = word.load(Ordering::Acquire);
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
                    Err(_) => continue,
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

        self.free_bitmap[word_idx].fetch_or(mask, Ordering::Release);
        self.alloc_hint.store(slot_idx, Ordering::Relaxed);
        self.allocated_count.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    fn get_slot(&self, idx: usize) -> Option<&TaskSlot> {
        if idx >= self.active_slots {
            return None;
        }
        unsafe { Some((*self.slots[idx].get()).assume_init_ref()) }
    }
}

// ============================================================================
// JoinableShard - Shard for joinable task slots
// ============================================================================

struct JoinableShard {
    free_bitmap: [AtomicU64; MAX_JOINABLE_SLOTS_PER_SHARD / 64],
    alloc_hint: AtomicUsize,
    slots: [UnsafeCell<MaybeUninit<JoinableSlot>>; MAX_JOINABLE_SLOTS_PER_SHARD],
    active_slots: usize,
    allocated_count: AtomicUsize,
}

unsafe impl Sync for JoinableShard {}

impl JoinableShard {
    fn init_in_place(dst: *mut JoinableShard, num_slots: usize) {
        let num_slots = num_slots.min(MAX_JOINABLE_SLOTS_PER_SHARD);
        let num_words = (num_slots + 63) / 64;

        unsafe {
            for i in 0..(MAX_JOINABLE_SLOTS_PER_SHARD / 64) {
                let p = ptr::addr_of_mut!((*dst).free_bitmap[i]);
                ptr::write(p, AtomicU64::new(0));
            }

            ptr::write(ptr::addr_of_mut!((*dst).alloc_hint), AtomicUsize::new(0));

            for i in 0..MAX_JOINABLE_SLOTS_PER_SHARD {
                let p = ptr::addr_of_mut!((*dst).slots[i]);
                ptr::write(p, UnsafeCell::new(MaybeUninit::uninit()));
            }

            ptr::write(ptr::addr_of_mut!((*dst).active_slots), num_slots);
            ptr::write(
                ptr::addr_of_mut!((*dst).allocated_count),
                AtomicUsize::new(0),
            );

            for i in 0..num_words {
                let slots_in_word = if i == num_words - 1 {
                    let rem = num_slots % 64;
                    if rem == 0 { 64 } else { rem }
                } else {
                    64
                };

                let mask = if slots_in_word == 64 {
                    !0u64
                } else {
                    (1u64 << slots_in_word) - 1
                };

                (*dst).free_bitmap[i].store(mask, Ordering::Relaxed);
            }

            for i in 0..num_slots {
                (*(*dst).slots[i].get()).write(JoinableSlot::new());
            }
        }
    }

    fn try_allocate(&self) -> Option<usize> {
        let hint = self.alloc_hint.load(Ordering::Relaxed);
        let num_words = (self.active_slots + 63) / 64;

        for offset in 0..num_words {
            let word_idx = (hint / 64 + offset) % num_words;
            let word = &self.free_bitmap[word_idx];

            loop {
                let bits = word.load(Ordering::Acquire);
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
                    Err(_) => continue,
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

        self.free_bitmap[word_idx].fetch_or(mask, Ordering::Release);
        self.alloc_hint.store(slot_idx, Ordering::Relaxed);
        self.allocated_count.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    fn get_slot(&self, idx: usize) -> Option<&JoinableSlot> {
        if idx >= self.active_slots {
            return None;
        }
        unsafe { Some((*self.slots[idx].get()).assume_init_ref()) }
    }
}

pub struct TaskSlab {
    shards: [SlabShard; NUM_SHARDS],
    joinable_shards: [JoinableShard; NUM_SHARDS],
    config: SlabConfig,
    total_allocations: AtomicU64,
    fallback_allocations: AtomicU64,
    joinable_allocations: AtomicU64,
    joinable_fallback_allocations: AtomicU64,
}

impl TaskSlab {
    fn init_in_place(dst: *mut TaskSlab, config: SlabConfig) {
        unsafe {
            ptr::write(ptr::addr_of_mut!((*dst).config), config);
            ptr::write(
                ptr::addr_of_mut!((*dst).total_allocations),
                AtomicU64::new(0),
            );
            ptr::write(
                ptr::addr_of_mut!((*dst).fallback_allocations),
                AtomicU64::new(0),
            );
            ptr::write(
                ptr::addr_of_mut!((*dst).joinable_allocations),
                AtomicU64::new(0),
            );
            ptr::write(
                ptr::addr_of_mut!((*dst).joinable_fallback_allocations),
                AtomicU64::new(0),
            );

            for i in 0..NUM_SHARDS {
                let shard_ptr = ptr::addr_of_mut!((*dst).shards[i]);
                SlabShard::init_in_place(shard_ptr, config.slots_per_shard);
            }

            // Initialize joinable shards
            let joinable_slots = config.slots_per_shard / 2; // Half as many joinable slots
            let joinable_slots = joinable_slots.max(32).min(MAX_JOINABLE_SLOTS_PER_SHARD);
            for i in 0..NUM_SHARDS {
                let shard_ptr = ptr::addr_of_mut!((*dst).joinable_shards[i]);
                JoinableShard::init_in_place(shard_ptr, joinable_slots);
            }
        }
    }

    pub fn allocate(&self) -> Option<SlotHandle<'_>> {
        let start_shard = self.shard_hint();

        for offset in 0..NUM_SHARDS {
            let shard_idx = (start_shard + offset) % NUM_SHARDS;
            let shard = &self.shards[shard_idx];

            if let Some(local_idx) = shard.try_allocate() {
                let slot = shard.get_slot(local_idx)?;

                // Bump generation and set ref_count=1 atomically.
                // Old value's generation is incremented (mod 24 bits).
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

    /// Atomically increment the ref count, but only if the generation still matches.
    /// Uses a CAS loop on the packed gen_ref field so that a concurrent
    /// deallocation + reallocation (which changes the generation) is detected.
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
            debug_assert!(rc < REF_MASK, "slab ref_count overflow");
            let new = pack_gen_ref(expected_gen, rc + 1);
            match slot
                .gen_ref
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(v) if unpack_gen(v) != expected_gen => return false,
                Err(_) => continue, // ref_count changed, retry
            }
        }
    }

    /// Atomically decrement the ref count, but only if the generation still matches.
    /// If this was the last reference, drops the future and frees the slot.
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
                return; // slot was already freed and possibly reallocated
            }
            let rc = unpack_ref(cur);
            if rc == 0 {
                return; // already fully released
            }
            let new = pack_gen_ref(expected_gen, rc - 1);
            match slot
                .gen_ref
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if rc == 1 {
                        // We took the last ref — clean up.
                        // Safety: rc 1→0 via CAS means no other thread holds a
                        // reference, so exclusive access is guaranteed.
                        unsafe { *slot.future.get() = None };
                        shard.deallocate(local_idx);
                    }
                    return;
                }
                Err(v) if unpack_gen(v) != expected_gen => return,
                Err(_) => continue,
            }
        }
    }

    // ========================================================================
    // Joinable slot allocation and reference counting
    // ========================================================================

    /// Allocate a joinable slot. Returns None if no slots available.
    /// The caller should check size constraints before calling.
    pub fn allocate_joinable(&self) -> Option<JoinableSlotHandle<'_>> {
        let start_shard = self.shard_hint();

        for offset in 0..NUM_SHARDS {
            let shard_idx = (start_shard + offset) % NUM_SHARDS;
            let shard = &self.joinable_shards[shard_idx];

            if let Some(local_idx) = shard.try_allocate() {
                let slot = shard.get_slot(local_idx)?;

                // Bump generation and set ref_count=1 atomically
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

    /// Atomically increment the ref count for a joinable slot.
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
            debug_assert!(rc < REF_MASK, "joinable slab ref_count overflow");
            let new = pack_gen_ref(expected_gen, rc + 1);
            match slot
                .gen_ref
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(v) if unpack_gen(v) != expected_gen => return false,
                Err(_) => continue,
            }
        }
    }

    /// Atomically decrement the ref count for a joinable slot.
    /// If this was the last reference, cleans up and frees the slot.
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
                        // Last ref - clean up
                        // Drop buffer contents if drop_fn is set
                        let drop_fn = slot.drop_fn.load(Ordering::Acquire);
                        if drop_fn != 0 {
                            unsafe {
                                let drop_fn: unsafe fn(*mut u8) = core::mem::transmute(drop_fn);
                                drop_fn((*slot.buffer.get()).as_mut_ptr() as *mut u8);
                            }
                        }
                        slot.drop_fn.store(0, Ordering::Release);

                        // Drop cached waker if valid
                        if slot.cached_waker_valid.load(Ordering::Acquire) != 0 {
                            unsafe {
                                core::ptr::drop_in_place(
                                    (*slot.cached_waker.get()).as_mut_ptr(),
                                );
                            }
                            slot.cached_waker_valid.store(0, Ordering::Release);
                        }

                        // Drop join waker if set but not taken
                        let waker_state = slot.waker_state.load(Ordering::Acquire);
                        if waker_state == WAKER_SET {
                            unsafe {
                                core::ptr::drop_in_place((*slot.join_waker.get()).as_mut_ptr());
                            }
                        }
                        slot.waker_state.store(WAKER_NONE, Ordering::Release);

                        shard.deallocate(local_idx);
                    }
                    return;
                }
                Err(v) if unpack_gen(v) != expected_gen => return,
                Err(_) => continue,
            }
        }
    }

    #[inline]
    fn shard_hint(&self) -> usize {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed) % NUM_SHARDS
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
            // Bump ref for the queued poll (allocate gave us rc=1 as the base ref;
            // the queue submission needs its own ref that slab_poll_trampoline will release).
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

// ============================================================================
// JoinableSlotHandle - Handle for allocated joinable slots
// ============================================================================

pub struct JoinableSlotHandle<'a> {
    slab: &'a TaskSlab,
    pub shard_idx: u8,
    pub local_idx: u16,
    pub generation: u32,
}

impl<'a> JoinableSlotHandle<'a> {
    /// Initialize the slot with a future and enqueue it for execution.
    /// Returns the indices for constructing a JoinHandle.
    pub fn init_and_enqueue<F, T>(self, future: F) -> (u8, u16, u32)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let shard = &self.slab.joinable_shards[self.shard_idx as usize];
        if let Some(slot) = shard.get_slot(self.local_idx as usize) {
            // Safety: slot is freshly allocated and we've verified size constraints
            unsafe { slot.init_joinable(future) };

            // Bump ref for the queued poll
            self.slab.increment_joinable_ref(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            );

            // Bump ref for the JoinHandle
            self.slab.increment_joinable_ref(
                self.shard_idx as usize,
                self.local_idx as usize,
                self.generation,
            );

            let encoded =
                encode_joinable_slab_ptr(self.shard_idx, self.local_idx, self.generation);
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

// ============================================================================
// Pointer encoding for slab tasks
// ============================================================================

// Detached slab pointer: bit 0 = 1, bit 1 = 0
// Joinable slab pointer: bit 0 = 1, bit 1 = 1 (i.e., bits[1:0] = 0b11)

#[inline]
pub fn encode_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let gen_bits = (generation as usize & 0xFFFFFF) << 25;
    let local_bits = (local_idx as usize) << 9;
    let shard_bits = (shard_idx as usize) << 2;
    gen_bits | local_bits | shard_bits | 0b01 // tag = 0b01 (detached)
}

#[inline]
pub fn decode_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    // Check for detached slab tag (0b01)
    if ptrv & 0b11 != 0b01 {
        return None;
    }
    let shard_idx = (ptrv >> 2) & 0xFF;
    let local_idx = (ptrv >> 9) & 0xFFFF;
    let generation = ((ptrv >> 25) & 0xFFFFFF) as u32;
    Some((shard_idx, local_idx, generation))
}

#[inline]
pub fn encode_joinable_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let gen_bits = (generation as usize & 0xFFFFFF) << 25;
    let local_bits = (local_idx as usize) << 9;
    let shard_bits = (shard_idx as usize) << 2;
    gen_bits | local_bits | shard_bits | 0b11 // tag = 0b11 (joinable)
}

#[inline]
pub fn decode_joinable_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    // Check for joinable slab tag (0b11)
    if ptrv & 0b11 != 0b11 {
        return None;
    }
    let shard_idx = (ptrv >> 2) & 0xFF;
    let local_idx = (ptrv >> 9) & 0xFFFF;
    let generation = ((ptrv >> 25) & 0xFFFFFF) as u32;
    Some((shard_idx, local_idx, generation))
}

#[inline]
#[allow(dead_code)]
pub fn is_slab_ptr(ptrv: usize) -> bool {
    ptrv & 0b01 != 0
}

#[inline]
#[allow(dead_code)]
pub fn is_joinable_slab_ptr(ptrv: usize) -> bool {
    ptrv & 0b11 == 0b11
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

    let waker = super::waker::create_slab_waker(shard_idx, local_idx, generation);

    let completed = slot.poll_once(&waker, shard_idx, local_idx, generation);

    // Always release the queue-owned ref. Every enqueue path (enqueue_slab_task,
    // poll_once re-enqueue on NOTIFIED, slab_inline_poll, init_and_enqueue) bumps
    // the refcount for the queued poll; we consume that ref here regardless of
    // whether the future completed or returned Pending.
    slab.decrement_ref(shard_idx, local_idx, generation);

    if completed {
        // The base task ref (from allocate) is also released on completion.
        slab.decrement_ref(shard_idx, local_idx, generation);
    }
}

pub fn enqueue_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    let slab = get_task_slab();
    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        return;
    };

    loop {
        // Try IDLE -> QUEUED
        if slot.try_enqueue() {
            slab.increment_ref(shard_idx, local_idx, generation);
            let encoded = encode_slab_ptr(shard_idx as u8, local_idx as u16, generation);
            submit_global(slab_poll_trampoline, encoded);
            return;
        }

        // If currently polling, upgrade to NOTIFIED.
        // Returns false if state raced to IDLE – retry the whole loop.
        if slot.try_notify() {
            return;
        }
    }
}

// ============================================================================
// Joinable slab poll trampoline and enqueue
// ============================================================================

#[inline(never)]
pub extern "win64" fn joinable_slab_poll_trampoline(ctx: usize) {
    let Some((shard_idx, local_idx, generation)) = decode_joinable_slab_ptr(ctx) else {
        return;
    };

    let slab = get_task_slab();
    let Some(slot) = slab.get_joinable_slot(shard_idx, local_idx, generation) else {
        return;
    };

    // Get or refresh cached waker (avoids creating new waker every poll)
    let waker = slot.get_or_refresh_cached_waker(shard_idx, local_idx, generation);

    // Poll the task (type-erased - the stored poll function handles everything)
    let completed = slot.poll_once_joinable(&waker, shard_idx, local_idx, generation);

    // Always release the queue-owned ref
    slab.decrement_joinable_ref(shard_idx, local_idx, generation);

    if completed {
        // Release the base task ref on completion
        // Note: JoinHandle still holds its own ref until it takes the result
        slab.decrement_joinable_ref(shard_idx, local_idx, generation);
    }
}

pub fn enqueue_joinable_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    let slab = get_task_slab();
    let Some(slot) = slab.get_joinable_slot(shard_idx, local_idx, generation) else {
        return;
    };

    loop {
        // Try IDLE -> QUEUED
        if slot.try_enqueue() {
            slab.increment_joinable_ref(shard_idx, local_idx, generation);
            let encoded = encode_joinable_slab_ptr(shard_idx as u8, local_idx as u16, generation);
            submit_global(joinable_slab_poll_trampoline, encoded);
            return;
        }

        // If currently polling, upgrade to NOTIFIED
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
