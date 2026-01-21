//! Task Slab Allocator for the async executor.
//!
//! Pre-allocated pool of task slots for detached tasks. Uses a sharded bitmap
//! to reduce contention.
//!
//! This version avoids constructing multi-MiB temporaries on the stack during
//! slab initialization by initializing the slab in-place in static storage.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use spin::{Mutex, Once};

use crate::println;

use super::runtime::submit_global;

const NUM_SHARDS: usize = 8;
const DEFAULT_SLOTS_PER_SHARD: usize = 128;
const MAX_SLOTS_PER_SHARD: usize = 4096;

/// Maximum size (in bytes) for inline future storage. Futures larger than this
/// will be heap-allocated. Default: 128 bytes covers most simple async state machines.
pub const INLINE_FUTURE_SIZE: usize = 256;

/// Required alignment for inline future storage.
pub const INLINE_FUTURE_ALIGN: usize = 8;

const SLOT_FREE: u8 = 0;
const SLOT_ALLOCATED: u8 = 1;

static TASK_SLAB_PTR: Once<&'static TaskSlab> = Once::new();
static mut TASK_SLAB_STORAGE: MaybeUninit<TaskSlab> = MaybeUninit::uninit();

/// Properly aligned buffer for inline future storage.
#[repr(C, align(8))]
struct InlineFutureBuffer {
    data: [u8; INLINE_FUTURE_SIZE],
}

impl InlineFutureBuffer {
    const fn new() -> Self {
        Self {
            data: [0u8; INLINE_FUTURE_SIZE],
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

/// Storage for a future - either inline (SBO) or heap-allocated.
enum FutureStorage {
    /// Heap-allocated future (for large futures)
    Boxed(Pin<Box<dyn Future<Output = ()> + Send + 'static>>),
    /// Inline storage with manual vtable for small futures
    Inline {
        /// Aligned storage buffer
        storage: InlineFutureBuffer,
        /// Function pointer to poll the future
        poll_fn: unsafe fn(*mut u8, &mut Context<'_>) -> Poll<()>,
        /// Function pointer to drop the future
        drop_fn: unsafe fn(*mut u8),
    },
}

/// Type-erased poll function for inline futures
unsafe fn poll_inline<F>(ptr: *mut u8, cx: &mut Context<'_>) -> Poll<()>
where
    F: Future<Output = ()>,
{
    let future = &mut *(ptr as *mut F);
    // Safety: The future is pinned within the TaskSlot which doesn't move
    Pin::new_unchecked(future).poll(cx)
}

/// Type-erased drop function for inline futures
unsafe fn drop_inline<F>(ptr: *mut u8) {
    core::ptr::drop_in_place(ptr as *mut F);
}

impl FutureStorage {
    /// Create storage for a future, using inline if it fits
    fn new<F>(future: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let size = core::mem::size_of::<F>();
        if size <= INLINE_FUTURE_SIZE && size <= INLINE_FUTURE_ALIGN {
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

    /// Poll the stored future
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

#[repr(C, align(64))]
pub struct TaskSlot {
    ref_count: AtomicU32,
    generation: AtomicU32,
    queued: AtomicBool,
    completed: AtomicBool,
    _pad: [u8; 6],
    future: Mutex<Option<FutureStorage>>,
}

impl TaskSlot {
    const fn new() -> Self {
        Self {
            ref_count: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            queued: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            _pad: [0; 6],
            future: Mutex::new(None),
        }
    }

    pub fn init(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut guard = self.future.lock();
        *guard = Some(FutureStorage::new(future));
        self.queued.store(false, Ordering::Release);
        self.completed.store(false, Ordering::Release);
    }

    pub fn poll_once(&self, waker: &Waker) -> bool {
        self.queued.store(false, Ordering::Release);

        if self.completed.load(Ordering::Acquire) {
            return true;
        }

        let mut cx = Context::from_waker(waker);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.completed.store(true, Ordering::Release);
                return true;
            };
            fut.poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            let mut guard = self.future.lock();
            *guard = None;
            self.completed.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    #[inline]
    pub fn is_queued(&self) -> bool {
        self.queued.load(Ordering::Acquire)
    }

    #[inline]
    pub fn try_set_queued(&self) -> bool {
        !self.queued.swap(true, Ordering::AcqRel)
    }
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

pub struct TaskSlab {
    shards: [SlabShard; NUM_SHARDS],
    config: SlabConfig,
    total_allocations: AtomicU64,
    fallback_allocations: AtomicU64,
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

            for i in 0..NUM_SHARDS {
                let shard_ptr = ptr::addr_of_mut!((*dst).shards[i]);
                SlabShard::init_in_place(shard_ptr, config.slots_per_shard);
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

                let gen = slot
                    .generation
                    .fetch_add(1, Ordering::AcqRel)
                    .wrapping_add(1);

                slot.ref_count.store(1, Ordering::Release);

                self.total_allocations.fetch_add(1, Ordering::Relaxed);

                return Some(SlotHandle {
                    slab: self,
                    shard_idx: shard_idx as u8,
                    local_idx: local_idx as u16,
                    generation: gen,
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
        if slot.generation.load(Ordering::Acquire) != expected_gen {
            return None;
        }
        Some(slot)
    }

    pub fn increment_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) -> bool {
        if let Some(slot) = self.get_slot(shard_idx, local_idx, expected_gen) {
            slot.ref_count.fetch_add(1, Ordering::AcqRel);
            true
        } else {
            false
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

        if slot.generation.load(Ordering::Acquire) != expected_gen {
            return;
        }

        let prev = slot.ref_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            {
                let mut guard = slot.future.lock();
                *guard = None;
            }
            shard.deallocate(local_idx);
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

#[inline]
pub fn encode_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let gen_bits = (generation as usize & 0xFFFFFF) << 25;
    let local_bits = (local_idx as usize) << 9;
    let shard_bits = (shard_idx as usize) << 1;
    gen_bits | local_bits | shard_bits | 1
}

#[inline]
pub fn decode_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    if ptrv & 1 == 0 {
        return None;
    }
    let shard_idx = (ptrv >> 1) & 0xFF;
    let local_idx = (ptrv >> 9) & 0xFFFF;
    let generation = ((ptrv >> 25) & 0xFFFFFF) as u32;
    Some((shard_idx, local_idx, generation))
}

#[inline]
#[allow(dead_code)]
pub fn is_slab_ptr(ptrv: usize) -> bool {
    ptrv & 1 != 0
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

    let completed = slot.poll_once(&waker);

    if completed {
        slab.decrement_ref(shard_idx, local_idx, generation);
    }
}

pub fn enqueue_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    let slab = get_task_slab();
    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        return;
    };

    if slot.is_completed() {
        return;
    }

    if !slot.try_set_queued() {
        return;
    }

    slab.increment_ref(shard_idx, local_idx, generation);

    let encoded = encode_slab_ptr(shard_idx as u8, local_idx as u16, generation);
    submit_global(slab_poll_trampoline, encoded);
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
