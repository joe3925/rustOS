use crate::platform::{ExecutorPlatform, ExecutorThreadLocal, SlabCacheEntry};
use alloc::{boxed::Box, vec::Vec};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicPtr;

use crate::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use crate::sync::spin_loop;

pub const DEFAULT_SLAB_SHARDS: usize = 8;
// Keep the eagerly allocated per-shard chunk table bounded while allowing the
// executor to hold well over one million resident tasks with its default shards.
pub(crate) const MAX_LOCAL_SLOTS: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlabHandle {
    pub shard: u8,
    pub local_index: u32,
    pub generation: u32,
}

struct StableSlot<T> {
    state: AtomicU32,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for StableSlot<T> {}
unsafe impl<T: Send> Sync for StableSlot<T> {}

impl<T> StableSlot<T> {
    fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }
}

struct SlabChunk<T> {
    free_bitmap: Box<[AtomicU64]>,
    slots: Box<[StableSlot<T>]>,
}

impl<T> SlabChunk<T> {
    fn new<F>(num_slots: usize, init: &F) -> Self
    where
        F: Fn() -> T,
    {
        let words = num_slots.div_ceil(64);
        let mut bitmap = Vec::with_capacity(words);
        for word in 0..words {
            let remaining = num_slots.saturating_sub(word * 64).min(64);
            let mask = if remaining == 64 {
                u64::MAX
            } else {
                (1u64 << remaining) - 1
            };
            bitmap.push(AtomicU64::new(mask));
        }

        let mut slots = Vec::with_capacity(num_slots);
        for _ in 0..num_slots {
            slots.push(StableSlot::new(init()));
        }
        Self {
            free_bitmap: bitmap.into_boxed_slice(),
            slots: slots.into_boxed_slice(),
        }
    }
}

struct SlabShard<T> {
    slots_per_chunk: usize,
    chunks: Box<[AtomicPtr<SlabChunk<T>>]>,
    published_chunks: AtomicUsize,
    alloc_hint: AtomicUsize,
    init: fn() -> T,
}

unsafe impl<T: Send> Send for SlabShard<T> {}
unsafe impl<T: Send> Sync for SlabShard<T> {}

impl<T> SlabShard<T> {
    fn new(slots_per_chunk: usize, max_chunks: usize, init: fn() -> T) -> Self {
        let max_chunks = max_chunks.min(MAX_LOCAL_SLOTS / slots_per_chunk).max(1);
        let mut chunks = Vec::with_capacity(max_chunks);
        for _ in 0..max_chunks {
            chunks.push(AtomicPtr::new(ptr::null_mut()));
        }
        let shard = Self {
            slots_per_chunk,
            chunks: chunks.into_boxed_slice(),
            published_chunks: AtomicUsize::new(0),
            alloc_hint: AtomicUsize::new(0),
            init,
        };
        let _ = shard.grow_chunk();
        shard
    }

    fn grow_chunk(&self) -> bool {
        let published = self.published_chunks.load(Ordering::Acquire);
        if published >= self.chunks.len() {
            return false;
        }
        let raw = Box::into_raw(Box::new(SlabChunk::new(self.slots_per_chunk, &self.init)));
        match self.chunks[published].compare_exchange(
            ptr::null_mut(),
            raw,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let _ = self.published_chunks.compare_exchange(
                    published,
                    published + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            Err(_) => {
                unsafe { drop(Box::from_raw(raw)) };
                if !self.chunks[published].load(Ordering::Acquire).is_null() {
                    let _ = self.published_chunks.compare_exchange(
                        published,
                        published + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
            }
        }
        true
    }

    fn try_reserve(&self, shard: u8) -> Option<SlabHandle> {
        let published = self.published_chunks.load(Ordering::Acquire);
        let words_per_chunk = self.slots_per_chunk.div_ceil(64);
        let total_words = published * words_per_chunk;
        if total_words == 0 {
            return None;
        }
        let hint = self.alloc_hint.load(Ordering::Relaxed);
        for offset in 0..total_words {
            let global_word = (hint / 64 + offset) % total_words;
            let chunk_index = global_word / words_per_chunk;
            let local_word = global_word % words_per_chunk;
            let chunk_ptr = self.chunks[chunk_index].load(Ordering::Acquire);
            if chunk_ptr.is_null() {
                continue;
            }
            let chunk = unsafe { &*chunk_ptr };
            let word = &chunk.free_bitmap[local_word];
            loop {
                let bits = word.load(Ordering::Relaxed);
                if bits == 0 {
                    break;
                }
                let bit = bits.trailing_zeros() as usize;
                let local_in_chunk = local_word * 64 + bit;
                if local_in_chunk >= self.slots_per_chunk {
                    break;
                }
                if word
                    .compare_exchange_weak(
                        bits,
                        bits & !(1u64 << bit),
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_err()
                {
                    spin_loop();
                    continue;
                }
                let index = chunk_index * self.slots_per_chunk + local_in_chunk;
                let slot = &chunk.slots[local_in_chunk];
                let generation = ((slot.state.load(Ordering::Relaxed) >> 1) + 1) & 0xffff;
                slot.state.store((generation << 1) | 1, Ordering::Release);
                self.alloc_hint.store(index + 1, Ordering::Relaxed);
                return Some(SlabHandle {
                    shard,
                    local_index: index as u32,
                    generation,
                });
            }
        }
        self.grow_chunk().then(|| self.try_reserve(shard)).flatten()
    }

    #[inline(never)]
    fn reserve_batch(&self, shard: u8, entries: &mut [SlabCacheEntry]) -> usize {
        let published = self.published_chunks.load(Ordering::Acquire);
        let words_per_chunk = self.slots_per_chunk.div_ceil(64);
        let total_words = published * words_per_chunk;
        let hint = self.alloc_hint.load(Ordering::Relaxed);
        for offset in 0..total_words {
            let global_word = (hint / 64 + offset) % total_words;
            let chunk_index = global_word / words_per_chunk;
            let local_word = global_word % words_per_chunk;
            let chunk_ptr = self.chunks[chunk_index].load(Ordering::Acquire);
            if chunk_ptr.is_null() {
                continue;
            }
            let chunk = unsafe { &*chunk_ptr };
            let word = &chunk.free_bitmap[local_word];
            let mut bits = word.load(Ordering::Relaxed);
            while bits != 0 {
                let mut remaining = bits;
                let mut selected = 0u64;
                for _ in 0..entries.len() {
                    if remaining == 0 {
                        break;
                    }
                    let bit = 1u64 << remaining.trailing_zeros();
                    selected |= bit;
                    remaining &= !bit;
                }
                match word.compare_exchange_weak(
                    bits,
                    remaining,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let mut count = 0;
                        while selected != 0 {
                            let bit = selected.trailing_zeros() as usize;
                            selected &= !(1u64 << bit);
                            let local = local_word * 64 + bit;
                            let slot = &chunk.slots[local];
                            entries[count] = SlabCacheEntry {
                                handle: SlabHandle {
                                    shard,
                                    local_index: (chunk_index * self.slots_per_chunk + local) as u32,
                                    generation: slot.state.load(Ordering::Relaxed) >> 1,
                                },
                                slot: ptr::from_ref(slot).cast(),
                            };
                            count += 1;
                        }
                        self.alloc_hint
                            .store(global_word * 64 + 64, Ordering::Relaxed);
                        return count;
                    }
                    Err(actual) => bits = actual,
                }
            }
        }
        if self.grow_chunk() {
            self.reserve_batch(shard, entries)
        } else {
            0
        }
    }

    fn cached_slot(&self, handle: SlabHandle) -> Option<&StableSlot<T>> {
        let index = handle.local_index as usize;
        let chunk_index = index / self.slots_per_chunk;
        let local = index % self.slots_per_chunk;
        if chunk_index >= self.published_chunks.load(Ordering::Acquire) {
            return None;
        }
        let chunk = self.chunks[chunk_index].load(Ordering::Acquire);
        if chunk.is_null() {
            return None;
        }
        Some(unsafe { &(*chunk).slots[local] })
    }

    fn slot(&self, handle: SlabHandle) -> Option<&StableSlot<T>> {
        if handle.generation > 0xffff {
            return None;
        }
        let slot = self.cached_slot(handle)?;
        if slot.state.load(Ordering::Acquire) != (handle.generation << 1) | 1 {
            return None;
        }
        Some(slot)
    }

    unsafe fn release(&self, handle: SlabHandle) -> bool {
        unsafe {
            let Some(slot) = self.slot(handle) else {
                return false;
            };
            if slot
                .state
                .compare_exchange(
                    (handle.generation << 1) | 1,
                    handle.generation << 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return false;
            }
            let index = handle.local_index as usize;
            let chunk_index = index / self.slots_per_chunk;
            let local = index % self.slots_per_chunk;
            let chunk = &*self.chunks[chunk_index].load(Ordering::Acquire);
            chunk.free_bitmap[local / 64].fetch_or(1u64 << (local % 64), Ordering::Release);
            self.alloc_hint.store(index, Ordering::Relaxed);
            true
        }
    }
}

impl<T> Drop for SlabShard<T> {
    fn drop(&mut self) {
        for chunk in self.chunks.iter() {
            let raw = chunk.load(Ordering::Relaxed);
            if !raw.is_null() {
                unsafe { drop(Box::from_raw(raw)) };
            }
        }
    }
}

pub struct GrowableSlab<T, E: ExecutorPlatform> {
    _platform: core::marker::PhantomData<fn() -> E>,
    shards: Box<[SlabShard<T>]>,
    shard_hint: AtomicUsize,
}

unsafe impl<T: Send, E: ExecutorPlatform> Send for GrowableSlab<T, E> {}
unsafe impl<T: Send, E: ExecutorPlatform> Sync for GrowableSlab<T, E> {}

impl<T, E: ExecutorPlatform> GrowableSlab<T, E> {
    pub fn new(
        shard_count: usize,
        slots_per_chunk: usize,
        max_chunks_per_shard: usize,
        init: fn() -> T,
    ) -> Self {
        let shard_count = shard_count.clamp(1, u8::MAX as usize + 1);
        let slots_per_chunk = slots_per_chunk.clamp(1, MAX_LOCAL_SLOTS);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(SlabShard::new(slots_per_chunk, max_chunks_per_shard, init));
        }
        Self {
            _platform: core::marker::PhantomData,
            shards: shards.into_boxed_slice(),
            shard_hint: AtomicUsize::new(0),
        }
    }

    pub fn reserve(&self) -> Option<SlabHandle> {
        let start = if E::in_interrupt_context() {
            self.shard_hint.fetch_add(1, Ordering::Relaxed) % self.shards.len()
        } else {
            crate::platform::with_executor_local::<E, _>(|tls| {
                let hint = tls.allocation_cursor.get();
                tls.allocation_cursor.set(hint.wrapping_add(1));
                hint % self.shards.len()
            })
        };
        for offset in 0..self.shards.len() {
            let shard = (start + offset) % self.shards.len();
            if let Some(handle) = self.shards[shard].try_reserve(shard as u8) {
                return Some(handle);
            }
        }
        None
    }

    #[inline(always)]
    pub(crate) unsafe fn reserve_cached(
        &self,
        tls: &ExecutorThreadLocal<E>,
        cache_index: usize,
        limit: usize,
    ) -> Option<(SlabHandle, &T)> {
        let uncached = || {
            let handle = self.reserve()?;
            Some((handle, self.get(handle)?))
        };
        debug_assert!(!E::in_interrupt_context());
        if tls.active_domain.get().is_null() {
            return uncached();
        }
        let mut caches = tls.caches.borrow_mut();
        let cache = &mut caches[cache_index];
        let owner = self as *const Self as *const ();
        if cache.owner.is_null() {
            cache.owner = owner;
            cache.flush = Some(Self::return_cached_batch);
        } else if cache.owner != owner {
            return uncached();
        }
        if cache.len == 0 {
            let shard_count = self.shards.len();
            let mut shard = tls.allocation_cursor.get();
            if shard >= shard_count {
                shard %= shard_count;
            }
            for _ in 0..shard_count {
                cache.len = self.shards[shard]
                    .reserve_batch(shard as u8, &mut cache.entries[..limit]);
                if cache.len != 0 {
                    tls.allocation_cursor.set(shard);
                    break;
                }
                shard += 1;
                if shard == shard_count {
                    shard = 0;
                }
            }
            if cache.len == 0 {
                return None;
            }
        }
        cache.len -= 1;
        let entry = cache.entries[cache.len];
        let handle = entry.handle;
        let slot = unsafe { &*entry.slot.cast::<StableSlot<T>>() };
        let generation = (handle.generation + 1) & 0xffff;
        slot.state.store((generation << 1) | 1, Ordering::Release);
        Some((
            SlabHandle {
                generation,
                ..handle
            },
            unsafe { &*slot.value.get() },
        ))
    }

    pub(crate) unsafe fn release_cached(
        &self,
        handle: SlabHandle,
        cache_index: usize,
        limit: usize,
    ) -> bool {
        if E::in_interrupt_context() {
            return unsafe { self.release(handle) };
        }
        crate::platform::with_executor_local::<E, _>(|tls| {
            if tls.active_domain.get().is_null() {
                return unsafe { self.release(handle) };
            }
            let mut caches = tls.caches.borrow_mut();
            let cache = &mut caches[cache_index];
            let owner = self as *const Self as *const ();
            if !cache.owner.is_null() && cache.owner != owner {
                return unsafe { self.release(handle) };
            }
            let Some(shard) = self.shards.get(handle.shard as usize) else {
                return false;
            };
            let Some(slot) = shard.slot(handle) else {
                return false;
            };
            if slot
                .state
                .compare_exchange(
                    (handle.generation << 1) | 1,
                    handle.generation << 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return false;
            }
            cache.owner = owner;
            cache.flush = Some(Self::return_cached_batch);
            if cache.len == limit {
                unsafe { Self::return_cached_batch(owner, &mut cache.entries[..cache.len]) };
                cache.len = 0;
            }
            let index = cache.len;
            cache.entries[index] = SlabCacheEntry {
                handle,
                slot: ptr::from_ref(slot).cast(),
            };
            cache.len = index + 1;
            true
        })
    }

    unsafe fn return_cached_batch(owner: *const (), entries: &mut [SlabCacheEntry]) {
        let slab = unsafe { &*owner.cast::<Self>() };
        for index in 0..entries.len() {
            if entries[index].slot.is_null() {
                continue;
            }
            let handle = entries[index].handle;
            entries[index].slot = ptr::null();
            let shard = &slab.shards[handle.shard as usize];
            let local = handle.local_index as usize;
            let chunk_index = local / shard.slots_per_chunk;
            let word = (local % shard.slots_per_chunk) / 64;
            let mut mask = 1u64 << (local % shard.slots_per_chunk % 64);
            for other in &mut entries[index + 1..] {
                if !other.slot.is_null() {
                    let candidate = other.handle;
                    let candidate_local = candidate.local_index as usize;
                    if candidate.shard == handle.shard
                        && candidate_local / shard.slots_per_chunk == chunk_index
                        && (candidate_local % shard.slots_per_chunk) / 64 == word
                    {
                        mask |= 1u64 << (candidate_local % shard.slots_per_chunk % 64);
                        other.slot = ptr::null();
                    }
                }
            }
            let chunk = unsafe { &*shard.chunks[chunk_index].load(Ordering::Acquire) };
            chunk.free_bitmap[word].fetch_or(mask, Ordering::Release);
        }
    }

    pub fn get(&self, handle: SlabHandle) -> Option<&T> {
        let shard = self.shards.get(handle.shard as usize)?;
        let slot = shard.slot(handle)?;
        Some(unsafe { &*slot.value.get() })
    }

    pub unsafe fn get_mut_ptr(&self, handle: SlabHandle) -> Option<*mut T> {
        let shard = self.shards.get(handle.shard as usize)?;
        let slot = shard.slot(handle)?;
        Some(slot.value.get())
    }

    pub unsafe fn release(&self, handle: SlabHandle) -> bool { unsafe {
        let Some(shard) = self.shards.get(handle.shard as usize) else {
            return false;
        };
        shard.release(handle)
    }}

    pub(crate) fn scan_slots(
        &self,
        cursor: &mut [usize; 3],
        remaining: &mut usize,
        mut visit: impl FnMut(SlabHandle, &T),
    ) -> bool
    where
        T: Sync,
    {
        while cursor[0] < self.shards.len() {
            let shard = &self.shards[cursor[0]];
            if cursor[1] >= shard.published_chunks.load(Ordering::Acquire) {
                cursor[0] += 1;
                cursor[1] = 0;
                cursor[2] = 0;
                continue;
            }
            let chunk = unsafe { &*shard.chunks[cursor[1]].load(Ordering::Acquire) };
            if cursor[2] == chunk.slots.len() {
                cursor[1] += 1;
                cursor[2] = 0;
                continue;
            }
            if *remaining == 0 {
                return false;
            }
            let index = cursor[2];
            cursor[2] += 1;
            *remaining -= 1;
            let slot = &chunk.slots[index];
            let state = slot.state.load(Ordering::Acquire);
            if state & 1 != 0 {
                visit(
                    SlabHandle {
                        shard: cursor[0] as u8,
                        local_index: (cursor[1] * shard.slots_per_chunk + index) as u32,
                        generation: state >> 1,
                    },
                    unsafe { &*slot.value.get() },
                );
            }
        }
        true
    }

    pub fn capacity(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.published_chunks.load(Ordering::Acquire) * shard.slots_per_chunk)
            .sum()
    }
}

#[cfg(all(test, not(any(loom, feature = "loom"))))]
mod tests {
    use super::GrowableSlab;
    use alloc::vec::Vec;

    fn zero() -> usize {
        0
    }

    #[test]
    fn grows_preserves_addresses_reuses_and_rejects_stale_handles() {
        let slab = GrowableSlab::<_, crate::test_support::TestExecutorPlatform>::new(1, 2, 4, zero);
        let first = slab.reserve().unwrap();
        let first_ptr = slab.get(first).unwrap() as *const usize;
        let second = slab.reserve().unwrap();
        let third = slab.reserve().unwrap();
        assert!(slab.capacity() >= 4);
        assert_eq!(first_ptr, slab.get(first).unwrap() as *const usize);

        unsafe {
            assert!(slab.release(second));
        }
        assert!(slab.get(second).is_none());
        let reused = slab.reserve().unwrap();
        assert_eq!(reused.local_index, second.local_index);
        assert_ne!(reused.generation, second.generation);
        assert!(slab.get(second).is_none());

        unsafe {
            assert!(slab.release(first));
            assert!(slab.release(third));
            assert!(slab.release(reused));
        }
    }

    #[test]
    fn concurrent_growth_publishes_initialized_slots() {
        let slab = std::sync::Arc::new(
            GrowableSlab::<_, crate::test_support::TestExecutorPlatform>::new(2, 2, 32, zero),
        );
        let handles = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let slab = slab.clone();
                let handles = handles.clone();
                scope.spawn(move || {
                    for _ in 0..8 {
                        let handle = slab.reserve().expect("concurrent slab exhausted");
                        assert_eq!(*slab.get(handle).expect("slot published before init"), 0);
                        handles.lock().unwrap().push(handle);
                    }
                });
            }
        });
        let handles = handles.lock().unwrap();
        assert_eq!(handles.len(), 64);
        for handle in handles.iter().copied() {
            unsafe {
                assert!(slab.release(handle));
            }
        }
    }
}
