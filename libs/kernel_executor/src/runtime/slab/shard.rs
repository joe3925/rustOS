use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicPtr, Ordering as CoreOrdering};

use crate::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::sync::spin_loop;

use super::slot::TaskSlot;
use super::storage::CachePadded;
use super::{MAX_SLOTS_PER_SHARD, MIN_SLOTS_PER_SHARD};

pub(super) struct TaskChunk {
    pub(super) free_bitmap: Box<[AtomicU64]>,
    pub(super) slots: Box<[TaskSlot]>,
}

impl TaskChunk {
    pub(super) fn new(num_slots: usize) -> Self {
        let num_slots = num_slots.min(MAX_SLOTS_PER_SHARD).max(MIN_SLOTS_PER_SHARD);
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
            slots.push(TaskSlot::new());
        }

        Self {
            free_bitmap: bitmap.into_boxed_slice(),
            slots: slots.into_boxed_slice(),
        }
    }
}

pub(super) struct SlabShard {
    pub(super) slots_per_chunk: usize,
    pub(super) max_chunks: usize,
    pub(super) chunks: Box<[AtomicPtr<TaskChunk>]>,
    pub(super) published_chunks: AtomicUsize,
    pub(super) alloc_hint: CachePadded<AtomicUsize>,
    pub(super) allocated_count: CachePadded<AtomicUsize>,
}

impl SlabShard {
    pub(super) fn new(slots_per_chunk: usize) -> Self {
        let slots_per_chunk = slots_per_chunk
            .min(MAX_SLOTS_PER_SHARD)
            .max(MIN_SLOTS_PER_SHARD);
        let max_addressable_slots = 1 << 16;
        let max_chunks = max_addressable_slots / slots_per_chunk;

        let mut chunks = Vec::with_capacity(max_chunks);
        for _ in 0..max_chunks {
            chunks.push(AtomicPtr::new(core::ptr::null_mut()));
        }

        let shard = Self {
            slots_per_chunk,
            max_chunks,
            chunks: chunks.into_boxed_slice(),
            published_chunks: AtomicUsize::new(0),
            alloc_hint: CachePadded::new(AtomicUsize::new(0)),
            allocated_count: CachePadded::new(AtomicUsize::new(0)),
        };

        shard.grow_chunk_internal();
        shard
    }

    fn grow_chunk_internal(&self) -> bool {
        let published = self.published_chunks.load(Ordering::Acquire);
        if published >= self.max_chunks {
            return false; // Reached capacity
        }

        let new_chunk = Box::into_raw(Box::new(TaskChunk::new(self.slots_per_chunk)));

        match self.chunks[published].compare_exchange(
            core::ptr::null_mut(),
            new_chunk,
            CoreOrdering::AcqRel,
            CoreOrdering::Acquire,
        ) {
            Ok(_) => {
                let _ = self.published_chunks.compare_exchange(
                    published,
                    published + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                true
            }
            Err(_) => {
                unsafe { drop(Box::from_raw(new_chunk)) };
                let current_val = self.chunks[published].load(CoreOrdering::Acquire);
                if !current_val.is_null() {
                    let _ = self.published_chunks.compare_exchange(
                        published,
                        published + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                true // Did not grow ourselves but someone else did
            }
        }
    }

    pub(super) fn try_allocate(&self) -> Option<usize> {
        let hint = self.alloc_hint.load(Ordering::Relaxed);
        let published = self.published_chunks.load(Ordering::Acquire);
        let total_slots = published * self.slots_per_chunk;
        let num_words_per_chunk = self.slots_per_chunk.div_ceil(64);
        let total_words = published * num_words_per_chunk;

        if total_words == 0 {
            return None;
        }

        for offset in 0..total_words {
            let word_idx_global = (hint / 64 + offset) % total_words;
            let chunk_idx = word_idx_global / num_words_per_chunk;
            let word_idx_local = word_idx_global % num_words_per_chunk;

            let chunk_ptr = self.chunks[chunk_idx].load(CoreOrdering::Acquire);
            if chunk_ptr.is_null() {
                continue;
            }
            let chunk = unsafe { &*chunk_ptr };

            let word = &chunk.free_bitmap[word_idx_local];

            loop {
                let bits = word.load(Ordering::Relaxed);
                if bits == 0 {
                    break;
                }

                let bit_idx = bits.trailing_zeros() as usize;
                let slot_idx_local = word_idx_local * 64 + bit_idx;

                if slot_idx_local >= self.slots_per_chunk {
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
                        let global_slot_idx = chunk_idx * self.slots_per_chunk + slot_idx_local;
                        self.alloc_hint
                            .store((global_slot_idx + 1) % total_slots, Ordering::Relaxed);
                        self.allocated_count.fetch_add(1, Ordering::Relaxed);
                        return Some(global_slot_idx);
                    }
                    Err(_) => {
                        spin_loop();
                        continue;
                    }
                }
            }
        }

        if self.grow_chunk_internal() {
            return self.try_allocate();
        }

        None
    }

    pub(super) fn deallocate(&self, slot_idx: usize) {
        let chunk_idx = slot_idx / self.slots_per_chunk;
        let slot_idx_local = slot_idx % self.slots_per_chunk;

        let chunk_ptr = self.chunks[chunk_idx].load(CoreOrdering::Acquire);
        if chunk_ptr.is_null() {
            return;
        }
        let chunk = unsafe { &*chunk_ptr };

        let word_idx = slot_idx_local / 64;
        let bit_idx = slot_idx_local % 64;
        let mask = 1u64 << bit_idx;

        chunk.free_bitmap[word_idx].fetch_or(mask, Ordering::Relaxed);
        self.alloc_hint.store(slot_idx, Ordering::Relaxed);
        self.allocated_count.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub(super) fn get_slot(&self, idx: usize) -> Option<&TaskSlot> {
        let chunk_idx = idx / self.slots_per_chunk;
        let slot_idx_local = idx % self.slots_per_chunk;

        let published = self.published_chunks.load(Ordering::Acquire);
        if chunk_idx >= published {
            return None;
        }

        let chunk_ptr = self.chunks[chunk_idx].load(CoreOrdering::Acquire);
        if chunk_ptr.is_null() {
            return None;
        }

        let chunk = unsafe { &*chunk_ptr };
        if slot_idx_local >= self.slots_per_chunk {
            return None;
        }
        Some(&chunk.slots[slot_idx_local])
    }
}
