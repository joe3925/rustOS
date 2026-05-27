use alloc::{boxed::Box, vec::Vec};

use crate::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::sync::spin_loop;

use super::slot::{JoinableSlot, SlabSlot, TaskSlot};
use super::storage::CachePadded;
use super::{
    MAX_JOINABLE_SLOTS_PER_SHARD, MAX_SLOTS_PER_SHARD, MIN_JOINABLE_SLOTS_PER_SHARD,
    MIN_SLOTS_PER_SHARD,
};

pub(super) struct SlotShard<S, const MIN_SLOTS: usize, const MAX_SLOTS: usize> {
    pub(super) free_bitmap: Box<[AtomicU64]>,
    pub(super) alloc_hint: CachePadded<AtomicUsize>,
    pub(super) slots: Box<[S]>,
    pub(super) active_slots: usize,
    pub(super) allocated_count: CachePadded<AtomicUsize>,
}

impl<S, const MIN_SLOTS: usize, const MAX_SLOTS: usize> SlotShard<S, MIN_SLOTS, MAX_SLOTS>
where
    S: SlabSlot,
{
    pub(super) fn new(num_slots: usize) -> Self {
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

    pub(super) fn try_allocate(&self) -> Option<usize> {
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

    pub(super) fn deallocate(&self, slot_idx: usize) {
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
    pub(super) fn get_slot(&self, idx: usize) -> Option<&S> {
        if idx >= self.active_slots {
            return None;
        }
        Some(&self.slots[idx])
    }
}

pub(super) type SlabShard = SlotShard<TaskSlot, MIN_SLOTS_PER_SHARD, MAX_SLOTS_PER_SHARD>;
pub(super) type JoinableShard =
    SlotShard<JoinableSlot, MIN_JOINABLE_SLOTS_PER_SHARD, MAX_JOINABLE_SLOTS_PER_SHARD>;
