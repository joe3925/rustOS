use core::future::Future;
use core::mem::MaybeUninit;
use core::ptr;

use spin::Once;

use crate::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::sync::spin_loop;

use super::super::runtime::submit_global;
use super::config::{SlabConfig, SlabConfigBuilder, SlabStats};
use super::ptr::{
    encode_joinable_slab_ptr, encode_slab_ptr, joinable_slab_poll_trampoline, slab_poll_trampoline,
};
use super::shard::{JoinableShard, SlabShard, SlotShard};
use super::slot::{JoinableSlot, SlabSlot, TaskSlot};
use super::storage::CachePadded;
use super::{
    DEFAULT_JOINABLE_SLOTS_PER_SHARD, MAX_JOINABLE_SLOTS_PER_SHARD, MAX_SLOTS_PER_SHARD,
    MIN_SLOTS_PER_SHARD, NUM_SHARDS,
};

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

static TASK_SLAB_PTR: Once<&'static TaskSlab> = Once::new();
static mut TASK_SLAB_STORAGE: MaybeUninit<TaskSlab> = MaybeUninit::uninit();

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

            match slot.gen_ref().compare_exchange_weak(
                cur,
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
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
            match slot.gen_ref().compare_exchange_weak(
                cur,
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
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
    pub(crate) fn get_slot(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> Option<&TaskSlot> {
        Self::get_slot_in(&self.shards, shard_idx, local_idx, expected_gen)
    }

    pub(crate) fn increment_ref(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> bool {
        Self::increment_ref_in(&self.shards, shard_idx, local_idx, expected_gen)
    }

    pub(crate) fn decrement_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) {
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
    pub(crate) fn get_joinable_slot(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> Option<&JoinableSlot> {
        Self::get_slot_in(&self.joinable_shards, shard_idx, local_idx, expected_gen)
    }

    pub(crate) fn increment_joinable_ref(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> bool {
        Self::increment_ref_in(&self.joinable_shards, shard_idx, local_idx, expected_gen)
    }

    pub(crate) fn decrement_joinable_ref(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) {
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
    shard_idx: u8,
    local_idx: u16,
    generation: u32,
}

impl<'a> JoinableSlotHandle<'a> {
    pub fn init_and_enqueue<F, T>(self, future: F) -> (u8, u16, u32)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        if let Some(slot) = self.slab.get_joinable_slot(
            self.shard_idx as usize,
            self.local_idx as usize,
            self.generation,
        ) {
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
