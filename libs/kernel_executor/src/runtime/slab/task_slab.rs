use core::mem::MaybeUninit;

use spin::Once;

use crate::growable_slab::{GrowableSlab, SlabHandle};
use crate::sync::atomic::{AtomicU64, Ordering};

use super::config::{SlabConfig, SlabConfigBuilder, SlabStats};
use super::ptr::encode_slab_task_ptr;
use super::slot::TaskSlot;
use super::{MAX_SLOTS_PER_SHARD, MIN_SLOTS_PER_SHARD, NUM_SHARDS};

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

fn new_task_slot() -> TaskSlot {
    TaskSlot::new()
}

static TASK_TABLE_PTR: Once<&'static TaskTable> = Once::new();
static mut TASK_TABLE_STORAGE: MaybeUninit<TaskTable> = MaybeUninit::uninit();

pub struct TaskTable {
    slab: GrowableSlab<TaskSlot>,
    total_allocations: AtomicU64,
}

impl TaskTable {
    fn new(mut config: SlabConfig) -> Self {
        config.slots_per_shard = config
            .slots_per_shard
            .clamp(MIN_SLOTS_PER_SHARD, MAX_SLOTS_PER_SHARD);
        let max_chunks = (1usize << 16) / config.slots_per_shard;
        Self {
            slab: GrowableSlab::new(
                NUM_SHARDS,
                config.slots_per_shard,
                max_chunks,
                new_task_slot,
            ),
            total_allocations: AtomicU64::new(0),
        }
    }

    pub fn allocate(&self) -> Option<SlotHandle> {
        let handle = self.slab.reserve()?;
        let slot = self.slab.get(handle)?;
        slot.prepare_for_allocation();
        slot.gen_ref
            .store(pack_gen_ref(handle.generation, 1), Ordering::Release);
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        Some(SlotHandle { handle })
    }

    #[inline]
    fn make_handle(&self, shard: usize, local: usize, generation: u32) -> Option<SlabHandle> {
        if shard >= NUM_SHARDS || local > u16::MAX as usize {
            return None;
        }
        Some(SlabHandle {
            shard: shard as u8,
            local_index: local as u16,
            generation: generation & GEN_MASK,
        })
    }

    #[inline]
    pub(crate) fn get_slot(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> Option<&TaskSlot> {
        let handle = self.make_handle(shard_idx, local_idx, expected_gen)?;
        let slot = self.slab.get(handle)?;
        let packed = slot.gen_ref.load(Ordering::Acquire);
        (unpack_gen(packed) == (expected_gen & GEN_MASK)).then_some(slot)
    }

    pub(crate) fn increment_ref(
        &self,
        shard_idx: usize,
        local_idx: usize,
        expected_gen: u32,
    ) -> bool {
        let Some(slot) = self.get_slot(shard_idx, local_idx, expected_gen) else {
            return false;
        };
        let expected_gen = expected_gen & GEN_MASK;
        loop {
            let current = slot.gen_ref.load(Ordering::Acquire);
            if unpack_gen(current) != expected_gen {
                return false;
            }
            let refs = unpack_ref(current);
            if refs == 0 || refs == REF_MASK {
                return false;
            }
            match slot.gen_ref.compare_exchange(
                current,
                pack_gen_ref(expected_gen, refs + 1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next) if unpack_gen(next) != expected_gen => return false,
                Err(_) => core::hint::spin_loop(),
            }
        }
    }

    pub(crate) fn decrement_ref(&self, shard_idx: usize, local_idx: usize, expected_gen: u32) {
        let Some(handle) = self.make_handle(shard_idx, local_idx, expected_gen) else {
            return;
        };
        let Some(slot) = self.slab.get(handle) else {
            return;
        };
        let expected_gen = expected_gen & GEN_MASK;
        loop {
            let current = slot.gen_ref.load(Ordering::Acquire);
            if unpack_gen(current) != expected_gen {
                return;
            }
            let refs = unpack_ref(current);
            if refs == 0 {
                return;
            }
            match slot.gen_ref.compare_exchange(
                current,
                pack_gen_ref(expected_gen, refs - 1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if refs == 1 {
                        slot.release_last_ref();
                        unsafe {
                            let _ = self.slab.release(handle);
                        }
                    }
                    return;
                }
                Err(next) if unpack_gen(next) != expected_gen => return,
                Err(_) => core::hint::spin_loop(),
            }
        }
    }

    pub fn stats(&self) -> SlabStats {
        SlabStats {
            total_capacity: self.slab.capacity(),
            currently_allocated: self.slab.allocated_count(),
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
        }
    }
}

pub struct SlotHandle {
    handle: SlabHandle,
}

impl SlotHandle {
    #[inline]
    pub fn encoded_ptr(&self) -> usize {
        encode_slab_task_ptr(
            self.handle.shard,
            self.handle.local_index,
            self.handle.generation,
        )
    }

    #[inline]
    pub fn indices(&self) -> (usize, usize, u32) {
        (
            self.handle.shard as usize,
            self.handle.local_index as usize,
            self.handle.generation,
        )
    }
}

pub fn init_task_table(config: SlabConfig) {
    TASK_TABLE_PTR.call_once(|| unsafe {
        let ptr = core::ptr::addr_of_mut!(TASK_TABLE_STORAGE).cast::<TaskTable>();
        ptr.write(TaskTable::new(config));
        &*ptr
    });
}

pub fn init_task_table_with<F>(configure: F)
where
    F: FnOnce(SlabConfigBuilder) -> SlabConfigBuilder,
{
    init_task_table(configure(SlabConfigBuilder::new()).build());
}

pub fn get_task_table() -> &'static TaskTable {
    TASK_TABLE_PTR.call_once(|| unsafe {
        let ptr = core::ptr::addr_of_mut!(TASK_TABLE_STORAGE).cast::<TaskTable>();
        ptr.write(TaskTable::new(SlabConfig::default()));
        &*ptr
    })
}

pub fn slab_stats() -> SlabStats {
    get_task_table().stats()
}
