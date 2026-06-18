pub const INLINE_FUTURE_SIZE: usize = 5096;
pub const JOINABLE_STORAGE_SIZE: usize = 480;
pub const INLINE_FUTURE_ALIGN: usize = 8;

pub(super) const NUM_SHARDS: usize = 8;

pub(super) const MIN_SLOTS_PER_SHARD: usize = 64;
pub(super) const DEFAULT_SLOTS_PER_SHARD: usize = 128;
pub(super) const MAX_SLOTS_PER_SHARD: usize = 4096;

pub(super) const MIN_JOINABLE_SLOTS_PER_SHARD: usize = 32;
pub(super) const DEFAULT_JOINABLE_SLOTS_PER_SHARD: usize = 64;
pub(super) const MAX_JOINABLE_SLOTS_PER_SHARD: usize = 1024;

mod config;
mod ptr;
mod shard;
mod slot;
mod storage;
mod task_slab;

#[cfg(test)]
mod tests;

pub use config::{SlabConfig, SlabConfigBuilder, SlabStats};
pub use ptr::{
    decode_joinable_slab_ptr, decode_slab_ptr, encode_joinable_slab_ptr, encode_slab_ptr,
    enqueue_joinable_slab_task, enqueue_slab_task, is_joinable_slab_ptr, is_slab_ptr,
    joinable_slab_poll_trampoline, slab_poll_trampoline,
};
pub use slot::{JoinableSlot, NotifyResult, TaskSlot};
pub use task_slab::{
    get_task_slab, init_task_slab, init_task_slab_with, slab_stats, JoinableSlotHandle, SlotHandle,
    TaskSlab,
};
