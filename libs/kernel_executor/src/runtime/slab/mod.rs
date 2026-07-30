pub const JOINABLE_STORAGE_SIZE: usize = 480;
pub const INLINE_FUTURE_ALIGN: usize = 8;

pub(super) const NUM_SHARDS: usize = 8;

pub(super) const MIN_SLOTS_PER_SHARD: usize = 64;
pub(super) const DEFAULT_SLOTS_PER_SHARD: usize = 128;
pub(super) const MAX_SLOTS_PER_SHARD: usize = 4096;

mod config;
mod ptr;
pub(crate) mod slot;
mod storage;
mod task_slab;

#[cfg(test)]
mod tests;

pub use config::{SlabConfig, SlabConfigBuilder, SlabStats};
pub use ptr::{
    decode_slab_task_ptr, encode_slab_task_ptr, enqueue_slab_task, slab_task_poll_trampoline,
};
pub use slot::{NotifyResult, TaskSlot};
pub use task_slab::{
    get_task_table, init_task_table, init_task_table_with, slab_stats, SlotHandle, TaskTable,
};
