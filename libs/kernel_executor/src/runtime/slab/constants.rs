pub const JOINABLE_STORAGE_SIZE: usize = 480;
pub const INLINE_FUTURE_ALIGN: usize = 8;

pub(super) const NUM_SHARDS: usize = 8;

pub(super) const MIN_SLOTS_PER_SHARD: usize = 64;
pub(super) const DEFAULT_SLOTS_PER_SHARD: usize = 128;
pub(super) const MAX_SLOTS_PER_SHARD: usize = 4096;
pub(crate) const MAX_TASK_SLOTS: usize = NUM_SHARDS * MAX_SLOTS_PER_SHARD;
