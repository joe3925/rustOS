use super::{DEFAULT_SLOTS_PER_SHARD, MAX_SLOTS_PER_SHARD, MIN_SLOTS_PER_SHARD, NUM_SHARDS};

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

impl Default for SlabConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SlabConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: SlabConfig::default(),
        }
    }

    pub fn capacity(mut self, total: usize) -> Self {
        self.config.slots_per_shard = total
            .div_ceil(NUM_SHARDS)
            .min(MAX_SLOTS_PER_SHARD)
            .max(MIN_SLOTS_PER_SHARD);
        self
    }

    pub fn slots_per_shard(mut self, slots: usize) -> Self {
        self.config.slots_per_shard = slots.min(MAX_SLOTS_PER_SHARD).max(MIN_SLOTS_PER_SHARD);
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
