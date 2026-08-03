pub const USER_EXECUTOR_UPDATE_MAX_ACTIVE: u32 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainCreate {
    /// Zero means unlimited.
    pub max_active_tasks: usize,
    /// Zero selects the executor CPU count. Other values are clamped to the
    /// kernel's supported ready-shard range.
    pub ready_shards: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainUpdate {
    pub fields: u32,
    /// Zero means unlimited.
    pub max_active_tasks: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainInfo {
    pub state: u32,
    pub max_active_tasks: usize,
    pub queued_tasks: usize,
    pub active_tasks: usize,
    pub live_tasks: usize,
    pub live_futures: usize,
    pub live_future_bytes: usize,
    pub ready_shards: usize,
}
