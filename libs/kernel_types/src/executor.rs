pub const USER_EXECUTOR_ABI_VERSION: u32 = 1;
pub const USER_EXECUTOR_PROFILE_GENERAL: u32 = 0;

pub const USER_EXECUTOR_RESIZE_FIXED: u32 = 0;
pub const USER_EXECUTOR_RESIZE_LINEAR: u32 = 1;
pub const USER_EXECUTOR_RESIZE_GEOMETRIC: u32 = 2;

pub const USER_EXECUTOR_UPDATE_MAX_ACTIVE: u32 = 1 << 0;
pub const USER_EXECUTOR_UPDATE_RESIZE_POLICY: u32 = 1 << 1;
pub const USER_EXECUTOR_UPDATE_ALL: u32 =
    USER_EXECUTOR_UPDATE_MAX_ACTIVE | USER_EXECUTOR_UPDATE_RESIZE_POLICY;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorResizePolicy {
    pub kind: u32,
    pub shrink_trigger_percent: u32,
    pub shrink_target_percent: u32,
    pub reserved: u32,
    pub minimum_capacity: usize,
    pub grow_by_or_factor: usize,
    pub shrink_by: usize,
    /// Zero means that no configured maximum is imposed.
    pub maximum_capacity: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainCreate {
    pub version: u32,
    pub profile: u32,
    pub initial_queue_capacity: usize,
    /// Zero means unlimited.
    pub max_active_tasks: usize,
    pub resize_policy: UserExecutorResizePolicy,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainUpdate {
    pub version: u32,
    pub fields: u32,
    /// Zero means unlimited.
    pub max_active_tasks: usize,
    pub resize_policy: UserExecutorResizePolicy,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainInfo {
    pub version: u32,
    pub profile: u32,
    pub state: u32,
    pub resize_policy_kind: u32,
    pub max_active_tasks: usize,
    pub initial_queue_capacity: usize,
    pub queue_capacity: usize,
    pub queue_minimum_capacity: usize,
    /// Zero means that no configured maximum is imposed.
    pub queue_maximum_capacity: usize,
    pub queued_tasks: usize,
    pub active_tasks: usize,
    pub live_tasks: usize,
    pub live_futures: usize,
    pub live_future_bytes: usize,
    pub resize_policy: UserExecutorResizePolicy,
}
