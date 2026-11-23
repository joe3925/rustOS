pub const USER_EXECUTOR_UPDATE_WEIGHT: u32 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainCreate {
    pub weight: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainUpdate {
    pub fields: u32,
    pub weight: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserExecutorDomainInfo {
    pub state: u32,
    pub reserved: u32,
    pub weight: u64,
}
