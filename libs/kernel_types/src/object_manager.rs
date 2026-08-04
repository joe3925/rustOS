#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmError {
    InvalidPath,
    NotFound,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    IsSymlink,
    LoopDetected,
    Unsupported,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectTag {
    Directory,
    Symlink,
    Generic,

    Program,
    Thread,
    Queue,
    CompletionQueue,
    File,
    Module,
    Device,
    IoBufferBacking,
    ExecutorDomain,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectInformationClass {
    Basic = 0,
    ExecutorDomain = 1,
    Module = 2,
    Program = 3,
    Queue = 4,
    IoBufferBacking = 5,
    Device = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserObjectBasicInfo {
    pub object_type: u32,
    pub reserved: u32,
    pub granted_interfaces: u64,
    pub supported_interfaces: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserModuleInfo {
    pub image_base: u64,
    pub image_size: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserProgramInfo {
    pub pid: u64,
    pub image_base: u64,
    pub managed_threads: u64,
    pub loaded_modules: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserQueueInfo {
    pub queued_messages: u64,
    pub closed: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserIoBufferBackingInfo {
    pub length: u64,
    pub access: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserDeviceInfo {
    pub generation: u64,
    pub protocol_generation: u64,
    pub dispatch_tickets: u32,
    pub started: u32,
    pub removed: u32,
    pub reserved: u32,
}
