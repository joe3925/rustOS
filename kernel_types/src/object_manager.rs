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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectTag {
    Directory,
    Symlink,
    Generic,

    Program,
    Thread,
    Queue,
    Module,
    Device,
}
