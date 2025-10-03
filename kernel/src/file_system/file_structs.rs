use alloc::{string::String, vec::Vec};

use crate::file_system::file::OpenFlags;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    NotFound,
    AlreadyExists,
    NotADirectory,
    IsDirectory,
    BadPath,
    Corrupt,
    Unsupported,
    AccessDenied,
    NoSpace,
    IoError,
    Unknown,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsOpenParams {
    pub flags: OpenFlags,
    pub path: String,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsOpenResult {
    pub fs_file_id: u64,
    pub is_dir: bool,
    pub size: u64,
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCloseParams {
    pub fs_file_id: u64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCloseResult {
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsReadParams {
    pub fs_file_id: u64,
    pub offset: u64,
    pub len: usize,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsReadResult {
    pub data: Vec<u8>,
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsWriteParams {
    pub fs_file_id: u64,
    pub offset: u64,
    pub data: Vec<u8>,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsWriteResult {
    pub written: usize,
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FsSeekWhence {
    Set,
    Cur,
    End,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsSeekParams {
    pub fs_file_id: u64,
    pub origin: FsSeekWhence,
    pub offset: i64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsSeekResult {
    pub pos: u64,
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsFlushParams {
    pub fs_file_id: u64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsFlushResult {
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCreateParams {
    pub path: String,
    pub dir: bool,
    pub flags: OpenFlags,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCreateResult {
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsRenameParams {
    pub src: String,
    pub dst: String,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsRenameResult {
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsListDirParams {
    pub path: String,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsListDirResult {
    pub names: Vec<String>,
    pub error: Option<FileError>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsGetInfoParams {
    pub fs_file_id: u64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsGetInfoResult {
    pub size: u64,
    pub is_dir: bool,
    pub attrs: u32,
    pub error: Option<FileError>,
}
