use crate::status::FileStatus;
use alloc::string::String;
use alloc::vec::Vec;

#[repr(C)]
pub struct File {
    _private: [u8; 0],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileAttribute {
    ReadOnly = 0x01,
    Hidden = 0x02,
    System = 0x04,
    VolumeLabel = 0x08,
    LFN = 0x0F,
    Directory = 0x10,
    Archive = 0x20,
    Unknown = 0xFF,
}
impl From<FileAttribute> for u8 {
    fn from(attribute: FileAttribute) -> Self {
        attribute as u8
    }
}
impl TryFrom<u8> for FileAttribute {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => FileAttribute::ReadOnly,
            0x02 => FileAttribute::Hidden,
            0x04 => FileAttribute::System,
            0x08 => FileAttribute::VolumeLabel,
            0x0F => FileAttribute::LFN,
            0x10 => FileAttribute::Directory,
            0x20 => FileAttribute::Archive,
            _ => FileAttribute::Unknown,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenFlags {
    ReadOnly = 1 << 0,
    WriteOnly = 1 << 1,
    ReadWrite = 1 << 2,
    Create = 1 << 3,
    CreateNew = 1 << 4,
    Open = 1 << 5,
}

/// A bitmask of `OpenFlags` for passing multiple flags efficiently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct OpenFlagsMask(pub u32);

impl OpenFlagsMask {
    pub const fn new() -> Self {
        Self(0)
    }

    pub const fn with(self, flag: OpenFlags) -> Self {
        Self(self.0 | flag as u32)
    }

    pub const fn contains(self, flag: OpenFlags) -> bool {
        (self.0 & flag as u32) != 0
    }

    pub const fn from_flag(flag: OpenFlags) -> Self {
        Self(flag as u32)
    }
}

impl From<OpenFlags> for OpenFlagsMask {
    fn from(flag: OpenFlags) -> Self {
        Self::from_flag(flag)
    }
}

impl From<&[OpenFlags]> for OpenFlagsMask {
    fn from(flags: &[OpenFlags]) -> Self {
        let mut mask = Self::new();
        for &f in flags {
            mask = mask.with(f);
        }
        mask
    }
}

impl core::ops::BitOr for OpenFlags {
    type Output = OpenFlagsMask;
    fn bitor(self, rhs: Self) -> OpenFlagsMask {
        OpenFlagsMask::from_flag(self).with(rhs)
    }
}

impl core::ops::BitOr<OpenFlags> for OpenFlagsMask {
    type Output = OpenFlagsMask;
    fn bitor(self, rhs: OpenFlags) -> OpenFlagsMask {
        self.with(rhs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum FsOp {
    Create,
    Open,
    Close,
    Read,
    Write,
    Flush,
    Seek,
    ReadDir,
    GetInfo,
    SetInfo,
    Delete,
    Rename,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsOpenParams {
    pub flags: OpenFlagsMask,
    pub path: String,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsOpenResult {
    pub fs_file_id: u64,
    pub is_dir: bool,
    pub size: u64,
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCloseParams {
    pub fs_file_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCloseResult {
    pub error: Option<FileStatus>,
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
    pub error: Option<FileStatus>,
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
    pub error: Option<FileStatus>,
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
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsFlushParams {
    pub fs_file_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsFlushResult {
    pub error: Option<FileStatus>,
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
    pub error: Option<FileStatus>,
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
    pub error: Option<FileStatus>,
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
    pub error: Option<FileStatus>,
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
    pub error: Option<FileStatus>,
}
