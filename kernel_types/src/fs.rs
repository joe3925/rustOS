use crate::status::FileStatus;
use alloc::string::{String, ToString};
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
    WriteThrough = 1 << 6,
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
    SetLen,
    Append,
    ZeroRange,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsOpenParams {
    pub flags: OpenFlagsMask,
    pub write_through: bool,
    pub path: Path,
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
    pub write_through: bool,
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
    pub path: Path,
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
    pub src: Path,
    pub dst: Path,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsRenameResult {
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsListDirParams {
    pub path: Path,
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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsSetLenParams {
    pub fs_file_id: u64,
    pub new_size: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsSetLenResult {
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsAppendParams {
    pub fs_file_id: u64,
    pub data: Vec<u8>,
    pub write_through: bool,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsAppendResult {
    pub written: usize,
    pub new_size: u64,
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsZeroRangeParams {
    pub fs_file_id: u64,
    pub offset: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsZeroRangeResult {
    pub error: Option<FileStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Path {
    pub symlink: Option<char>,
    pub components: Vec<String>,
}

impl Path {
    pub fn from_string(raw: &str) -> Self {
        let b = raw.as_bytes();
        let mut drive = None;
        let mut start = 0;

        if b.len() >= 2 && b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
            drive = Some(b[0] as char);
            start = 2;
        }

        if b.get(start) == Some(&b'\\') || b.get(start) == Some(&b'/') {
            start += 1;
        }

        let comps = raw[start..]
            .split(['\\', '/'])
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        Self {
            symlink: drive,
            components: comps,
        }
    }
    pub fn parse(raw: &str, base: Option<&Self>) -> Self {
        let b = raw.as_bytes();

        if b.len() >= 2 && b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
            let d = b[0] as char;
            if b.len() == 2 {
                return Self {
                    symlink: Some(d),
                    components: Vec::new(),
                };
            }
            if b.get(2) == Some(&b'\\') || b.get(2) == Some(&b'/') {
                Self::from_string(raw)
            } else if let Some(base) = base {
                let mut out = base.clone();
                out.symlink = Some(d);
                out.join(&raw[2..])
            } else {
                panic!("Relative path {} given with no base", raw);
            }
        } else if b.first() == Some(&b'\\') || b.first() == Some(&b'/') {
            if let Some(base) = base {
                let out = Self {
                    symlink: base.symlink,
                    components: Vec::new(),
                };
                out.join(&raw[1..])
            } else {
                panic!("Root-relative {} given with no base drive", raw);
            }
        } else if let Some(base) = base {
            base.clone().join(raw)
        } else {
            panic!("Relative path {} given with no base", raw);
        }
    }

    pub fn join(mut self, rel: &str) -> Self {
        for comp in rel.split(['\\', '/']) {
            if comp.is_empty() || comp == "." {
                continue;
            } else if comp == ".." {
                if !self.components.is_empty() {
                    self.components.pop();
                }
            } else {
                self.components.push(comp.to_string());
            }
        }
        self
    }

    pub fn push(&mut self, comp: &str) {
        if comp.is_empty() {
            return;
        }
        self.components.push(comp.to_string());
    }

    pub fn pop(&mut self) -> Option<String> {
        self.components.pop()
    }

    pub fn parent(&self) -> Option<Self> {
        if self.components.is_empty() {
            return None;
        }
        let mut out = self.clone();
        out.components.pop();
        Some(out)
    }

    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(|s| s.as_str())
    }

    pub fn with_symlink(mut self, symlink: Option<char>) -> Self {
        self.symlink = symlink;
        self
    }

    pub fn normalize(&mut self) {
        let mut new_comps = Vec::new();
        for comp in &self.components {
            if comp == "." {
                continue;
            } else if comp == ".." {
                if !new_comps.is_empty() {
                    new_comps.pop();
                }
            } else {
                new_comps.push(comp.clone());
            }
        }
        self.components = new_comps;
    }

    pub fn to_string(&self) -> String {
        match self.symlink {
            Some(d) => {
                let mut s = String::new();
                s.push(d);
                s.push(':');
                s.push('/');
                if !self.components.is_empty() {
                    s.push_str(&self.components.join("/"));
                }
                s
            }
            None => self.components.join("/"),
        }
    }
}
