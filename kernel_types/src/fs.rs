use crate::status::FileStatus;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ptr;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

const SPAN_ZERO: Span = Span { start: 0, end: 0 };

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Components64 {
    buf: [Span; 64],
    len: u8,
}

impl Components64 {
    pub const fn new() -> Self {
        Self {
            buf: [SPAN_ZERO; 64],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[Span] {
        &self.buf[..self.len()]
    }

    fn clear_(&mut self) {
        self.len = 0;
    }

    fn last_(&self) -> Option<Span> {
        let n = self.len();
        if n == 0 { None } else { Some(self.buf[n - 1]) }
    }

    fn push_(&mut self, span: Span) {
        let n = self.len();
        if n >= 64 {
            panic!("Path has more than 64 components");
        }
        self.buf[n] = span;
        self.len = (n as u8) + 1;
    }

    fn pop_(&mut self) -> Option<Span> {
        let n = self.len();
        if n == 0 {
            return None;
        }
        let new_n = n - 1;
        self.len = new_n as u8;
        Some(self.buf[new_n])
    }
}

impl Default for Components64 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::ops::Deref for Components64 {
    type Target = [Span];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl core::fmt::Debug for Components64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice().iter()).finish()
    }
}

impl<'a> IntoIterator for &'a Components64 {
    type Item = &'a Span;
    type IntoIter = core::slice::Iter<'a, Span>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

pub struct Components64IntoIter {
    buf: [Span; 64],
    idx: usize,
    len: usize,
}

impl Iterator for Components64IntoIter {
    type Item = Span;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.len {
            None
        } else {
            let v = self.buf[self.idx];
            self.idx += 1;
            Some(v)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.len - self.idx;
        (rem, Some(rem))
    }
}

impl ExactSizeIterator for Components64IntoIter {}
impl core::iter::FusedIterator for Components64IntoIter {}

impl IntoIterator for Components64 {
    type Item = Span;
    type IntoIter = Components64IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        Components64IntoIter {
            buf: self.buf,
            idx: 0,
            len: self.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Path {
    pub symlink: Option<char>,
    pub components: Components64,
    raw: String,
}

impl Path {
    pub fn from_symlink(d: char) -> Self {
        if !d.is_ascii_alphabetic() {
            panic!("Invalid symlink {}", d);
        }
        Self::empty_with_symlink(Some(d))
    }

    pub fn from_string(raw: &str) -> Self {
        Self::from_string_owned(raw.to_string())
    }

    // Consumes the String and normalizes separators in-place. No new String allocation.
    pub fn from_string_owned(raw: String) -> Self {
        let mut bytes = raw.into_bytes();

        let mut drive = None;
        if bytes.len() >= 2 && bytes[1] == b':' && (bytes[0] as char).is_ascii_alphabetic() {
            drive = Some(bytes[0] as char);
        }

        let mut read = 0usize;
        let mut write = 0usize;

        if let Some(d) = drive {
            if bytes.len() == 2 {
                bytes.push(b'/');
            } else if bytes.get(2) != Some(&b'\\') && bytes.get(2) != Some(&b'/') {
                let old_len = bytes.len();
                bytes.push(0);
                bytes.copy_within(2..old_len, 3);
            }

            bytes[0] = d as u8;
            bytes[1] = b':';
            bytes[2] = b'/';
            read = 3;
            write = 3;
        } else {
            if bytes.first() == Some(&b'\\') || bytes.first() == Some(&b'/') {
                read = 1;
            }
            write = 0;
        }

        let mut comps = Components64::new();
        let mut have_any = false;

        while read < bytes.len() {
            while read < bytes.len() && (bytes[read] == b'\\' || bytes[read] == b'/') {
                read += 1;
            }
            if read >= bytes.len() {
                break;
            }

            let comp_start = read;
            while read < bytes.len() && bytes[read] != b'\\' && bytes[read] != b'/' {
                read += 1;
            }
            let comp_end = read;

            if comp_end == comp_start {
                continue;
            }

            if have_any {
                bytes[write] = b'/';
                write += 1;
            } else {
                have_any = true;
            }

            let start = write;
            let n = comp_end - comp_start;
            unsafe {
                ptr::copy(
                    bytes.as_ptr().add(comp_start),
                    bytes.as_mut_ptr().add(write),
                    n,
                );
            }
            write += n;
            let end = write;

            comps.push_(Span { start, end });
        }

        bytes.truncate(write);
        let raw = unsafe { String::from_utf8_unchecked(bytes) };

        Self {
            symlink: drive,
            components: comps,
            raw,
        }
    }

    pub fn parse(raw: &str, base: Option<&Self>) -> Self {
        let b = raw.as_bytes();

        if b.len() >= 2 && b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
            let d = b[0] as char;
            if b.len() == 2 {
                return Self::from_symlink(d);
            }
            if b.get(2) == Some(&b'\\') || b.get(2) == Some(&b'/') {
                Self::from_string(raw)
            } else if let Some(base) = base {
                let mut out = base.clone();
                out.set_symlink(Some(d));
                out.join(&raw[2..])
            } else {
                panic!("Relative path {} given with no base", raw);
            }
        } else if b.first() == Some(&b'\\') || b.first() == Some(&b'/') {
            if let Some(base) = base {
                let out = Self::empty_with_symlink(base.symlink);
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
                self.pop_in_place();
            } else {
                self.push_in_place(comp);
            }
        }
        self
    }

    pub fn push(&mut self, comp: &str) {
        if comp.is_empty() {
            return;
        }
        self.push_in_place(comp);
    }

    pub fn pop(&mut self) -> Option<String> {
        let span = match self.components.pop_() {
            Some(s) => s,
            None => return None,
        };

        let out = self.span_str(span).to_string();

        let new_len = match self.components.last_() {
            Some(last) => last.end,
            None => self.prefix_len(),
        };
        self.raw.truncate(new_len);

        Some(out)
    }

    pub fn parent(&self) -> Option<Self> {
        if self.components.is_empty() {
            return None;
        }
        let mut out = self.clone();
        out.pop_in_place();
        Some(out)
    }

    pub fn file_name(&self) -> Option<&str> {
        self.components.last_().map(|s| self.span_str(s))
    }

    pub fn with_symlink(mut self, symlink: Option<char>) -> Self {
        self.set_symlink(symlink);
        self
    }

    pub fn normalize(&mut self) {
        if self.components.is_empty() {
            return;
        }

        let old_raw = core::mem::take(&mut self.raw);
        let old_components = self.components;

        let mut kept = Components64::new();

        for sp in old_components.as_slice().iter().copied() {
            if sp.end > old_raw.len() || sp.start > sp.end {
                panic!(
                    "Path invariant violated in normalize: span {:?} not within raw len {} ('{}')",
                    sp,
                    old_raw.len(),
                    old_raw
                );
            }

            let seg = &old_raw[sp.start..sp.end];
            if seg == "." {
                continue;
            }
            if seg == ".." {
                let _ = kept.pop_();
                continue;
            }
            kept.push_(sp);
        }

        self.raw = String::new();
        self.components.clear_();
        self.write_prefix();

        for sp in kept.as_slice().iter().copied() {
            let seg = &old_raw[sp.start..sp.end];
            self.push_in_place(seg);
        }
    }

    pub fn to_string(&self) -> String {
        self.raw.clone()
    }

    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }

    fn span_str(&self, sp: Span) -> &str {
        if sp.end > self.raw.len() || sp.start > sp.end {
            panic!(
                "Path invariant violated: span {:?} not within raw len {} ('{}')",
                sp,
                self.raw.len(),
                self.raw
            );
        }
        &self.raw[sp.start..sp.end]
    }

    fn empty_with_symlink(symlink: Option<char>) -> Self {
        let mut raw = String::new();
        if let Some(d) = symlink {
            raw.push(d);
            raw.push(':');
            raw.push('/');
        }
        Self {
            symlink,
            components: Components64::new(),
            raw,
        }
    }

    fn prefix_len(&self) -> usize {
        if self.symlink.is_some() { 3 } else { 0 }
    }

    fn write_prefix(&mut self) {
        if let Some(d) = self.symlink {
            self.raw.push(d);
            self.raw.push(':');
            self.raw.push('/');
        }
    }

    fn push_in_place(&mut self, comp: &str) {
        if self.components.len() >= 64 {
            panic!("Path has more than 64 components");
        }

        if !self.components.is_empty() {
            self.raw.push('/');
        }

        let start = self.raw.len();
        self.raw.push_str(comp);
        let end = self.raw.len();

        self.components.push_(Span { start, end });
    }

    fn pop_in_place(&mut self) -> bool {
        if self.components.pop_().is_none() {
            return false;
        }

        let new_len = match self.components.last_() {
            Some(last) => last.end,
            None => self.prefix_len(),
        };
        self.raw.truncate(new_len);

        true
    }

    fn set_symlink(&mut self, symlink: Option<char>) {
        if self.symlink == symlink {
            return;
        }

        let old_raw = core::mem::take(&mut self.raw);
        let old_components = self.components;

        self.symlink = symlink;
        self.raw = String::new();
        self.components.clear_();
        self.write_prefix();

        for sp in old_components.as_slice().iter().copied() {
            if sp.end > old_raw.len() || sp.start > sp.end {
                panic!(
                    "Path invariant violated in set_symlink: span {:?} not within raw len {} ('{}')",
                    sp,
                    old_raw.len(),
                    old_raw
                );
            }
            let seg = &old_raw[sp.start..sp.end];
            self.push_in_place(seg);
        }
    }
}
