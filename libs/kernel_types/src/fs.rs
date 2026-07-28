use crate::dma::{FromDevice, IoBuffer, ToDevice};
use crate::error::KernelError;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hint::black_box;
use core::ptr;
use core::sync::atomic::AtomicU64;
use kernel_macros;
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

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsOpenParams {
    pub flags: OpenFlagsMask,
    pub write_through: bool,
    pub path: Path,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsOpenResult {
    pub fs_file_id: u64,
    pub is_dir: bool,
    pub size: u64,
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsCloseParams {
    pub fs_file_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsCloseResult {
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, kernel_macros::RequestPayload)]
pub struct FsReadParams<'a> {
    pub fs_file_id: u64,
    pub offset: u64,
    pub buffer: Option<IoBuffer<'a, 'a, FromDevice>>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsReadResult {
    pub bytes_read: usize,
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, kernel_macros::RequestPayload)]
pub struct FsWriteParams<'a> {
    pub fs_file_id: u64,
    pub offset: u64,
    pub write_through: bool,
    pub buffer: Option<IoBuffer<'a, 'a, ToDevice>>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsWriteResult {
    pub written: usize,
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FsSeekWhence {
    Set,
    Cur,
    End,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsSeekParams {
    pub fs_file_id: u64,
    pub origin: FsSeekWhence,
    pub offset: i64,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsSeekResult {
    pub pos: u64,
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsFlushParams {
    pub fs_file_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsFlushResult {
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsCreateParams {
    pub path: Path,
    pub dir: bool,
    pub flags: OpenFlags,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsCreateResult {
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsRemoveDirParams {
    pub path: Path,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsRemoveDirResult {
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsDeleteParams {
    pub path: Path,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsDeleteResult {
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsRenameParams {
    pub src: Path,
    pub dst: Path,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsRenameResult {
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsListDirParams {
    pub path: Path,
}
#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsListDirResult {
    pub names: Option<Vec<String>>,
    pub error: Option<KernelError>,
}
#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsGetInfoParams {
    pub fs_file_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsGetInfoResult {
    pub size: u64,
    pub is_dir: bool,
    pub attrs: u32,
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsSetLenParams {
    pub fs_file_id: u64,
    pub new_size: u64,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsSetLenResult {
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, kernel_macros::RequestPayload)]
pub struct FsAppendParams<'a> {
    pub fs_file_id: u64,
    pub buffer: Option<IoBuffer<'a, 'a, ToDevice>>,
    pub write_through: bool,
}
#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsAppendResult {
    pub written: usize,
    pub new_size: u64,
    pub error: Option<KernelError>,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsZeroRangeParams {
    pub fs_file_id: u64,
    pub offset: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct FsZeroRangeResult {
    pub error: Option<KernelError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Components64 {
    buf: Vec<Span>,
}

impl Components64 {
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[Span] {
        self.buf.as_slice()
    }

    fn clear_(&mut self) {
        self.buf.clear();
    }

    fn last_(&self) -> Option<Span> {
        self.buf.last().copied()
    }

    fn push_(&mut self, span: Span) {
        if self.buf.len() >= 64 {
            panic!("Path has more than 64 components");
        }

        self.buf.push(span);
    }

    fn pop_(&mut self) -> Option<Span> {
        self.buf.pop()
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
        f.debug_list().entries(self.buf.iter()).finish()
    }
}

impl<'a> IntoIterator for &'a Components64 {
    type Item = &'a Span;
    type IntoIter = core::slice::Iter<'a, Span>;

    fn into_iter(self) -> Self::IntoIter {
        self.buf.iter()
    }
}

pub struct Components64IntoIter {
    inner: alloc::vec::IntoIter<Span>,
}

impl Iterator for Components64IntoIter {
    type Item = Span;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for Components64IntoIter {}

impl core::iter::FusedIterator for Components64IntoIter {}

impl IntoIterator for Components64 {
    type Item = Span;
    type IntoIter = Components64IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        Components64IntoIter {
            inner: self.buf.into_iter(),
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

    pub fn from_string_owned(raw: String) -> Self {
        let bytes = raw.as_bytes();

        let symlink =
            if bytes.len() >= 2 && bytes[1] == b':' && (bytes[0] as char).is_ascii_alphabetic() {
                Some(bytes[0] as char)
            } else {
                None
            };

        let body = if symlink.is_some() {
            &raw[2..]
        } else {
            raw.as_str()
        };

        let mut out = Self::empty_with_symlink(symlink);

        for comp in body.split(['\\', '/']) {
            if !comp.is_empty() {
                out.push_in_place(comp);
            }
        }

        out
    }

    pub fn parse(raw: &str, base: Option<&Self>) -> Self {
        let bytes = raw.as_bytes();

        if bytes.len() >= 2 && bytes[1] == b':' && (bytes[0] as char).is_ascii_alphabetic() {
            let drive = bytes[0] as char;

            if bytes.len() == 2 {
                return Self::from_symlink(drive);
            }

            if bytes.get(2) == Some(&b'\\') || bytes.get(2) == Some(&b'/') {
                Self::from_string(raw)
            } else if let Some(base) = base {
                let mut out = base.clone();
                out.set_symlink(Some(drive));
                out.join(&raw[2..])
            } else {
                panic!("Relative path {} given with no base", raw);
            }
        } else if bytes.first() == Some(&b'\\') || bytes.first() == Some(&b'/') {
            if let Some(base) = base {
                Self::empty_with_symlink(base.symlink).join(&raw[1..])
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
            match comp {
                "" | "." => {}
                ".." => {
                    self.pop_in_place();
                }
                _ => {
                    self.push_in_place(comp);
                }
            }
        }

        self
    }

    pub fn push(&mut self, comp: &str) {
        if comp.is_empty() {
            return;
        }

        if comp == "." || comp == ".." {
            panic!("Invalid path component '{}'", comp);
        }

        if comp
            .as_bytes()
            .iter()
            .any(|&byte| byte == b'/' || byte == b'\\')
        {
            panic!("Path::push expects a single component, got '{}'", comp);
        }

        self.push_in_place(comp);
    }

    pub fn pop(&mut self) -> Option<String> {
        let span = self.components.pop_()?;
        let component = self.span_str(span).to_string();

        let new_len = self
            .components
            .last_()
            .map_or_else(|| self.prefix_len(), |last| last.end);

        self.raw.truncate(new_len);

        Some(component)
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
        self.components.last_().map(|span| self.span_str(span))
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
        let old_components = core::mem::take(&mut self.components);

        let mut kept = Components64::new();

        for span in old_components {
            self.validate_span(&old_raw, span, "normalize");

            let component = &old_raw[span.start..span.end];

            match component {
                "." => {}
                ".." => {
                    kept.pop_();
                }
                _ => {
                    kept.push_(span);
                }
            }
        }

        self.components.clear_();
        self.write_prefix();

        for span in kept {
            self.push_in_place(&old_raw[span.start..span.end]);
        }
    }

    pub fn to_string(&self) -> String {
        self.raw.clone()
    }

    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }

    fn span_str(&self, span: Span) -> &str {
        if span.start > span.end || span.end > self.raw.len() {
            panic!(
                "Path invariant violated: span {:?} not within raw len {} ('{}')",
                span,
                self.raw.len(),
                self.raw
            );
        }

        &self.raw[span.start..span.end]
    }

    fn empty_with_symlink(symlink: Option<char>) -> Self {
        let mut path = Self {
            symlink,
            components: Components64::new(),
            raw: String::new(),
        };

        path.write_prefix();
        path
    }

    fn prefix_len(&self) -> usize {
        if self.symlink.is_some() { 3 } else { 0 }
    }

    fn write_prefix(&mut self) {
        if let Some(drive) = self.symlink {
            self.raw.push(drive);
            self.raw.push(':');
            self.raw.push('/');
        }
    }

    fn push_in_place(&mut self, comp: &str) {
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

        let new_len = self
            .components
            .last_()
            .map_or_else(|| self.prefix_len(), |last| last.end);

        self.raw.truncate(new_len);
        true
    }

    fn set_symlink(&mut self, symlink: Option<char>) {
        if self.symlink == symlink {
            return;
        }

        let old_raw = core::mem::take(&mut self.raw);
        let old_components = core::mem::take(&mut self.components);

        self.symlink = symlink;
        self.write_prefix();

        for span in old_components {
            self.validate_span(&old_raw, span, "set_symlink");
            self.push_in_place(&old_raw[span.start..span.end]);
        }
    }

    fn validate_span(&self, raw: &str, span: Span, operation: &str) {
        if span.start > span.end || span.end > raw.len() {
            panic!(
                "Path invariant violated in {}: span {:?} not within raw len {} ('{}')",
                operation,
                span,
                raw.len(),
                raw
            );
        }
    }
}
