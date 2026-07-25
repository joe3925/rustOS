use alloc::format;
use alloc::string::{String, ToString};
use bincode::{Decode, Encode};
use core::convert::Infallible;
use core::fmt;
use core::ops::{ControlFlow, FromResidual, Residual, Try};

use crate::dma::IoBufferError;

#[repr(i32)]
#[derive(Debug, Clone, Eq, Copy)]
pub enum DriverStatus {
    Success = 0x0000_0000,
    PendingStep = 0x0000_0103,
    ContinueStep = 0x0000_0203,
    NotImplemented = 0xC000_0002u32 as i32,
    InvalidParameter = 0xC000_000Du32 as i32,
    InsufficientResources = 0xC000_009Au32 as i32,
    NoSuchDevice = 0xC000_000Eu32 as i32,
    NoSuchFile = 0xC000_000Fu32 as i32,
    DeviceNotReady = 0xC000_00A3u32 as i32,
    Unsuccessful = 0xC000_0001u32 as i32,
    DeviceError { message: &'static str } = 0xC000_002Fu32 as i32,
    Timeout = 0xC000_001Fu32 as i32,
}

impl DriverStatus {
    pub const STATUS_SUCCESS: i32 = 0x0000_0000;
    pub const STATUS_PENDING_STEP: i32 = 0x0000_0103;
    pub const STATUS_CONTINUE_STEP: i32 = 0x0000_0203;
    pub const STATUS_NOT_IMPLEMENTED: i32 = 0xC000_0002u32 as i32;
    pub const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
    pub const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
    pub const STATUS_NO_SUCH_DEVICE: i32 = 0xC000_000Eu32 as i32;
    pub const STATUS_NO_SUCH_FILE: i32 = 0xC000_000Fu32 as i32;
    pub const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;
    pub const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;
    pub const STATUS_DEVICE_ERROR: i32 = 0xC000_002Fu32 as i32;
    pub const STATUS_TIMEOUT: i32 = 0xC000_001Fu32 as i32;

    #[inline]
    pub fn code(&self) -> i32 {
        match self {
            Self::Success => Self::STATUS_SUCCESS,
            Self::PendingStep => Self::STATUS_PENDING_STEP,
            Self::ContinueStep => Self::STATUS_CONTINUE_STEP,
            Self::NotImplemented => Self::STATUS_NOT_IMPLEMENTED,
            Self::InvalidParameter => Self::STATUS_INVALID_PARAMETER,
            Self::InsufficientResources => Self::STATUS_INSUFFICIENT_RESOURCES,
            Self::NoSuchDevice => Self::STATUS_NO_SUCH_DEVICE,
            Self::NoSuchFile => Self::STATUS_NO_SUCH_FILE,
            Self::DeviceNotReady => Self::STATUS_DEVICE_NOT_READY,
            Self::Unsuccessful => Self::STATUS_UNSUCCESSFUL,
            Self::DeviceError { .. } => Self::STATUS_DEVICE_ERROR,
            Self::Timeout => Self::STATUS_TIMEOUT,
        }
    }
}

impl PartialEq for DriverStatus {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.code() == other.code()
    }
}

impl fmt::Display for DriverStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => f.write_str("Success"),
            Self::PendingStep => f.write_str("PendingStep"),
            Self::ContinueStep => f.write_str("ContinueStep"),
            Self::NotImplemented => f.write_str("NotImplemented"),
            Self::InvalidParameter => f.write_str("InvalidParameter"),
            Self::InsufficientResources => f.write_str("InsufficientResources"),
            Self::NoSuchDevice => f.write_str("NoSuchDevice"),
            Self::NoSuchFile => f.write_str("NoSuchFile"),
            Self::DeviceNotReady => f.write_str("DeviceNotReady"),
            Self::Unsuccessful => f.write_str("Unsuccessful"),
            Self::DeviceError { message } => write!(f, "DeviceError: {message}"),
            Self::Timeout => f.write_str("Timeout"),
        }
    }
}

impl Try for DriverStatus {
    type Output = ();
    type Residual = DriverStatus;

    #[inline]
    fn from_output((): Self::Output) -> Self {
        DriverStatus::Success
    }

    #[inline]
    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        if self == DriverStatus::Success {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(self)
        }
    }
}

impl Residual<()> for DriverStatus {
    type TryType = DriverStatus;
}

impl From<i32> for DriverStatus {
    #[inline]
    fn from(v: i32) -> Self {
        match v {
            Self::STATUS_SUCCESS => Self::Success,
            Self::STATUS_PENDING_STEP => Self::PendingStep,
            Self::STATUS_CONTINUE_STEP => Self::ContinueStep,
            Self::STATUS_NOT_IMPLEMENTED => Self::NotImplemented,
            Self::STATUS_INVALID_PARAMETER => Self::InvalidParameter,
            Self::STATUS_INSUFFICIENT_RESOURCES => Self::InsufficientResources,
            Self::STATUS_NO_SUCH_DEVICE => Self::NoSuchDevice,
            Self::STATUS_NO_SUCH_FILE => Self::NoSuchFile,
            Self::STATUS_DEVICE_NOT_READY => Self::DeviceNotReady,
            Self::STATUS_UNSUCCESSFUL => Self::Unsuccessful,
            Self::STATUS_DEVICE_ERROR => Self::DeviceError {
                message: "Device Error",
            },
            Self::STATUS_TIMEOUT => Self::Timeout,
            _ => Self::Unsuccessful,
        }
    }
}
impl<T> FromResidual<DriverStatus> for Result<T, DriverStatus> {
    #[inline]
    fn from_residual(r: DriverStatus) -> Self {
        Err(r)
    }
}
impl FromResidual<Result<Infallible, DriverStatus>> for DriverStatus {
    #[inline]
    fn from_residual(residual: Result<Infallible, DriverStatus>) -> Self {
        match residual {
            Ok(_) => unreachable!(),
            Err(e) => e,
        }
    }
}
impl FromResidual<DriverStatus> for DriverStatus {
    #[inline]
    fn from_residual(r: DriverStatus) -> Self {
        r
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum LoadError {
    IsNotExecutable,
    Not64Bit,
    NoEntryPoint,
    InvalidSubsystem,
    InvalidDllCharacteristics,
    UnsupportedRelocationFormat,
    MissingSections,
    UnsupportedImageBase,
    NotImplemented,
    NoMemory,
    BadPID,
    NotDLL,
    NoFile,
    NoMainThread,
    NoSuchSymbol(String),
    PageError(PageMapError),
}

impl From<PageMapError> for LoadError {
    fn from(err: PageMapError) -> Self {
        LoadError::PageError(err)
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum DriverError {
    File(FileStatus),
    InvalidUtf8,
    TomlParse,
    DriverAlreadyInstalled,
    NoParent,
    Registry(RegError),
    LoadErr(LoadError),
    ProbeFailed(DriverStatus),
    DriverEntryFailed,
}

impl From<FileStatus> for DriverError {
    fn from(e: FileStatus) -> Self {
        if e == FileStatus::FileAlreadyExist {
            return DriverError::DriverAlreadyInstalled;
        }
        DriverError::File(e)
    }
}

impl From<RegError> for DriverError {
    fn from(e: RegError) -> Self {
        DriverError::Registry(e)
    }
}

impl From<LoadError> for DriverError {
    fn from(e: LoadError) -> Self {
        DriverError::LoadErr(e)
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum PageMapError {
    Page4KiB(PageMapFailure),
    Page2MiB(PageMapFailure),
    Page1GiB(PageMapFailure),
    TranslationFailed(),
    NoMemory(),
    NoMemoryMap(),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PageMapFailure {
    FrameAllocationFailed,
    PageAlreadyMapped,
    ParentEntryHugePage,
}

#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
    BadName,
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum FileStatus {
    Success,
    FileAlreadyExist,
    PathNotFound,
    UnknownFail,
    NoBuffer,
    BufferError(IoBufferError),
    FileSystemError,
    DriverError(DriverStatus),
    NotFat,
    DriveNotFound,
    IncompatibleFlags,
    CorruptFilesystem,
    InternalError,
    BadPath,
    AccessDenied,
    NoSpace,
    FileTooLarge,
}
impl From<DriverStatus> for FileStatus {
    fn from(failure: DriverStatus) -> Self {
        FileStatus::DriverError(failure)
    }
}
impl FileStatus {
    pub fn to_str(&self) -> String {
        match self {
            FileStatus::Success => "Success".into(),
            FileStatus::FileAlreadyExist => "File already exists".into(),
            FileStatus::PathNotFound => "Path not found".into(),
            FileStatus::UnknownFail => "The operation failed for an unknown reason".into(),
            FileStatus::NoBuffer => {
                "The file system recived the request but there was no buffer passed with it".into()
            }
            FileStatus::BufferError(e) => format!("{e:#?}"),
            FileStatus::DriverError(e) => format!("{e:#?}"),
            FileStatus::FileSystemError => "The file system encountered an internal error".into(),
            FileStatus::NotFat => "The partition is unformatted or not supported".into(),
            FileStatus::DriveNotFound => "The drive specified doesn't exist".into(),
            FileStatus::IncompatibleFlags => "The flags can contain CreateNew and Create".into(),
            FileStatus::CorruptFilesystem => "The File Allocation Table is corrupt".into(),
            FileStatus::InternalError => "Internal error".into(),
            FileStatus::BadPath => "Invalid path".into(),
            FileStatus::AccessDenied => {
                "Insufficient permissions to access the current file".into()
            }
            FileStatus::NoSpace => "Insufficient space on drive to write the requested data".into(),
            FileStatus::FileTooLarge => {
                "The op would cause the file to exceed the max file size".into()
            }
        }
    }
}
impl From<FileStatus> for u32 {
    fn from(status: FileStatus) -> Self {
        match status {
            FileStatus::Success => 0,
            FileStatus::FileAlreadyExist => 1,
            FileStatus::PathNotFound => 2,
            FileStatus::UnknownFail => 3,
            FileStatus::NoBuffer => 4,
            FileStatus::BufferError(_) => 5,
            FileStatus::FileSystemError => 6,
            FileStatus::DriverError(_) => 7,
            FileStatus::NotFat => 8,
            FileStatus::DriveNotFound => 9,
            FileStatus::IncompatibleFlags => 10,
            FileStatus::CorruptFilesystem => 11,
            FileStatus::InternalError => 12,
            FileStatus::BadPath => 13,
            FileStatus::AccessDenied => 14,
            FileStatus::NoSpace => 15,
            FileStatus::FileTooLarge => 16,
        }
    }
}
impl PartialEq for FileStatus {
    fn eq(&self, other: &FileStatus) -> bool {
        self.to_str() == other.to_str()
    }
}
// TODO: move this to a better place
#[derive(Debug)]
#[repr(C)]
pub enum RegError {
    KeyAlreadyExists,
    KeyNotFound,
    ValueNotFound,
    PersistenceFailed,
    EncodingFailed,
    CorruptReg,
    FileIO { status: FileStatus },
}

impl From<FileStatus> for RegError {
    fn from(status: FileStatus) -> Self {
        RegError::FileIO { status }
    }
}
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Data {
    #[prost(uint32, tag = "1")]
    U32(u32),
    #[prost(uint64, tag = "2")]
    U64(u64),
    #[prost(sint32, tag = "3")]
    I32(i32),
    #[prost(sint64, tag = "4")]
    I64(i64),
    #[prost(bool, tag = "5")]
    Bool(bool),
    #[prost(string, tag = "6")]
    Str(String),
}
