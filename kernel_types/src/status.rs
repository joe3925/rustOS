use alloc::string::String;
use bincode::{Decode, Encode};
use core::convert::Infallible;
use core::fmt;
use core::ops::{ControlFlow, FromResidual, Try};
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{Size1GiB, Size2MiB, Size4KiB};

#[repr(i32)]
#[derive(Debug, Clone, Eq)]
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
    DeviceError { message: String } = 0xC000_002Fu32 as i32,
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
    pub fn device_error(message: impl Into<String>) -> Self {
        Self::DeviceError {
            message: message.into(),
        }
    }

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
            Self::STATUS_DEVICE_ERROR => Self::device_error("Device error"),
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
    NoSuchSymbol,
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
    Page4KiB(MapToError<Size4KiB>),
    Page2MiB(MapToError<Size2MiB>),
    Page1GiB(MapToError<Size1GiB>),
    TranslationFailed(),
    NoMemory(),
    NoMemoryMap(),
}

impl From<MapToError<Size4KiB>> for PageMapError {
    fn from(e: MapToError<Size4KiB>) -> Self {
        PageMapError::Page4KiB(e)
    }
}
impl From<MapToError<Size2MiB>> for PageMapError {
    fn from(e: MapToError<Size2MiB>) -> Self {
        PageMapError::Page2MiB(e)
    }
}
impl From<MapToError<Size1GiB>> for PageMapError {
    fn from(e: MapToError<Size1GiB>) -> Self {
        PageMapError::Page1GiB(e)
    }
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

impl FileStatus {
    pub fn to_str(&self) -> &str {
        match self {
            FileStatus::Success => "Success",
            FileStatus::FileAlreadyExist => "File already exists",
            FileStatus::PathNotFound => "Path not found",
            FileStatus::UnknownFail => "The operation failed for an unknown reason",
            FileStatus::NotFat => "The partition is unformatted or not supported",
            FileStatus::DriveNotFound => "The drive specified doesn't exist",
            FileStatus::IncompatibleFlags => "The flags can contain CreateNew and Create",
            FileStatus::CorruptFilesystem => "The File Allocation Table is corrupt",
            FileStatus::InternalError => "Internal error",
            FileStatus::BadPath => "Invalid path",
            FileStatus::AccessDenied => "Insufficient permissions to access the current file",
            FileStatus::NoSpace => "Insufficient space on drive to write the requested data",
            FileStatus::FileTooLarge => "The op would cause the file to exceed the max file size",
        }
    }
}
impl PartialEq for FileStatus {
    fn eq(&self, other: &FileStatus) -> bool {
        self.to_str() == other.to_str()
    }
}

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
#[derive(Debug, Clone, Encode, Decode, PartialEq)]
#[repr(u32)]
pub enum Data {
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
    Bool(bool),
    Str(String),
}
