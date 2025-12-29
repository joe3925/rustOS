use alloc::string::String;
use bincode::{Decode, Encode};
use core::convert::Infallible;
use core::ops::{ControlFlow, FromResidual, Try};
use strum::Display;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{Size1GiB, Size2MiB, Size4KiB};

#[repr(i32)]
#[derive(Display, Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DriverError {
    LoadError,
    BindError,
    StartError,
}

#[derive(Debug)]
#[repr(u32)]
pub enum PageMapError {
    Page4KiB(MapToError<Size4KiB>),
    Page2MiB(MapToError<Size2MiB>),
    Page1GiB(MapToError<Size1GiB>),
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
    Success = 0x00,
    FileAlreadyExist = 0x01,
    PathNotFound = 0x02,
    UnknownFail = 0x03,
    NotFat = 0x04,
    DriveNotFound,
    IncompatibleFlags,
    CorruptFilesystem,
    InternalError,
    BadPath,
    AccessDenied,
    NoSpace,
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
    FileIO(FileStatus),
}

impl From<FileStatus> for RegError {
    fn from(status: FileStatus) -> Self {
        RegError::FileIO(status)
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
