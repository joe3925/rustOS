#![no_std]

extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use spin::RwLock;

use crate::drivers::pnp::driver_object::{DriverStatus, Request};
use crate::file_system::file::OpenFlags;
use crate::file_system::file_structs::{
    FileError, FsCloseParams, FsCloseResult, FsCreateParams, FsCreateResult, FsFlushParams,
    FsFlushResult, FsGetInfoParams, FsGetInfoResult, FsListDirParams, FsListDirResult,
    FsOpenParams, FsOpenResult, FsReadParams, FsReadResult, FsRenameParams, FsRenameResult,
    FsSeekParams, FsSeekResult, FsSeekWhence, FsWriteParams, FsWriteResult,
};

pub trait FileProvider: Send + Sync {
    fn open_path(&self, path: &str, flags: &[OpenFlags]) -> (FsOpenResult, DriverStatus);
    fn close_handle(&self, file_id: u64) -> (FsCloseResult, DriverStatus);
    fn read_at(&self, file_id: u64, offset: u64, len: u32) -> (FsReadResult, DriverStatus);
    fn write_at(&self, file_id: u64, offset: u64, data: &[u8]) -> (FsWriteResult, DriverStatus);
    fn flush_handle(&self, file_id: u64) -> (FsFlushResult, DriverStatus);
    fn get_info(&self, file_id: u64) -> (FsGetInfoResult, DriverStatus);

    fn list_dir_path(&self, path: &str) -> (FsListDirResult, DriverStatus);
    fn make_dir_path(&self, path: &str) -> (FsCreateResult, DriverStatus);
    fn remove_dir_path(&self, path: &str) -> (FsCreateResult, DriverStatus);
    fn rename_path(&self, src: &str, dst: &str) -> (FsRenameResult, DriverStatus);
    fn delete_path(&self, path: &str) -> (FsCreateResult, DriverStatus);

    // Async variants: return the in-flight Request handle without waiting.
    fn open_path_async(
        &self,
        path: &str,
        flags: &[OpenFlags],
    ) -> Result<Arc<RwLock<Request>>, FileError>;
    fn read_at_async(
        &self,
        file_id: u64,
        offset: u64,
        len: u32,
    ) -> Result<Arc<RwLock<Request>>, FileError>;
    fn write_at_async(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Arc<RwLock<Request>>, FileError>;
}

static CURRENT_PROVIDER: RwLock<Option<Box<dyn FileProvider>>> = RwLock::new(None);

pub fn install_file_provider(p: Box<dyn FileProvider>) {
    *CURRENT_PROVIDER.write() = Some(p);
}

#[inline]
pub(crate) fn provider() -> &'static dyn FileProvider {
    let guard = CURRENT_PROVIDER.read();
    let p = guard.as_ref().expect("FileProvider not installed");
    unsafe { &*(&**p as *const dyn FileProvider) }
}

pub fn map_file_error(err: FileError) -> super::file::FileStatus {
    use super::file::FileStatus;
    match err {
        FileError::AlreadyExists => FileStatus::FileAlreadyExist,
        FileError::NotFound => FileStatus::PathNotFound,
        FileError::BadPath => FileStatus::BadPath,
        FileError::Unsupported => FileStatus::UnknownFail,
        FileError::Corrupt => FileStatus::CorruptFat,
        FileError::Unknown => FileStatus::UnknownFail,
        FileError::NotADirectory => FileStatus::PathNotFound,
        FileError::IsDirectory => FileStatus::BadPath,
        FileError::AccessDenied => FileStatus::UnknownFail,
        FileError::NoSpace => todo!(),
        FileError::IoError => todo!(),
    }
}
