#![no_std]

extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use spin::RwLock;

use kernel_types::{
    fs::*,
    request::Request,
    status::{DriverStatus, FileStatus},
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
    ) -> Result<Arc<RwLock<Request>>, FileStatus>;
    fn read_at_async(
        &self,
        file_id: u64,
        offset: u64,
        len: u32,
    ) -> Result<Arc<RwLock<Request>>, FileStatus>;
    fn write_at_async(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Arc<RwLock<Request>>, FileStatus>;
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
