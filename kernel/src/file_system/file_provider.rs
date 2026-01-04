#![no_std]

extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use spin::RwLock;

use kernel_types::{
    async_ffi::FfiFuture,
    fs::{*, Path},
    request::Request,
    status::{DriverStatus, FileStatus},
};

pub trait FileProvider: Send + Sync {
    fn open_path(&self, path: &Path, flags: &[OpenFlags])
        -> FfiFuture<(FsOpenResult, DriverStatus)>;

    fn close_handle(&self, file_id: u64) -> FfiFuture<(FsCloseResult, DriverStatus)>;
    fn seek_handle(
        &self,
        file_id: u64,
        offset: i64,
        origin: FsSeekWhence,
    ) -> FfiFuture<(FsSeekResult, DriverStatus)>;
    fn read_at(
        &self,
        file_id: u64,
        offset: u64,
        len: u32,
    ) -> FfiFuture<(FsReadResult, DriverStatus)>;

    fn write_at(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> FfiFuture<(FsWriteResult, DriverStatus)>;

    fn flush_handle(&self, file_id: u64) -> FfiFuture<(FsFlushResult, DriverStatus)>;

    fn get_info(&self, file_id: u64) -> FfiFuture<(FsGetInfoResult, DriverStatus)>;

    fn list_dir_path(&self, path: &Path) -> FfiFuture<(FsListDirResult, DriverStatus)>;

    fn make_dir_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)>;

    fn remove_dir_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)>;

    fn rename_path(&self, src: &Path, dst: &Path) -> FfiFuture<(FsRenameResult, DriverStatus)>;

    fn delete_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)>;
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
