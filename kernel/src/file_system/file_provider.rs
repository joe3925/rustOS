use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};
use spin::Lazy;

use kernel_types::{
    async_ffi::FfiFuture,
    fs::{Path, *},
    request::Request,
    status::{DriverStatus, FileStatus},
};

// These must exist somewhere in your crate and implement `FileProvider`.
use crate::{
    drivers::drive::vfs::Vfs, file_system::bootstrap_filesystem::BootstrapProvider, util::BOOTSET,
};

pub trait FileProvider: Send + Sync {
    fn open_path(
        &self,
        path: &Path,
        flags: &[OpenFlags],
        write_through: bool,
    ) -> FfiFuture<(FsOpenResult, DriverStatus)>;

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
        write_through: bool,
    ) -> FfiFuture<(FsWriteResult, DriverStatus)>;

    fn flush_handle(&self, file_id: u64) -> FfiFuture<(FsFlushResult, DriverStatus)>;

    fn get_info(&self, file_id: u64) -> FfiFuture<(FsGetInfoResult, DriverStatus)>;

    fn list_dir_path(&self, path: &Path) -> FfiFuture<(FsListDirResult, DriverStatus)>;

    fn make_dir_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)>;

    fn remove_dir_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)>;

    fn rename_path(&self, src: &Path, dst: &Path) -> FfiFuture<(FsRenameResult, DriverStatus)>;

    fn delete_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)>;

    fn set_len(&self, file_id: u64, new_size: u64) -> FfiFuture<(FsSetLenResult, DriverStatus)>;

    fn append(
        &self,
        file_id: u64,
        data: &[u8],
        write_through: bool,
    ) -> FfiFuture<(FsAppendResult, DriverStatus)>;

    fn zero_range(
        &self,
        file_id: u64,
        offset: u64,
        len: u64,
    ) -> FfiFuture<(FsZeroRangeResult, DriverStatus)>;
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    Bootstrap = 0,
    Vfs = 1,
}

pub static BOOTSTRAP_PROVIDER: Lazy<BootstrapProvider> =
    Lazy::new(|| BootstrapProvider::new(BOOTSET));
pub static VFS_PROVIDER: Lazy<Vfs> = Lazy::new(Vfs::new);

static CURRENT_PROVIDER: AtomicU8 = AtomicU8::new(ProviderKind::Bootstrap as u8);

pub fn install_file_provider(kind: ProviderKind) {
    CURRENT_PROVIDER.store(kind as u8, Ordering::Release);
}

#[inline]
pub(crate) fn provider() -> &'static dyn FileProvider {
    match CURRENT_PROVIDER.load(Ordering::Acquire) {
        x if x == ProviderKind::Vfs as u8 => &*VFS_PROVIDER as &dyn FileProvider,
        _ => &*BOOTSTRAP_PROVIDER as &dyn FileProvider,
    }
}
