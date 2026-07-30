use crate::println;
use core::sync::atomic::{AtomicU8, Ordering};
use kernel_types::{
    dma::{FromDevice, IoBuffer, ToDevice},
    error::{FileErrorKind, KernelError},
    fs::{Path, *},
};
use spin::Lazy;

use crate::{
    drivers::drive::vfs::Vfs, file_system::bootstrap_filesystem::BootstrapProvider,
    static_handlers::print, util::take_boot_packages,
};

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    Bootstrap = 0,
    Vfs = 1,
}

pub static BOOTSTRAP_PROVIDER: Lazy<BootstrapProvider> =
    Lazy::new(|| BootstrapProvider::new(take_boot_packages()));
pub static VFS_PROVIDER: Lazy<Vfs> = Lazy::new(Vfs::new);

pub fn initialize_bootstrap_provider() {
    let _ = &*BOOTSTRAP_PROVIDER;
}

static CURRENT_PROVIDER: AtomicU8 = AtomicU8::new(ProviderKind::Bootstrap as u8);

pub fn install_file_provider(kind: ProviderKind) {
    CURRENT_PROVIDER.store(kind as u8, Ordering::Release);
}

#[derive(Copy, Clone)]
pub(crate) enum Provider {
    Bootstrap,
    Vfs,
}

#[inline]
pub(crate) fn provider() -> Provider {
    match CURRENT_PROVIDER.load(Ordering::Acquire) {
        x if x == ProviderKind::Vfs as u8 => Provider::Vfs,
        _ => Provider::Bootstrap,
    }
}

#[inline]
fn bootstrap<T>(f: impl FnOnce() -> T) -> T {
    core::hint::cold_path();
    f()
}

impl Provider {
    pub async fn open_path(
        self,
        path: &Path,
        flags: &[OpenFlags],
        write_through: bool,
    ) -> Result<FsOpenResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                BOOTSTRAP_PROVIDER.open_path_sync(&path.to_string(), flags)
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .open(FsOpenParams {
                        flags: OpenFlagsMask::from(flags),
                        write_through,
                        path: path.clone(),
                    })
                    .await
            }
        }
    }

    pub async fn close_handle(self, file_id: u64) -> Result<FsCloseResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| BOOTSTRAP_PROVIDER.close_handle_sync(file_id))),
            Provider::Vfs => {
                VFS_PROVIDER
                    .close(FsCloseParams {
                        fs_file_id: file_id,
                    })
                    .await
            }
        }
    }

    pub async fn seek_handle(
        self,
        file_id: u64,
        offset: i64,
        origin: FsSeekWhence,
    ) -> Result<FsSeekResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                BOOTSTRAP_PROVIDER.seek_handle_sync(file_id, offset, origin)
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .seek(FsSeekParams {
                        fs_file_id: file_id,
                        offset,
                        origin,
                    })
                    .await
            }
        }
    }

    pub async fn read_iobuffer_at<'buffer>(
        self,
        file_id: u64,
        offset: u64,
        mut buffer: IoBuffer<'buffer, 'buffer, FromDevice>,
    ) -> Result<FsReadResult, KernelError> {
        match self {
            Provider::Bootstrap => bootstrap(|| {
                let mut bytes = alloc::vec![0; buffer.len()];
                let result = BOOTSTRAP_PROVIDER.read_at_sync(file_id, offset, &mut bytes);
                if result.error.is_none()
                    && let Err(e) = buffer.copy_from_slice(0, &bytes[..result.bytes_read])
                {
                    return Ok(FsReadResult {
                        bytes_read: 0,
                        error: Some(crate::error::error(FileErrorKind::BufferError(e))),
                    });
                }
                Ok(result)
            }),
            Provider::Vfs => {
                VFS_PROVIDER
                    .read(FsReadParams {
                        fs_file_id: file_id,
                        offset,
                        buffer: Some(buffer),
                    })
                    .await
            }
        }
    }

    pub async fn write_iobuffer_at<'buffer>(
        self,
        file_id: u64,
        offset: u64,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        write_through: bool,
    ) -> Result<FsWriteResult, KernelError> {
        match self {
            Provider::Bootstrap => bootstrap(|| {
                let mut bytes = alloc::vec![0; buffer.len()];
                if let Err(e) = buffer.copy_to_slice(0, &mut bytes) {
                    return Ok(FsWriteResult {
                        written: 0,
                        error: Some(crate::error::error(FileErrorKind::BufferError(e))),
                    });
                }
                Ok(BOOTSTRAP_PROVIDER.write_at_sync(file_id, offset, &bytes))
            }),
            Provider::Vfs => {
                VFS_PROVIDER
                    .write(FsWriteParams {
                        fs_file_id: file_id,
                        offset,
                        write_through,
                        buffer: Some(buffer),
                    })
                    .await
            }
        }
    }

    pub async fn flush_handle(self, file_id: u64) -> Result<FsFlushResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| BOOTSTRAP_PROVIDER.flush_handle_sync(file_id))),
            Provider::Vfs => {
                VFS_PROVIDER
                    .flush(FsFlushParams {
                        fs_file_id: file_id,
                    })
                    .await
            }
        }
    }

    pub async fn get_info(self, file_id: u64) -> Result<FsGetInfoResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| BOOTSTRAP_PROVIDER.get_info_sync(file_id))),
            Provider::Vfs => {
                VFS_PROVIDER
                    .get_info(FsGetInfoParams {
                        fs_file_id: file_id,
                    })
                    .await
            }
        }
    }

    pub async fn list_dir_path(self, path: &Path) -> Result<FsListDirResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                BOOTSTRAP_PROVIDER.list_dir_path_sync(&path.to_string())
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .list_dir(FsListDirParams { path: path.clone() })
                    .await
            }
        }
    }

    pub async fn make_dir_path(self, path: &Path) -> Result<FsCreateResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                BOOTSTRAP_PROVIDER.make_dir_path_sync(&path.to_string())
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .create(FsCreateParams {
                        path: path.clone(),
                        dir: true,
                        flags: OpenFlags::Create,
                    })
                    .await
            }
        }
    }

    pub async fn remove_dir_path(self, path: &Path) -> Result<FsRemoveDirResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                let result = BOOTSTRAP_PROVIDER.remove_dir_path_sync(&path.to_string());
                FsRemoveDirResult {
                    error: result.error,
                }
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .remove_dir(FsRemoveDirParams { path: path.clone() })
                    .await
            }
        }
    }

    pub async fn rename_path(self, src: &Path, dst: &Path) -> Result<FsRenameResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                BOOTSTRAP_PROVIDER.rename_path_sync(&src.to_string(), &dst.to_string())
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .rename(FsRenameParams {
                        src: src.clone(),
                        dst: dst.clone(),
                    })
                    .await
            }
        }
    }

    pub async fn delete_path(self, path: &Path) -> Result<FsDeleteResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                let result = BOOTSTRAP_PROVIDER.delete_path_sync(&path.to_string());
                FsDeleteResult {
                    error: result.error,
                }
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .delete(FsDeleteParams { path: path.clone() })
                    .await
            }
        }
    }

    pub async fn set_len(self, file_id: u64, new_size: u64) -> Result<FsSetLenResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                BOOTSTRAP_PROVIDER.set_len_sync(file_id, new_size)
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .set_len(FsSetLenParams {
                        fs_file_id: file_id,
                        new_size,
                    })
                    .await
            }
        }
    }

    pub async fn append_iobuffer<'buffer>(
        self,
        file_id: u64,
        buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
        write_through: bool,
    ) -> Result<FsAppendResult, KernelError> {
        match self {
            Provider::Bootstrap => bootstrap(|| {
                let mut bytes = alloc::vec![0; buffer.len()];
                if let Err(e) = buffer.copy_to_slice(0, &mut bytes) {
                    return Ok(FsAppendResult {
                        written: 0,
                        new_size: 0,
                        error: Some(crate::error::error(FileErrorKind::BufferError(e))),
                    });
                }
                Ok(BOOTSTRAP_PROVIDER.append_sync(file_id, &bytes))
            }),
            Provider::Vfs => {
                VFS_PROVIDER
                    .append(FsAppendParams {
                        fs_file_id: file_id,
                        buffer: Some(buffer),
                        write_through,
                    })
                    .await
            }
        }
    }

    pub async fn zero_range(
        self,
        file_id: u64,
        offset: u64,
        len: u64,
    ) -> Result<FsZeroRangeResult, KernelError> {
        match self {
            Provider::Bootstrap => Ok(bootstrap(|| {
                BOOTSTRAP_PROVIDER.zero_range_sync(file_id, offset, len)
            })),
            Provider::Vfs => {
                VFS_PROVIDER
                    .zero_range(FsZeroRangeParams {
                        fs_file_id: file_id,
                        offset,
                        len,
                    })
                    .await
            }
        }
    }
}
